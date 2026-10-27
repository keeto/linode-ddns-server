// Package linodetest provides an in-memory fake of the Linode Domains API for
// tests.
package linodetest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"

	"linode-ddns/internal/linode"
)

// Fake serves GET /domains, GET /domains/{id}/records and
// PUT /domains/{id}/records/{rid}.
type Fake struct {
	*httptest.Server

	Token string
	// PageSize overrides the page size requested by the client, to exercise
	// pagination.
	PageSize int

	mu      sync.Mutex
	domains []linode.Domain
	records map[int][]linode.Record
	fail    int
	calls   map[string]int
}

func New(token string) *Fake {
	f := &Fake{Token: token, records: map[int][]linode.Record{}, calls: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /domains", f.listDomains)
	mux.HandleFunc("GET /domains/{id}/records", f.listRecords)
	mux.HandleFunc("PUT /domains/{id}/records/{rid}", f.updateRecord)
	f.Server = httptest.NewServer(f.auth(mux))
	return f
}

// Client returns a client pointed at the fake.
func (f *Fake) Client() *linode.Client {
	c := linode.NewClient()
	c.BaseURL = f.URL
	return c
}

func (f *Fake) AddDomain(id int, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains = append(f.domains, linode.Domain{ID: id, Domain: name})
}

func (f *Fake) AddRecord(domainID int, r linode.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[domainID] = append(f.records[domainID], r)
}

// DeleteRecord removes a record, simulating an out-of-band change.
func (f *Fake) DeleteRecord(domainID, recordID int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	recs := f.records[domainID]
	for i, r := range recs {
		if r.ID == recordID {
			f.records[domainID] = append(recs[:i], recs[i+1:]...)
			return
		}
	}
}

// Target returns the current target of a record, or "".
func (f *Fake) Target(domainID, recordID int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records[domainID] {
		if r.ID == recordID {
			return r.Target
		}
	}
	return ""
}

// FailWith makes every following request respond with status until reset with 0.
func (f *Fake) FailWith(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = status
}

// Calls returns how many requests matched the route pattern, e.g.
// "PUT /domains/{id}/records/{rid}".
func (f *Fake) Calls(pattern string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[pattern]
}

func (f *Fake) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.Token {
			writeError(w, http.StatusUnauthorized, "Invalid Token")
			return
		}
		f.mu.Lock()
		fail := f.fail
		f.mu.Unlock()
		if fail != 0 {
			writeError(w, fail, "fake failure")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (f *Fake) listDomains(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[r.Pattern]++
	f.writePage(w, r, f.domains)
}

func (f *Fake) listRecords(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[r.Pattern]++
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !f.hasDomain(id) {
		writeError(w, http.StatusNotFound, "Not found")
		return
	}
	f.writePage(w, r, f.records[id])
}

func (f *Fake) updateRecord(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[r.Pattern]++
	id, _ := strconv.Atoi(r.PathValue("id"))
	rid, _ := strconv.Atoi(r.PathValue("rid"))
	var body struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad body")
		return
	}
	for i, rec := range f.records[id] {
		if rec.ID == rid {
			f.records[id][i].Target = body.Target
			json.NewEncoder(w).Encode(f.records[id][i])
			return
		}
	}
	writeError(w, http.StatusNotFound, "Not found")
}

func (f *Fake) hasDomain(id int) bool {
	for _, d := range f.domains {
		if d.ID == id {
			return true
		}
	}
	return false
}

func (f *Fake) writePage(w http.ResponseWriter, r *http.Request, items any) {
	all, _ := json.Marshal(items)
	var list []json.RawMessage
	json.Unmarshal(all, &list)

	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if f.PageSize > 0 {
		size = f.PageSize
	}
	if size <= 0 {
		size = 100
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pages := max(1, (len(list)+size-1)/size)
	start := min(len(list), (page-1)*size)
	end := min(len(list), start+size)
	json.NewEncoder(w).Encode(map[string]any{
		"data":    append([]json.RawMessage{}, list[start:end]...),
		"page":    page,
		"pages":   pages,
		"results": len(list),
	})
}

func writeError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"reason": reason}}})
}

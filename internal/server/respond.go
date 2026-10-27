package server

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// Result codes. Most follow the dyndns2 protocol so router clients understand
// them; "ok" is used by /v1/status and "badip" for missing or malformed IPs.
const (
	CodeGood    = "good"
	CodeNoChg   = "nochg"
	CodeOK      = "ok"
	CodeBadAuth = "badauth"
	CodeAbuse   = "abuse"
	CodeNotFQDN = "notfqdn"
	CodeBadIP   = "badip"
	CodeNoHost  = "nohost"
	CodeError   = "911"
)

// Result is the outcome for one record, or a request-level error when Type is
// empty.
type Result struct {
	Type    string `json:"type,omitempty"`
	Code    string `json:"status"`
	IP      string `json:"ip,omitempty"`
	Message string `json:"message,omitempty"`
}

func httpStatus(code string) int {
	switch code {
	case CodeGood, CodeNoChg, CodeOK:
		return http.StatusOK
	case CodeBadAuth:
		return http.StatusUnauthorized
	case CodeAbuse:
		return http.StatusTooManyRequests
	case CodeNotFQDN, CodeBadIP:
		return http.StatusBadRequest
	case CodeNoHost:
		return http.StatusNotFound
	default:
		return http.StatusBadGateway
	}
}

// write renders results as JSON or dyndns2 text depending on the Accept
// header. The HTTP status is taken from the first failed result.
func write(w http.ResponseWriter, r *http.Request, results ...Result) {
	status := http.StatusOK
	for _, res := range results {
		if s := httpStatus(res.Code); s != http.StatusOK {
			status = s
			break
		}
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="linode-ddns", charset="UTF-8"`)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if wantsJSON(r.Header.Values("Accept")) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(struct {
			Results []Result `json:"results"`
		}{results})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	for _, res := range results {
		switch {
		case res.Code == CodeOK:
			fmt.Fprintf(w, "%s %s\n", res.Type, res.IP)
		case res.IP != "":
			fmt.Fprintf(w, "%s %s\n", res.Code, res.IP)
		default:
			fmt.Fprintln(w, res.Code)
		}
	}
}

// wantsJSON reports whether the Accept header prefers application/json over
// text/plain. Ties, including */* and an absent header, go to text.
func wantsJSON(accept []string) bool {
	return quality(accept, "application", "json") > quality(accept, "text", "plain")
}

// quality returns the q-value of the most specific Accept range matching
// typ/sub, or 0 when nothing matches.
func quality(accept []string, typ, sub string) float64 {
	bestSpec, bestQ := -1, 0.0
	for _, header := range accept {
		for _, part := range strings.Split(header, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			t, s, _ := strings.Cut(mt, "/")
			var spec int
			switch {
			case t == typ && s == sub:
				spec = 2
			case t == typ && s == "*":
				spec = 1
			case t == "*" && s == "*":
				spec = 0
			default:
				continue
			}
			if spec <= bestSpec {
				continue
			}
			q := 1.0
			if v, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					q = f
				}
			}
			bestSpec, bestQ = spec, q
		}
	}
	return bestQ
}

// Package linode is a minimal client for the Linode API v4 Domains endpoints.
package linode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the Linode API v4 root.
const DefaultBaseURL = "https://api.linode.com/v4"

const pageSize = 500

// maxResponseBytes bounds a decoded response body. A full page of records is
// well under 1 MiB.
const maxResponseBytes = 8 << 20

// ErrNotFound is returned when the API responds 404.
var ErrNotFound = errors.New("linode: not found")

type Domain struct {
	ID     int    `json:"id"`
	Domain string `json:"domain"`
}

type Record struct {
	ID     int    `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Target string `json:"target"`
}

// APIError is a non-2xx API response.
type APIError struct {
	Status  int
	Reasons []string
}

func (e *APIError) Error() string {
	if len(e.Reasons) == 0 {
		return fmt.Sprintf("linode: HTTP %d", e.Status)
	}
	return fmt.Sprintf("linode: HTTP %d: %s", e.Status, strings.Join(e.Reasons, "; "))
}

// Client talks to the Linode API. The token is supplied per call so one client
// can serve multiple users.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient() *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) ListDomains(ctx context.Context, token string) ([]Domain, error) {
	return listAll[Domain](ctx, c, token, "/domains")
}

func (c *Client) ListRecords(ctx context.Context, token string, domainID int) ([]Record, error) {
	return listAll[Record](ctx, c, token, "/domains/"+strconv.Itoa(domainID)+"/records")
}

// UpdateRecordTarget sets the target of an existing record.
func (c *Client) UpdateRecordTarget(ctx context.Context, token string, domainID, recordID int, target string) (*Record, error) {
	body, err := json.Marshal(map[string]string{"target": target})
	if err != nil {
		return nil, err
	}
	var rec Record
	path := fmt.Sprintf("/domains/%d/records/%d", domainID, recordID)
	if err := c.do(ctx, token, http.MethodPut, path, nil, body, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

type page[T any] struct {
	Data  []T `json:"data"`
	Page  int `json:"page"`
	Pages int `json:"pages"`
}

func listAll[T any](ctx context.Context, c *Client, token, path string) ([]T, error) {
	var all []T
	for n := 1; ; n++ {
		q := url.Values{"page": {strconv.Itoa(n)}, "page_size": {strconv.Itoa(pageSize)}}
		var p page[T]
		if err := c.do(ctx, token, http.MethodGet, path, q, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		if n >= p.Pages {
			return all, nil
		}
	}
}

func (c *Client) do(ctx context.Context, token, method, path string, query url.Values, body []byte, out any) error {
	u := strings.TrimSuffix(c.BaseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("linode: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		var e struct {
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&e) == nil {
			for _, r := range e.Errors {
				apiErr.Reasons = append(apiErr.Reasons, r.Reason)
			}
		}
		return apiErr
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("linode: decode %s %s: %w", method, path, err)
	}
	return nil
}

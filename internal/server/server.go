// Package server implements the HTTP API used by DDNS clients.
package server

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"linode-ddns/internal/config"
	"linode-ddns/internal/linode"
)

type Server struct {
	cfg      *config.Config
	resolver *linode.Resolver
	log      *slog.Logger
	mux      *http.ServeMux

	// dummyHash is compared against for unknown usernames so that response
	// time does not reveal which usernames exist.
	dummyHash []byte
	limiter   *failLimiter
}

func New(cfg *config.Config, resolver *linode.Resolver, log *slog.Logger) *Server {
	dummy, err := bcrypt.GenerateFromPassword([]byte("linode-ddns-dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	s := &Server{cfg: cfg, resolver: resolver, log: log, mux: http.NewServeMux(), dummyHash: dummy, limiter: newFailLimiter()}
	s.mux.HandleFunc("GET /v1/status", s.handleStatus)
	s.mux.HandleFunc("GET /v1/update", s.handleUpdate)
	return s
}

// ServeHTTP routes the request and logs one line per request with its outcome.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.mux.ServeHTTP(rec, r)
	s.log.Info("request",
		"method", r.Method,
		"path", r.URL.Path,
		"domain", r.URL.Query().Get("domain"),
		"remote", s.clientIP(r),
		"status", rec.status,
		"duration", time.Since(start).Round(time.Millisecond),
	)
}

// clientIP returns the client address for logging. When the direct peer is a
// trusted proxy, X-Forwarded-For is walked from right to left, skipping trusted
// proxies, and the first untrusted address is returned. Without trusted
// proxies the header is ignored, since clients can set it to anything.
func (s *Server) clientIP(r *http.Request) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	client := peer.Addr().Unmap()
	if !s.cfg.TrustedProxy(client) {
		return client.String()
	}

	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // Malformed entry; keep the last address we could verify.
		}
		client = addr.Unmap()
		if !s.cfg.TrustedProxy(client) {
			break
		}
	}
	return client.String()
}

// statusRecorder captures the response status for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// authenticate checks basic auth credentials and returns the user, or nil.
// Wrong credentials count against the client's failed login limit.
func (s *Server) authenticate(r *http.Request, client string) *config.User {
	name, pass, ok := r.BasicAuth()
	if !ok {
		s.log.Info("auth failed", "reason", "no credentials", "remote", client)
		return nil
	}
	u := s.cfg.User(name)
	if u == nil {
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(pass))
		s.limiter.fail(client)
		s.log.Warn("auth failed", "reason", "unknown user", "user", name, "remote", client)
		return nil
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pass)) != nil {
		s.limiter.fail(client)
		s.log.Warn("auth failed", "reason", "wrong password", "user", name, "remote", client)
		return nil
	}
	return u
}

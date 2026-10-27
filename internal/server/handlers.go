package server

import (
	"errors"
	"math"
	"net/http"
	"net/netip"
	"strconv"

	"linode-ddns/internal/config"
	"linode-ddns/internal/linode"
)

// recordRequest is one record to update: A for ip, AAAA for ipv6.
type recordRequest struct {
	typ string
	ip  netip.Addr
}

// handleUpdate serves GET /v1/update?domain=<host>&ip=<ipv4>&ipv6=<ipv6>.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	u, host, ok := s.authorize(w, r)
	if !ok {
		return
	}

	ip4, ip6 := r.URL.Query().Get("ip"), r.URL.Query().Get("ipv6")
	s.log.Info("update requested", "user", u.Username, "host", host, "ip", ip4, "ipv6", ip6)
	reqs, msg := parseIPs(ip4, ip6)
	if msg != "" {
		s.log.Info("update rejected", "user", u.Username, "host", host, "reason", msg)
		write(w, r, Result{Code: CodeBadIP, Message: msg})
		return
	}

	results := make([]Result, 0, len(reqs))
	for _, req := range reqs {
		res := Result{Type: req.typ, IP: req.ip.String()}
		changed, err := s.resolver.Update(r.Context(), u.LinodeAPIToken, host, req.typ, req.ip)
		switch {
		case err != nil:
			res = s.failure(req.typ, host, u.Username, err)
		case changed:
			res.Code = CodeGood
		default:
			res.Code = CodeNoChg
		}
		s.log.Info("update", "user", u.Username, "host", host, "type", req.typ, "ip", req.ip, "result", res.Code)
		results = append(results, res)
	}
	write(w, r, results...)
}

// handleStatus serves GET /v1/status?domain=<host> with the current A and AAAA
// targets.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	u, host, ok := s.authorize(w, r)
	if !ok {
		return
	}

	s.log.Info("status requested", "user", u.Username, "host", host)
	var results []Result
	for _, typ := range []string{"A", "AAAA"} {
		target, err := s.resolver.Current(r.Context(), u.LinodeAPIToken, host, typ)
		switch {
		case errors.Is(err, linode.ErrNoHost):
			s.log.Info("status", "user", u.Username, "host", host, "type", typ, "result", "no record")
			continue
		case err != nil:
			res := s.failure(typ, host, u.Username, err)
			s.log.Info("status", "user", u.Username, "host", host, "type", typ, "result", res.Code)
			results = append(results, res)
		default:
			s.log.Info("status", "user", u.Username, "host", host, "type", typ, "ip", target, "result", CodeOK)
			results = append(results, Result{Type: typ, Code: CodeOK, IP: target})
		}
	}
	if len(results) == 0 {
		results = append(results, Result{Code: CodeNoHost, Message: "no A or AAAA record for " + host})
	}
	write(w, r, results...)
}

// authorize authenticates the request and validates its domain parameter. On
// failure it writes the response and returns ok=false.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (u *config.User, host string, ok bool) {
	client := s.clientIP(r)
	if wait, blocked := s.limiter.blocked(client); blocked {
		s.log.Warn("auth blocked", "reason", "too many failed logins", "remote", client)
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		write(w, r, Result{Code: CodeAbuse, Message: "too many failed logins"})
		return nil, "", false
	}
	if u = s.authenticate(r, client); u == nil {
		write(w, r, Result{Code: CodeBadAuth})
		return nil, "", false
	}
	host = config.NormalizeHost(r.URL.Query().Get("domain"))
	if !config.ValidHost(host) {
		s.log.Info("invalid domain", "user", u.Username, "domain", r.URL.Query().Get("domain"))
		write(w, r, Result{Code: CodeNotFQDN, Message: "domain must be a fully qualified hostname"})
		return nil, "", false
	}
	if !u.Allows(host) {
		s.log.Warn("host not allowed", "user", u.Username, "host", host)
		write(w, r, Result{Code: CodeNoHost, Message: host + " is not configured for this user"})
		return nil, "", false
	}
	return u, host, true
}

// failure converts a resolver error into a result, logging unexpected errors.
func (s *Server) failure(typ, host, user string, err error) Result {
	if errors.Is(err, linode.ErrNoHost) {
		return Result{Type: typ, Code: CodeNoHost, Message: "no " + typ + " record for " + host}
	}
	s.log.Error("linode api", "user", user, "host", host, "type", typ, "err", err)
	return Result{Type: typ, Code: CodeError, Message: "upstream error"}
}

// parseIPs validates the ip (IPv4) and ipv6 parameters. At least one is
// required. A non-empty message describes the problem.
func parseIPs(ip4, ip6 string) ([]recordRequest, string) {
	if ip4 == "" && ip6 == "" {
		return nil, "ip or ipv6 is required"
	}
	var reqs []recordRequest
	if ip4 != "" {
		a, err := netip.ParseAddr(ip4)
		if err != nil || !a.Is4() {
			return nil, "ip must be an IPv4 address"
		}
		reqs = append(reqs, recordRequest{"A", a})
	}
	if ip6 != "" {
		a, err := netip.ParseAddr(ip6)
		if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
			return nil, "ipv6 must be an IPv6 address"
		}
		reqs = append(reqs, recordRequest{"AAAA", a})
	}
	return reqs, ""
}

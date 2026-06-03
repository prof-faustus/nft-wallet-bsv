// auth.go — the local control boundary for the sidecar (security hardening
// for the WS7 IPC surface, docs/06; CLAUDE.md §4 "no overclaiming": the
// sidecar is where keys live, so its mutating routes MUST authenticate the
// caller, not merely bind loopback).
//
// Threat model this addresses:
//   - A malicious LOCAL process probing 127.0.0.1 to drive money-moving
//     routes (key creation, fund, mint, swap, shred, attest).
//   - A malicious WEBPAGE issuing cross-origin POSTs to the loopback port
//     (CSRF). The browser cannot read the response, but a blind POST can
//     still trigger an action — so binding loopback is NOT sufficient.
//
// Defences (all enforced BEFORE the body is read or any action runs):
//   - A high-entropy per-process control token, required in a custom header
//     on every MUTATING route. A custom header forces a CORS preflight that
//     this server never answers, so a cross-origin page cannot set it; a
//     local process must know the token (printed at startup / handed to the
//     shell that launched the sidecar).
//   - POST-only for mutating routes (rejects GET/HEAD form navigations).
//   - application/json required (rejects browser form content-types that can
//     be sent cross-origin without preflight).
//   - Origin / Sec-Fetch-Site checks (defence in depth against CSRF).
//   - http.MaxBytesReader body cap → 413 on oversize (DoS/robustness).
//
// MUST NOT: weaken to "loopback is enough"; expose keys; import BTC.
package sidecar

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ControlTokenHeader is the custom header carrying the per-process control
// token. Custom (non-CORS-safelisted) headers cannot be set on a cross-origin
// request without a preflight this server never grants — defeating CSRF.
const ControlTokenHeader = "X-NFTBSV-Control-Token" //nolint:gosec // header name, not a secret

// maxControlBodyBytes bounds a request body on the control surface. Named, not
// magic (CLAUDE.md §6): the largest legitimate body (a swap-review tx) is far
// under 1 MiB; anything larger is rejected with 413.
const maxControlBodyBytes int64 = 1 << 20 // 1 MiB

// newControlToken returns a fresh 256-bit hex control token.
func newControlToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand failure is fatal for a security token; surface via an
		// unusable (empty) token so guard() denies everything.
		return ""
	}
	return hex.EncodeToString(b[:])
}

// SetControlToken overrides the per-process token (used by the launcher to pin
// a token it shares with the shell, and by tests). An empty token makes the
// guard deny all mutating requests (fail-closed).
func (s *Server) SetControlToken(tok string) { s.mu.Lock(); s.token = tok; s.mu.Unlock() }

// ControlToken returns the current control token so the launcher can hand it
// to the shell and the served control panel can embed it for same-origin use.
func (s *Server) ControlToken() string { s.mu.Lock(); defer s.mu.Unlock(); return s.token }

// guard wraps a MUTATING handler with the control-boundary checks. It rejects
// (before reading the body or running the action) any request that is not a
// same-site, token-bearing, JSON POST, and caps the body. Read-only routes
// (/status, /address, /healthz, /v2/options) are NOT wrapped.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed (mutating routes are POST-only)", http.StatusMethodNotAllowed)
			return
		}
		// CSRF: reject explicit cross-site browser submissions.
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !loopbackOrigin(origin) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
		// Require JSON: blocks the form-encoded/simple content-types a page
		// can POST cross-origin without a preflight.
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
			http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		// Capability token (constant-time compare; fail-closed on empty).
		want := s.ControlToken()
		got := r.Header.Get(ControlTokenHeader)
		if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "missing or invalid control token", http.StatusUnauthorized)
			return
		}
		// Bound the body for every downstream reader (413 on oversize).
		r.Body = http.MaxBytesReader(w, r.Body, maxControlBodyBytes)
		h(w, r)
	}
}

// loopbackOrigin reports whether an Origin header names a loopback host (any
// scheme/port). The sidecar binds loopback, so a legitimate same-machine UI is
// loopback-origin; anything else is a cross-host attempt.
func loopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

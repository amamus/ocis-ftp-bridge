// Package http provides the operations HTTP server (health, readiness,
// metrics) for ocis-ftp-bridge.
//
// This file implements optional authentication for the operations endpoints.
package http

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthConfig configures authentication for the operations HTTP endpoints.
type AuthConfig struct {
	// Enabled turns authentication on. When false, requests pass through.
	Enabled bool
	// Method is "basic" or "bearer".
	Method string
	// Username and Password are the basic-auth credentials.
	Username string
	Password string
	// Token is the bearer token.
	Token string
}

// authRealm is sent in the WWW-Authenticate challenge header.
const authRealm = "ocis-ftp-bridge"

// middleware wraps next with authentication according to the config.
// Credential comparisons are constant-time to avoid leaking them through
// timing side channels. Any misconfiguration (unknown method, empty
// credential) fails closed.
func (c AuthConfig) middleware(next http.Handler) http.Handler {
	if !c.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.authenticate(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// authenticate reports whether the request carries valid credentials.
func (c AuthConfig) authenticate(r *http.Request) bool {
	switch c.Method {
	case "basic":
		// Fail closed: an empty configured password authenticates no one.
		if c.Password == "" {
			return false
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			return false
		}
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(c.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(c.Password)) == 1
		return userOK && passOK
	case "bearer":
		// Fail closed: an empty configured token authenticates no one.
		if c.Token == "" {
			return false
		}
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			return false
		}
		token := strings.TrimPrefix(header, prefix)
		return subtle.ConstantTimeCompare([]byte(token), []byte(c.Token)) == 1
	default:
		// Unknown method: fail closed.
		return false
	}
}

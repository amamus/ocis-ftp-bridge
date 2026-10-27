package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func basicAuthHeader(user, pass string) map[string]string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

func bearerHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func TestAuthMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	basic := AuthConfig{Enabled: true, Method: "basic", Username: "admin", Password: "secret"}
	bearer := AuthConfig{Enabled: true, Method: "bearer", Token: "test-token"}

	tests := []struct {
		name    string
		config  AuthConfig
		headers map[string]string
		want    int
	}{
		{"disabled passes without credentials", AuthConfig{Enabled: false}, nil, http.StatusOK},
		{"basic without credentials", basic, nil, http.StatusUnauthorized},
		{"basic with wrong password", basic, basicAuthHeader("admin", "wrong"), http.StatusUnauthorized},
		{"basic with wrong username", basic, basicAuthHeader("root", "secret"), http.StatusUnauthorized},
		{"basic with valid credentials", basic, basicAuthHeader("admin", "secret"), http.StatusOK},
		{"basic with empty configured password fails closed", AuthConfig{Enabled: true, Method: "basic", Username: "admin"}, basicAuthHeader("admin", ""), http.StatusUnauthorized},
		{"bearer without header", bearer, nil, http.StatusUnauthorized},
		{"bearer with wrong token", bearer, bearerHeader("wrong"), http.StatusUnauthorized},
		{"bearer with valid token", bearer, bearerHeader("test-token"), http.StatusOK},
		{"bearer with empty configured token fails closed", AuthConfig{Enabled: true, Method: "bearer"}, bearerHeader(""), http.StatusUnauthorized},
		{"unknown method fails closed", AuthConfig{Enabled: true, Method: "digest"}, nil, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			tt.config.middleware(handler).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// TestAuthMiddlewareChallengeHeader verifies that rejected requests carry a
// WWW-Authenticate challenge so HTTP clients know to send credentials.
func TestAuthMiddlewareChallengeHeader(t *testing.T) {
	cfg := AuthConfig{Enabled: true, Method: "basic", Username: "admin", Password: "secret"}
	rec := httptest.NewRecorder()
	cfg.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="ocis-ftp-bridge"` {
		t.Errorf("WWW-Authenticate = %q, want %q", got, `Basic realm="ocis-ftp-bridge"`)
	}
}

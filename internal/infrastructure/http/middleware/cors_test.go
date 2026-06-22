package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func runCORS(t *testing.T, allowed []string, method, origin string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(method, "/", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	c.Request = req
	CORSMiddleware(allowed)(c)
	return w
}

func TestCORS_wildcardHasNoCredentials(t *testing.T) {
	w := runCORS(t, []string{"*"}, http.MethodGet, "https://anything.example")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected wildcard origin, got %q", got)
	}
	// "*" + credentials is invalid per the CORS spec; we must not send it.
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("wildcard mode must not send credentials, got %q", got)
	}
}

func TestCORS_allowlistReflectsKnownOrigin(t *testing.T) {
	origin := "https://app.example"
	w := runCORS(t, []string{origin}, http.MethodGet, origin)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected reflected origin %q, got %q", origin, got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected credentials for a known origin, got %q", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("expected Vary: Origin, got %q", got)
	}
}

func TestCORS_allowlistRejectsUnknownOrigin(t *testing.T) {
	w := runCORS(t, []string{"https://app.example"}, http.MethodGet, "https://evil.example")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unknown origin must not be allowed, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("unknown origin must not receive credentials, got %q", got)
	}
}

func TestCORS_optionsShortCircuitsWith204(t *testing.T) {
	w := runCORS(t, []string{"*"}, http.MethodOptions, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS preflight, got %d", w.Code)
	}
}

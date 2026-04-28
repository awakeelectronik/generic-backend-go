package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newCtxWithHeader(header string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("POST", "/", nil)
	if header != "" {
		req.Header.Set("Idempotency-Key", header)
	}
	c.Request = req
	return c
}

func TestResolveUUIDIdempotencyKey_emptyBoth(t *testing.T) {
	key, bad := ResolveUUIDIdempotencyKey(newCtxWithHeader(""), "")
	if key != "" || bad != nil {
		t.Fatalf("expected empty key and nil bad, got key=%q bad=%v", key, bad)
	}
}

func TestResolveUUIDIdempotencyKey_headerWins(t *testing.T) {
	headerUUID := "11111111-1111-1111-1111-111111111111"
	bodyUUID := "22222222-2222-2222-2222-222222222222"
	key, bad := ResolveUUIDIdempotencyKey(newCtxWithHeader(headerUUID), bodyUUID)
	if bad != nil {
		t.Fatalf("expected no error, got %v", bad)
	}
	if key != headerUUID {
		t.Fatalf("expected header to win, got %q", key)
	}
}

func TestResolveUUIDIdempotencyKey_invalidHeaderRejected(t *testing.T) {
	key, bad := ResolveUUIDIdempotencyKey(newCtxWithHeader("not-a-uuid"), "22222222-2222-2222-2222-222222222222")
	if bad == nil {
		t.Fatalf("expected error for invalid header")
	}
	if key != "" {
		t.Fatalf("expected empty key on error, got %q", key)
	}
}

func TestResolveUUIDIdempotencyKey_bodyFallback(t *testing.T) {
	bodyUUID := "33333333-3333-3333-3333-333333333333"
	key, bad := ResolveUUIDIdempotencyKey(newCtxWithHeader(""), bodyUUID)
	if bad != nil {
		t.Fatalf("unexpected error: %v", bad)
	}
	if key != bodyUUID {
		t.Fatalf("expected body fallback, got %q", key)
	}
}

func TestResolveUUIDIdempotencyKey_invalidBodyRejected(t *testing.T) {
	key, bad := ResolveUUIDIdempotencyKey(newCtxWithHeader(""), "garbage")
	if bad == nil {
		t.Fatalf("expected error for invalid body uuid")
	}
	if key != "" {
		t.Fatalf("expected empty key on error, got %q", key)
	}
}

package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

func newTestRedisRateStore(t *testing.T) (RateStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return NewRedisRateStore(client, logger), mr
}

func TestRedisRateStore_allowsUpToRateThenBlocks(t *testing.T) {
	store, _ := newTestRedisRateStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if !store.Allow(ctx, "1.2.3.4", 3, time.Minute) {
			t.Fatalf("request %d within limit should be allowed", i+1)
		}
	}
	if store.Allow(ctx, "1.2.3.4", 3, time.Minute) {
		t.Fatalf("request over the limit should be blocked")
	}
}

func TestRedisRateStore_separatesByKeyAndWindow(t *testing.T) {
	store, _ := newTestRedisRateStore(t)
	ctx := context.Background()

	if !store.Allow(ctx, "1.1.1.1", 1, time.Minute) {
		t.Fatalf("first IP, first request should pass")
	}
	if !store.Allow(ctx, "2.2.2.2", 1, time.Minute) {
		t.Fatalf("second IP has its own bucket")
	}
	if store.Allow(ctx, "1.1.1.1", 1, time.Minute) {
		t.Fatalf("first IP, second request should be blocked")
	}
	// A different (rate, window) is a different bucket even for the same IP.
	if !store.Allow(ctx, "1.1.1.1", 5, 30*time.Second) {
		t.Fatalf("a distinct rate/window must not share the counter")
	}
}

// TestRedisRateStore_subSecondWindowsDoNotCollide guards the millisecond-keyed
// fix: two distinct sub-second windows for the same IP previously truncated to
// `0` seconds in the key and shared one counter.
func TestRedisRateStore_subSecondWindowsDoNotCollide(t *testing.T) {
	store, _ := newTestRedisRateStore(t)
	ctx := context.Background()

	// Exhaust the 200ms window (limit 1).
	if !store.Allow(ctx, "7.7.7.7", 1, 200*time.Millisecond) {
		t.Fatalf("first 200ms request should pass")
	}
	if store.Allow(ctx, "7.7.7.7", 1, 200*time.Millisecond) {
		t.Fatalf("second 200ms request should be blocked")
	}
	// The 500ms window is a separate bucket and must still allow its first hit.
	if !store.Allow(ctx, "7.7.7.7", 1, 500*time.Millisecond) {
		t.Fatalf("a distinct sub-second window must not share the counter")
	}
}

func TestRedisRateStore_resetsAfterWindow(t *testing.T) {
	store, mr := newTestRedisRateStore(t)
	ctx := context.Background()

	if !store.Allow(ctx, "9.9.9.9", 1, time.Minute) {
		t.Fatalf("first request should pass")
	}
	if store.Allow(ctx, "9.9.9.9", 1, time.Minute) {
		t.Fatalf("second request inside the window should be blocked")
	}
	// Advance miniredis past the window so the key TTL expires.
	mr.FastForward(2 * time.Minute)
	if !store.Allow(ctx, "9.9.9.9", 1, time.Minute) {
		t.Fatalf("request after the window elapses should pass again")
	}
}

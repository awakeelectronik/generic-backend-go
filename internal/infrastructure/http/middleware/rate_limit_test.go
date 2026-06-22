package middleware

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_allowsUpToRateThenBlocks(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d within limit should be allowed", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatalf("request over the limit should be blocked")
	}
}

func TestRateLimiter_separatesByIP(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	if !rl.allow("1.1.1.1") {
		t.Fatalf("first IP, first request should pass")
	}
	if !rl.allow("2.2.2.2") {
		t.Fatalf("second IP should have its own bucket")
	}
	if rl.allow("1.1.1.1") {
		t.Fatalf("first IP, second request should be blocked")
	}
}

func TestRateLimiter_resetsAfterWindow(t *testing.T) {
	rl := NewRateLimiter(1, 20*time.Millisecond)
	if !rl.allow("1.2.3.4") {
		t.Fatalf("first request should pass")
	}
	if rl.allow("1.2.3.4") {
		t.Fatalf("second request inside the window should be blocked")
	}
	time.Sleep(30 * time.Millisecond)
	if !rl.allow("1.2.3.4") {
		t.Fatalf("request after the window elapses should pass again")
	}
}

// TestRateLimiter_concurrentAllowCountsExactly guards the single-critical-section
// invariant: with a limit well above the load, every concurrent call must be
// counted (no lost updates). Run with -race to also catch data races.
func TestRateLimiter_concurrentAllowCountsExactly(t *testing.T) {
	rl := NewRateLimiter(1_000_000, time.Minute)

	const goroutines, perGoroutine = 50, 100
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				rl.allow("9.9.9.9")
			}
		}()
	}
	wg.Wait()

	rl.mu.Lock()
	got := rl.visitors["9.9.9.9"].count
	rl.mu.Unlock()

	if want := goroutines * perGoroutine; got != want {
		t.Fatalf("expected exactly %d counted requests, got %d", want, got)
	}
}

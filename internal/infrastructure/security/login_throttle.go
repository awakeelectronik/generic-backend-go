package security

import (
	"context"
	"sync"
	"time"
)

// LoginThrottlePolicy define el lockout por cuenta: tras MaxFailures fallos
// dentro de Window, la cuenta queda bloqueada por LockDuration.
type LoginThrottlePolicy struct {
	MaxFailures  int
	Window       time.Duration
	LockDuration time.Duration
}

// DefaultLoginThrottlePolicy: 10 fallos en 15 min → 15 min de bloqueo.
// Complementa el rate-limit por IP: frena ataques distribuidos (muchas IPs,
// una cuenta) sin castigar un dedazo ocasional.
func DefaultLoginThrottlePolicy() LoginThrottlePolicy {
	return LoginThrottlePolicy{
		MaxFailures:  10,
		Window:       15 * time.Minute,
		LockDuration: 15 * time.Minute,
	}
}

type accountFailures struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// memoryLoginThrottle es el backend in-process (una sola instancia; el estado
// se pierde al reiniciar — mismo tradeoff documentado que el rate-limiter).
type memoryLoginThrottle struct {
	mu       sync.Mutex
	policy   LoginThrottlePolicy
	accounts map[string]*accountFailures
}

// NewMemoryLoginThrottle crea el throttle in-memory con limpieza periódica
// para que el mapa no crezca sin límite.
func NewMemoryLoginThrottle(p LoginThrottlePolicy) *memoryLoginThrottle {
	t := &memoryLoginThrottle{
		policy:   p,
		accounts: make(map[string]*accountFailures),
	}
	go t.janitor()
	return t
}

func (t *memoryLoginThrottle) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		t.mu.Lock()
		for id, a := range t.accounts {
			if now.After(a.lockedUntil) && now.Sub(a.windowStart) > t.policy.Window {
				delete(t.accounts, id)
			}
		}
		t.mu.Unlock()
	}
}

func (t *memoryLoginThrottle) IsLocked(_ context.Context, accountID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.accounts[accountID]
	if !ok {
		return false
	}
	return time.Now().Before(a.lockedUntil)
}

func (t *memoryLoginThrottle) RegisterFailure(_ context.Context, accountID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	a, ok := t.accounts[accountID]
	if !ok || now.Sub(a.windowStart) > t.policy.Window {
		a = &accountFailures{windowStart: now}
		t.accounts[accountID] = a
	}
	a.count++
	if a.count >= t.policy.MaxFailures {
		a.lockedUntil = now.Add(t.policy.LockDuration)
	}
}

func (t *memoryLoginThrottle) Reset(_ context.Context, accountID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.accounts, accountID)
}

package security

import (
	"context"
	"sync"
	"time"

	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

// VerificationPolicy holds the throttling/expiry tunables shared by every
// VerificationStore implementation so the in-memory and Redis backends behave
// identically.
type VerificationPolicy struct {
	CodeTTL           time.Duration
	MinResendInterval time.Duration
	MaxSendsPerWindow int
	SendWindow        time.Duration
	MaxAttempts       int
}

// DefaultVerificationPolicy mirrors the historical in-memory constants.
func DefaultVerificationPolicy() VerificationPolicy {
	return VerificationPolicy{
		CodeTTL:           verificationCodeTTL,
		MinResendInterval: minResendInterval,
		MaxSendsPerWindow: maxSendsPerHourPerUser,
		SendWindow:        sendHistoryWindow,
		MaxAttempts:       maxVerificationAttempts,
	}
}

// VerificationStore persists verification codes and send-throttle state.
//
//   - memoryVerificationStore is process-local: state is lost on restart and is
//     NOT shared across instances. Fine for single-instance / dev.
//   - redisVerificationStore is restart-safe and shared across instances, which
//     is what a horizontally-scaled deployment needs (a code issued by one
//     replica must be verifiable by another).
//
// VerifyCode and RegisterSend must be atomic: concurrent callers must not race
// on the attempt counter or the send window.
type VerificationStore interface {
	// RegisterSend enforces send throttling and, if allowed, records the send.
	// Returns ErrVerificationRateLimited when throttled.
	RegisterSend(ctx context.Context, userID string) error
	// SaveCode stores a fresh code for userID, replacing any previous one and
	// resetting attempts/used, with the policy TTL.
	SaveCode(ctx context.Context, userID, code string) error
	// VerifyCode atomically validates the code, applying expiry/used/attempt
	// rules, and returns the matching typed verification error on failure.
	VerifyCode(ctx context.Context, userID, code string) error
	// PeekCode returns the current stored code (tests / dev console).
	PeekCode(ctx context.Context, userID string) (string, bool)
	// ResetSends clears send throttling for a user (integration tests).
	ResetSends(ctx context.Context, userID string)
	// CleanupExpired purges expired codes. No-op where TTL handles it (Redis).
	CleanupExpired(ctx context.Context)
}

// memoryVerificationStore is the in-process backend. It is the historical
// behavior, extracted verbatim behind the VerificationStore interface.
type memoryVerificationStore struct {
	mu          sync.Mutex
	policy      VerificationPolicy
	codes       map[string]*VerificationCode
	sendHistory map[string][]time.Time // per user: timestamps of code sends
}

func newMemoryVerificationStore(p VerificationPolicy) *memoryVerificationStore {
	return &memoryVerificationStore{
		policy:      p,
		codes:       make(map[string]*VerificationCode),
		sendHistory: make(map[string][]time.Time),
	}
}

func (s *memoryVerificationStore) RegisterSend(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.assertSendAllowedLocked(userID); err != nil {
		return err
	}
	s.cleanupExpiredLocked()
	s.sendHistory[userID] = append(s.sendHistory[userID], time.Now())
	return nil
}

func (s *memoryVerificationStore) assertSendAllowedLocked(userID string) error {
	now := time.Now()
	history := s.sendHistory[userID]
	var recent []time.Time
	for _, t := range history {
		if now.Sub(t) <= s.policy.SendWindow {
			recent = append(recent, t)
		}
	}
	s.sendHistory[userID] = recent

	if len(recent) >= s.policy.MaxSendsPerWindow {
		return appErrors.ErrVerificationRateLimited
	}
	if len(recent) > 0 {
		last := recent[len(recent)-1]
		if now.Sub(last) < s.policy.MinResendInterval {
			return appErrors.ErrVerificationRateLimited
		}
	}
	return nil
}

func (s *memoryVerificationStore) SaveCode(_ context.Context, userID, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Nuevo envío invalida el código anterior (mismo almacén por userID).
	s.codes[userID] = &VerificationCode{
		UserID:    userID,
		Code:      code,
		ExpiresAt: time.Now().Add(s.policy.CodeTTL),
		Used:      false,
	}
	return nil
}

func (s *memoryVerificationStore) VerifyCode(_ context.Context, userID, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.codes[userID]
	if !exists {
		return appErrors.ErrVerificationCodeNotFound
	}
	if stored.Used {
		return appErrors.ErrVerificationCodeUsed
	}
	if time.Now().After(stored.ExpiresAt) {
		return appErrors.ErrVerificationCodeExpired
	}
	if stored.Attempts >= s.policy.MaxAttempts {
		// Cierre defensivo: una vez agotados los intentos, el código queda
		// inutilizable aun si el siguiente envío llega correcto. Forzar
		// reenvío evita brute-force con el código vigente.
		stored.Used = true
		return appErrors.ErrVerificationCodeAttemptsExceeded
	}
	if stored.Code != code {
		stored.Attempts++
		if stored.Attempts >= s.policy.MaxAttempts {
			stored.Used = true
		}
		return appErrors.ErrVerificationCodeInvalid
	}

	stored.Used = true
	return nil
}

func (s *memoryVerificationStore) PeekCode(_ context.Context, userID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.codes[userID]
	if !ok || stored == nil {
		return "", false
	}
	return stored.Code, true
}

func (s *memoryVerificationStore) ResetSends(_ context.Context, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sendHistory, userID)
}

func (s *memoryVerificationStore) CleanupExpired(_ context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked()
}

func (s *memoryVerificationStore) cleanupExpiredLocked() {
	now := time.Now()
	for userID, code := range s.codes {
		if now.After(code.ExpiresAt) {
			delete(s.codes, userID)
		}
	}
}

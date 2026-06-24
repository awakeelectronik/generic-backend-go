package security

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/redis/go-redis/v9"
)

// newTestRedisStore spins up an in-process miniredis and returns a
// redisVerificationStore wired to it with a fast policy for tests.
func newTestRedisStore(t *testing.T, p VerificationPolicy) VerificationStore {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisVerificationStore(client, p)
}

func fastPolicy() VerificationPolicy {
	return VerificationPolicy{
		CodeTTL:           time.Hour,
		MinResendInterval: 10 * time.Millisecond,
		MaxSendsPerWindow: 3,
		SendWindow:        time.Hour,
		MaxAttempts:       3,
	}
}

func TestRedisStore_saveAndVerifyHappyPath(t *testing.T) {
	s := newTestRedisStore(t, fastPolicy())
	ctx := context.Background()

	if err := s.SaveCode(ctx, "u1", "123456"); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if code, ok := s.PeekCode(ctx, "u1"); !ok || code != "123456" {
		t.Fatalf("PeekCode = %q, %v", code, ok)
	}
	if err := s.VerifyCode(ctx, "u1", "123456"); err != nil {
		t.Fatalf("expected verify to succeed, got %v", err)
	}
	// Second use of a consumed code must fail.
	if err := s.VerifyCode(ctx, "u1", "123456"); !stderrors.Is(err, appErrors.ErrVerificationCodeUsed) {
		t.Fatalf("expected ErrVerificationCodeUsed, got %v", err)
	}
}

func TestRedisStore_notFound(t *testing.T) {
	s := newTestRedisStore(t, fastPolicy())
	if err := s.VerifyCode(context.Background(), "nobody", "000000"); !stderrors.Is(err, appErrors.ErrVerificationCodeNotFound) {
		t.Fatalf("expected ErrVerificationCodeNotFound, got %v", err)
	}
}

func TestRedisStore_wrongCodeAttemptsLockout(t *testing.T) {
	p := fastPolicy()
	s := newTestRedisStore(t, p)
	ctx := context.Background()

	if err := s.SaveCode(ctx, "u2", "654321"); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	for i := 0; i < p.MaxAttempts; i++ {
		if err := s.VerifyCode(ctx, "u2", "000000"); !stderrors.Is(err, appErrors.ErrVerificationCodeInvalid) {
			t.Fatalf("attempt %d: expected ErrVerificationCodeInvalid, got %v", i+1, err)
		}
	}
	// Hitting the attempt cap consumes the code: even the correct value fails.
	if err := s.VerifyCode(ctx, "u2", "654321"); !stderrors.Is(err, appErrors.ErrVerificationCodeUsed) {
		t.Fatalf("expected ErrVerificationCodeUsed after lockout, got %v", err)
	}
}

func TestRedisStore_expired(t *testing.T) {
	p := fastPolicy()
	p.CodeTTL = 20 * time.Millisecond
	s := newTestRedisStore(t, p)
	ctx := context.Background()

	if err := s.SaveCode(ctx, "u3", "111111"); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if err := s.VerifyCode(ctx, "u3", "111111"); !stderrors.Is(err, appErrors.ErrVerificationCodeExpired) {
		t.Fatalf("expected ErrVerificationCodeExpired, got %v", err)
	}
}

func TestRedisStore_sendThrottleMinInterval(t *testing.T) {
	p := fastPolicy()
	s := newTestRedisStore(t, p)
	ctx := context.Background()

	if err := s.RegisterSend(ctx, "u4"); err != nil {
		t.Fatalf("first send should pass: %v", err)
	}
	// Immediate resend violates MinResendInterval.
	if err := s.RegisterSend(ctx, "u4"); !stderrors.Is(err, appErrors.ErrVerificationRateLimited) {
		t.Fatalf("expected rate limited on immediate resend, got %v", err)
	}
	time.Sleep(p.MinResendInterval + 5*time.Millisecond)
	if err := s.RegisterSend(ctx, "u4"); err != nil {
		t.Fatalf("send after min interval should pass: %v", err)
	}
}

func TestRedisStore_sendThrottleMaxPerWindow(t *testing.T) {
	p := fastPolicy()
	s := newTestRedisStore(t, p)
	ctx := context.Background()

	for i := 0; i < p.MaxSendsPerWindow; i++ {
		if err := s.RegisterSend(ctx, "u5"); err != nil {
			t.Fatalf("send %d within window should pass: %v", i+1, err)
		}
		time.Sleep(p.MinResendInterval + 5*time.Millisecond)
	}
	// One more exceeds MaxSendsPerWindow.
	if err := s.RegisterSend(ctx, "u5"); !stderrors.Is(err, appErrors.ErrVerificationRateLimited) {
		t.Fatalf("expected rate limited beyond window cap, got %v", err)
	}
	// ResetSends clears the window.
	s.ResetSends(ctx, "u5")
	if err := s.RegisterSend(ctx, "u5"); err != nil {
		t.Fatalf("after ResetSends a send should pass: %v", err)
	}
}

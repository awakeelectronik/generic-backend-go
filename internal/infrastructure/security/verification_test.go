package security

import (
	stderrors "errors"
	"testing"

	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type recordingSender struct {
	calls int
}

func (r *recordingSender) Send(to, subject, body string) error {
	r.calls++
	return nil
}

func newSilentLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

func TestVerificationService_emailDestinationCallsSender(t *testing.T) {
	sender := &recordingSender{}
	svc := NewVerificationService(sender, "TestApp", "#000000", newSilentLogger())

	if err := svc.SendVerificationCode("user-1", "u@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("expected sender to be called once, got %d", sender.calls)
	}
	if _, ok := svc.GetDebugCode("user-1"); !ok {
		t.Fatalf("expected a stored code for user-1")
	}
}

func TestVerificationService_phoneDestinationDoesNotCallSender(t *testing.T) {
	sender := &recordingSender{}
	svc := NewVerificationService(sender, "TestApp", "#000000", newSilentLogger())

	if err := svc.SendVerificationCode("user-2", "3001234567"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("phone should not call email sender, got %d calls", sender.calls)
	}
}

func TestVerificationService_minIntervalRejectsSecondSend(t *testing.T) {
	svc := NewVerificationService(&recordingSender{}, "TestApp", "#000000", newSilentLogger())

	if err := svc.SendVerificationCode("user-3", "u@example.com"); err != nil {
		t.Fatalf("first send failed: %v", err)
	}
	err := svc.SendVerificationCode("user-3", "u@example.com")
	if err == nil {
		t.Fatalf("expected rate limit error on immediate resend")
	}
	if !stderrors.Is(err, appErrors.ErrVerificationRateLimited) {
		t.Fatalf("expected ErrVerificationRateLimited, got %v", err)
	}
}

func TestVerificationService_resetRateLimitClearsHistory(t *testing.T) {
	svc := NewVerificationService(&recordingSender{}, "TestApp", "#000000", newSilentLogger())

	if err := svc.SendVerificationCode("user-4", "u@example.com"); err != nil {
		t.Fatalf("first send failed: %v", err)
	}
	svc.ResetRateLimitsForUser("user-4")
	if err := svc.SendVerificationCode("user-4", "u@example.com"); err != nil {
		t.Fatalf("expected reset to allow immediate resend, got %v", err)
	}
}

func TestVerificationService_verifyCodeFlow(t *testing.T) {
	svc := NewVerificationService(&recordingSender{}, "TestApp", "#000000", newSilentLogger())

	if err := svc.SendVerificationCode("user-5", "u@example.com"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	code, ok := svc.GetDebugCode("user-5")
	if !ok {
		t.Fatalf("expected a stored code")
	}
	if err := svc.VerifyCode("user-5", code); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	// Second verify with same code should fail (already used).
	if err := svc.VerifyCode("user-5", code); err == nil {
		t.Fatalf("expected reuse of code to fail")
	}
}

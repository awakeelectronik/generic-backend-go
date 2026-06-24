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

// TestVerificationService_codeIsSixDigits guards the 4->6 digit widening: a
// 4-digit code has only 10k combinations and is brute-forceable within the
// attempt window; 6 digits raises that to 1M.
func TestVerificationService_codeIsSixDigits(t *testing.T) {
	svc := NewVerificationService(&recordingSender{}, "TestApp", "#000000", newSilentLogger())
	if err := svc.SendVerificationCode("user-6digit", "u@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	code, ok := svc.GetDebugCode("user-6digit")
	if !ok {
		t.Fatal("expected a stored code")
	}
	if len(code) != 6 {
		t.Fatalf("expected a 6-digit code, got %q (len %d)", code, len(code))
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("expected only digits, got %q", code)
		}
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

func wrongCodeFor(code string) string {
	if code == "0000" {
		return "9999"
	}
	return "0000"
}

func TestVerificationService_attemptLimitInvalidatesCode(t *testing.T) {
	svc := NewVerificationService(&recordingSender{}, "TestApp", "#000000", newSilentLogger())

	const userID = "user-attempts"
	if err := svc.SendVerificationCode(userID, "u@example.com"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	correct, ok := svc.GetDebugCode(userID)
	if !ok {
		t.Fatalf("expected a stored code")
	}
	wrong := wrongCodeFor(correct)

	// Agotar los intentos con códigos incorrectos.
	for i := 0; i < maxVerificationAttempts; i++ {
		err := svc.VerifyCode(userID, wrong)
		if err == nil {
			t.Fatalf("wrong attempt %d unexpectedly succeeded", i+1)
		}
		if !stderrors.Is(err, appErrors.ErrVerificationCodeInvalid) {
			t.Fatalf("attempt %d: expected ErrVerificationCodeInvalid, got %v", i+1, err)
		}
	}

	// El correcto ya no debe valer: el código quedó invalidado.
	err := svc.VerifyCode(userID, correct)
	if err == nil {
		t.Fatalf("correct code succeeded after attempt limit was exhausted")
	}
	// Tras agotar intentos, el código queda marcado como usado, así que el
	// siguiente VerifyCode devuelve ErrVerificationCodeUsed.
	if !stderrors.Is(err, appErrors.ErrVerificationCodeUsed) {
		t.Fatalf("expected ErrVerificationCodeUsed after lockout, got %v", err)
	}
}

func TestVerificationService_correctCodeBeforeAttemptLimitSucceeds(t *testing.T) {
	svc := NewVerificationService(&recordingSender{}, "TestApp", "#000000", newSilentLogger())

	const userID = "user-attempts-ok"
	if err := svc.SendVerificationCode(userID, "u@example.com"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	correct, ok := svc.GetDebugCode(userID)
	if !ok {
		t.Fatalf("expected a stored code")
	}

	// Un fallo previo no debe impedir validar con el correcto antes del límite.
	if err := svc.VerifyCode(userID, wrongCodeFor(correct)); err == nil {
		t.Fatalf("wrong code unexpectedly succeeded")
	}
	if err := svc.VerifyCode(userID, correct); err != nil {
		t.Fatalf("correct code before attempt limit: %v", err)
	}
}

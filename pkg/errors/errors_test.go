package errors

import (
	stderrors "errors"
	"testing"
)

func TestNewAppErrorWithData_carriesPayload(t *testing.T) {
	payload := map[string]string{"user_id": "abc"}
	e := NewAppErrorWithData("UNVERIFIED_USER", "msg", 403, payload)

	if e.Code != "UNVERIFIED_USER" || e.StatusCode != 403 || e.Message != "msg" {
		t.Fatalf("unexpected fields: %+v", e)
	}
	got, ok := e.Data.(map[string]string)
	if !ok || got["user_id"] != "abc" {
		t.Fatalf("data payload not preserved: %+v", e.Data)
	}
}

func TestErrVerificationRateLimited_isSentinel(t *testing.T) {
	wrapped := stderrors.Join(stderrors.New("a"), ErrVerificationRateLimited)
	if !stderrors.Is(wrapped, ErrVerificationRateLimited) {
		t.Fatalf("expected errors.Is to detect sentinel through Join")
	}
}

func TestNewNotFoundError_spanishMessage(t *testing.T) {
	e := NewNotFoundError("Usuario")
	if e.Code != "NOT_FOUND" || e.StatusCode != 404 {
		t.Fatalf("unexpected code/status: %+v", e)
	}
	if e.Message != "Usuario no encontrado" {
		t.Fatalf("expected Spanish message, got %q", e.Message)
	}
}

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/gin-gonic/gin"
)

func recorderCtx() (*httptest.ResponseRecorder, *gin.Context) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	return w, c
}

func TestHandleError_appError4xxPassesThrough(t *testing.T) {
	w, c := recorderCtx()
	HandleError(c, appErrors.NewAppError("VALIDATION_ERROR", "campo inválido", http.StatusBadRequest))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var body ErrorResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Success {
		t.Fatalf("success must be false on error")
	}
	if body.Code != "VALIDATION_ERROR" || body.Message != "campo inválido" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

// TestHandleError_serverErrorMasksMessage is the important one: 5xx responses
// must keep the code but never leak the internal message to the client.
func TestHandleError_serverErrorMasksMessage(t *testing.T) {
	w, c := recorderCtx()
	HandleError(c, appErrors.NewAppErrorWithInternal("DB_ERROR", "dsn=root:secret@tcp(...)", 500, nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	var body ErrorResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Code != "DB_ERROR" {
		t.Fatalf("code should be preserved, got %q", body.Code)
	}
	if body.Message != "Error interno del servidor" {
		t.Fatalf("5xx message must be masked, got %q", body.Message)
	}
}

func TestHandleError_includesDataFor4xx(t *testing.T) {
	w, c := recorderCtx()
	HandleError(c, appErrors.NewAppErrorWithData("UNVERIFIED_USER", "verifica", http.StatusForbidden, map[string]string{"user_id": "u1"}))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data, ok := raw["data"].(map[string]any)
	if !ok || data["user_id"] != "u1" {
		t.Fatalf("expected data.user_id=u1, got %v", raw["data"])
	}
}

func TestHandleError_nonAppErrorIsGeneric500(t *testing.T) {
	w, c := recorderCtx()
	HandleError(c, errors.New("raw boom with internals"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	var body ErrorResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Code != "INTERNAL_ERROR" || body.Message != "Error interno del servidor" {
		t.Fatalf("unexpected generic body: %+v", body)
	}
}

func TestSuccessResponse_envelope(t *testing.T) {
	w, c := recorderCtx()
	SuccessResponse(c, http.StatusCreated, map[string]string{"id": "42"})

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	var body SuccessResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.Success {
		t.Fatalf("success must be true")
	}
	data, ok := body.Data.(map[string]any)
	if !ok || data["id"] != "42" {
		t.Fatalf("unexpected data: %v", body.Data)
	}
}

func TestErrorResponse_envelope(t *testing.T) {
	w, c := recorderCtx()
	ErrorResponse(c, http.StatusBadRequest, "BAD", "nope")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var body ErrorResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Success || body.Code != "BAD" || body.Message != "nope" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

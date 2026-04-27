package errors

import (
	stderrors "errors"
	"fmt"
	"net/http"
)

// ErrVerificationRateLimited indicates too many verification code sends for the user.
var ErrVerificationRateLimited = stderrors.New("verification code rate limited")

type AppError struct {
	Code       string      `json:"code"`
	Message    string      `json:"message"`
	StatusCode int         `json:"-"`
	Internal   error       `json:"-"`
	Data       interface{} `json:"-"`
}

func (e *AppError) Error() string {
	return e.Message
}

var (
	ErrUnauthorized   = &AppError{Code: "UNAUTHORIZED", Message: "No autorizado", StatusCode: http.StatusUnauthorized}
	ErrForbidden      = &AppError{Code: "FORBIDDEN", Message: "Prohibido", StatusCode: http.StatusForbidden}
	ErrNotFound       = &AppError{Code: "NOT_FOUND", Message: "Recurso no encontrado", StatusCode: http.StatusNotFound}
	ErrInvalidInput   = &AppError{Code: "INVALID_INPUT", Message: "Entrada inválida", StatusCode: http.StatusBadRequest}
	ErrConflict       = &AppError{Code: "CONFLICT", Message: "Conflicto de recurso", StatusCode: http.StatusConflict}
	ErrInternalServer = &AppError{Code: "INTERNAL_ERROR", Message: "Error interno del servidor", StatusCode: http.StatusInternalServerError}
)

func NewAppError(code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

func NewAppErrorWithInternal(code, message string, statusCode int, internal error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Internal:   internal,
	}
}

// NewAppErrorWithData is used when the client needs structured context
// (e.g. user_id on UNVERIFIED_USER so the client can call resend).
func NewAppErrorWithData(code, message string, statusCode int, data interface{}) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Data:       data,
	}
}

func NewNotFoundError(resource string) *AppError {
	return NewAppError("NOT_FOUND", fmt.Sprintf("%s no encontrado", resource), http.StatusNotFound)
}

func NewConflictError(resource string) *AppError {
	return NewAppError("CONFLICT", fmt.Sprintf("%s ya existe", resource), http.StatusConflict)
}

func NewValidationError(field, reason string) *AppError {
	return NewAppError("VALIDATION_ERROR", fmt.Sprintf("Campo '%s': %s", field, reason), http.StatusBadRequest)
}

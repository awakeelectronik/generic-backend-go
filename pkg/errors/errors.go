package errors

import (
	"fmt"
	"net/http"
)

type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Internal   error  `json:"-"`
}

func (e *AppError) Error() string {
	return e.Message
}

var (
	ErrUnauthorized   = &AppError{Code: "UNAUTHORIZED", Message: "Unauthorized", StatusCode: http.StatusUnauthorized}
	ErrForbidden      = &AppError{Code: "FORBIDDEN", Message: "Forbidden", StatusCode: http.StatusForbidden}
	ErrNotFound       = &AppError{Code: "NOT_FOUND", Message: "Resource not found", StatusCode: http.StatusNotFound}
	ErrInvalidInput   = &AppError{Code: "INVALID_INPUT", Message: "Invalid input", StatusCode: http.StatusBadRequest}
	ErrConflict       = &AppError{Code: "CONFLICT", Message: "Resource conflict", StatusCode: http.StatusConflict}
	ErrInternalServer = &AppError{Code: "INTERNAL_ERROR", Message: "Internal server error", StatusCode: http.StatusInternalServerError}
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

func NewNotFoundError(resource string) *AppError {
	return NewAppError("NOT_FOUND", fmt.Sprintf("%s not found", resource), http.StatusNotFound)
}

func NewConflictError(resource string) *AppError {
	return NewAppError("CONFLICT", fmt.Sprintf("%s already exists", resource), http.StatusConflict)
}

func NewValidationError(field, reason string) *AppError {
	return NewAppError("VALIDATION_ERROR", fmt.Sprintf("Field '%s': %s", field, reason), http.StatusBadRequest)
}

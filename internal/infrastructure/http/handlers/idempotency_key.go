package handlers

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ResolveUUIDIdempotencyKey picks the idempotency key from the Idempotency-Key
// header if present, otherwise falls back to the body-supplied bodyKey.
//
// Returns:
//   - key:    the resolved UUID (empty string when neither was provided).
//   - badMsg: a pointer to a user-facing error message when the supplied value
//     was non-empty but not a valid UUID; nil when valid or both empty.
//
// The header takes precedence so clients can retry safely without rewriting the
// body. Callers should respond 400 with *badMsg when it is non-nil; an empty
// key means "no idempotency requested" and the caller decides how to proceed.
func ResolveUUIDIdempotencyKey(c *gin.Context, bodyKey string) (key string, badMsg *string) {
	h := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if h != "" {
		if _, err := uuid.Parse(h); err != nil {
			msg := "Idempotency-Key debe ser un UUID válido"
			return "", &msg
		}
		return h, nil
	}
	b := strings.TrimSpace(bodyKey)
	if b == "" {
		return "", nil
	}
	if _, err := uuid.Parse(b); err != nil {
		msg := "idempotency_key debe ser un UUID válido"
		return "", &msg
	}
	return b, nil
}

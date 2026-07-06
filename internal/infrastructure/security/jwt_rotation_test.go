package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Rotación de secreto: tokens firmados con el secreto ANTERIOR deben seguir
// validando mientras JWT_SECRET_PREVIOUS esté configurado; los nuevos se firman
// con el vigente.
func TestJWTRotationAcceptsPreviousSecret(t *testing.T) {
	oldSecret := "old-secret-0123456789abcdef012345"
	newSecret := "new-secret-0123456789abcdef012345"

	oldProvider := NewJWTProvider(oldSecret, 1, 24, "app")
	rotating := NewJWTProviderWithPrevious(newSecret, oldSecret, 1, 24, "app")

	// Token emitido antes de la rotación (firmado con el secreto viejo).
	oldToken, err := oldProvider.GenerateToken("user-1", "a@b.com", 3)
	assert.NoError(t, err)
	oldRefresh, err := oldProvider.GenerateRefreshToken("user-1", 3)
	assert.NoError(t, err)

	userID, email, version, err := rotating.ValidateToken(oldToken)
	assert.NoError(t, err, "token del secreto anterior debe validar durante la rotación")
	assert.Equal(t, "user-1", userID)
	assert.Equal(t, "a@b.com", email)
	assert.Equal(t, 3, version)

	_, _, err = rotating.ValidateRefreshToken(oldRefresh)
	assert.NoError(t, err)

	// Los tokens nuevos se firman con el secreto vigente: validan sin el viejo.
	newToken, err := rotating.GenerateToken("user-2", "c@d.com", 1)
	assert.NoError(t, err)
	onlyNew := NewJWTProvider(newSecret, 1, 24, "app")
	_, _, _, err = onlyNew.ValidateToken(newToken)
	assert.NoError(t, err)
}

// Terminada la rotación (sin previous), los tokens del secreto viejo mueren.
func TestJWTRotationRejectsOldSecretWhenFinished(t *testing.T) {
	oldSecret := "old-secret-0123456789abcdef012345"
	newSecret := "new-secret-0123456789abcdef012345"

	oldProvider := NewJWTProvider(oldSecret, 1, 24, "app")
	finished := NewJWTProvider(newSecret, 1, 24, "app")

	oldToken, err := oldProvider.GenerateToken("user-1", "a@b.com", 1)
	assert.NoError(t, err)

	_, _, _, err = finished.ValidateToken(oldToken)
	assert.Error(t, err)
}

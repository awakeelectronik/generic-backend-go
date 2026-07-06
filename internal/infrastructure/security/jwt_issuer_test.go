package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Un token firmado con el MISMO secreto pero otro issuer (otro despliegue del
// template reutilizando el secreto) no debe validar aquí.
func TestValidateTokenRejectsForeignIssuer(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	local := NewJWTProvider(secret, 1, 24, "app-a")
	foreign := NewJWTProvider(secret, 1, 24, "app-b")

	token, err := foreign.GenerateToken("user-1", "a@b.com", 1)
	assert.NoError(t, err)

	_, _, _, err = local.ValidateToken(token)
	assert.Error(t, err)

	refresh, err := foreign.GenerateRefreshToken("user-1", 1)
	assert.NoError(t, err)

	_, _, err = local.ValidateRefreshToken(refresh)
	assert.Error(t, err)
}

func TestValidateTokenAcceptsOwnIssuer(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	p := NewJWTProvider(secret, 1, 24, "app-a")

	token, err := p.GenerateToken("user-1", "a@b.com", 7)
	assert.NoError(t, err)

	userID, email, version, err := p.ValidateToken(token)
	assert.NoError(t, err)
	assert.Equal(t, "user-1", userID)
	assert.Equal(t, "a@b.com", email)
	assert.Equal(t, 7, version)
}

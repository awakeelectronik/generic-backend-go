package security

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig se define AQUÍ (local), no importado desde config
// Esto rompe el ciclo: security ya no importa el paquete config
type JWTConfig struct {
	Secret string
	// PreviousSecret permite rotar JWT_SECRET sin invalidar de golpe todas las
	// sesiones: los tokens NUEVOS se firman siempre con Secret, pero los ya
	// emitidos con el secreto anterior siguen validando durante la ventana de
	// rotación. Vacío = sin rotación en curso.
	PreviousSecret  string
	ExpirationHours int
	RefreshHours    int
	IssuerName      string
}

type JWTProvider struct {
	config *JWTConfig
}

// Token types embedded in the "typ" claim so an access token can't be replayed
// as a refresh token (or vice versa) — they share the same HMAC secret, so
// without this they'd be structurally interchangeable.
const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

type Claims struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	TokenVersion int    `json:"token_version"`
	Type         string `json:"typ"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID       string `json:"user_id"`
	TokenVersion int    `json:"token_version"`
	Type         string `json:"typ"`
	jwt.RegisteredClaims
}

func NewJWTProvider(secret string, expirationHours, refreshHours int, issuerName string) *JWTProvider {
	return NewJWTProviderWithPrevious(secret, "", expirationHours, refreshHours, issuerName)
}

// NewJWTProviderWithPrevious acepta además el secreto ANTERIOR (rotación en
// curso). Ver JWTConfig.PreviousSecret.
func NewJWTProviderWithPrevious(secret, previousSecret string, expirationHours, refreshHours int, issuerName string) *JWTProvider {
	return &JWTProvider{
		config: &JWTConfig{
			Secret:          secret,
			PreviousSecret:  previousSecret,
			ExpirationHours: expirationHours,
			RefreshHours:    refreshHours,
			IssuerName:      issuerName,
		},
	}
}

func (p *JWTProvider) GenerateToken(userID, email string, tokenVersion int) (string, error) {
	claims := Claims{
		UserID:       userID,
		Email:        email,
		TokenVersion: tokenVersion,
		Type:         tokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(p.config.ExpirationHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    p.config.IssuerName,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(p.config.Secret))
}

func (p *JWTProvider) GenerateRefreshToken(userID string, tokenVersion int) (string, error) {
	claims := RefreshClaims{
		UserID:       userID,
		TokenVersion: tokenVersion,
		Type:         tokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(p.config.RefreshHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    p.config.IssuerName,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(p.config.Secret))
}

// parserOptions endurece la validación en el parseo:
//   - WithValidMethods fija HS256 exacto (el keyfunc además re-verifica la
//     familia HMAC): imposible colar "none" o un downgrade de algoritmo.
//   - WithIssuer rechaza tokens firmados por OTRO despliegue de este mismo
//     template si alguien reutiliza el secreto entre apps clonadas.
func (p *JWTProvider) parserOptions() []jwt.ParserOption {
	return []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(p.config.IssuerName),
	}
}

// validationSecrets devuelve los secretos aceptados para VALIDAR, en orden:
// el vigente primero y, si hay rotación en curso, el anterior. Firmar siempre
// usa solo el vigente.
func (p *JWTProvider) validationSecrets() []string {
	secrets := []string{p.config.Secret}
	if p.config.PreviousSecret != "" {
		secrets = append(secrets, p.config.PreviousSecret)
	}
	return secrets
}

// parseWithSecrets intenta validar el token contra cada secreto aceptado.
// claimsFactory produce un struct de claims fresco por intento (reutilizarlo
// entre parseos dejaría campos contaminados de un intento fallido).
func (p *JWTProvider) parseWithSecrets(tokenString string, claimsFactory func() jwt.Claims) (jwt.Claims, error) {
	var lastErr error
	for _, secret := range p.validationSecrets() {
		claims := claimsFactory()
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(secret), nil
		}, p.parserOptions()...)
		if err == nil && token.Valid {
			return claims, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("token not valid")
	}
	return nil, lastErr
}

func (p *JWTProvider) ValidateToken(tokenString string) (userID string, email string, tokenVersion int, err error) {
	parsed, err := p.parseWithSecrets(tokenString, func() jwt.Claims { return &Claims{} })
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid token")
	}
	claims, ok := parsed.(*Claims)
	if !ok || claims.Type != tokenTypeAccess {
		return "", "", 0, fmt.Errorf("invalid token")
	}

	return claims.UserID, claims.Email, claims.TokenVersion, nil
}

func (p *JWTProvider) ValidateRefreshToken(tokenString string) (userID string, tokenVersion int, err error) {
	parsed, err := p.parseWithSecrets(tokenString, func() jwt.Claims { return &RefreshClaims{} })
	if err != nil {
		return "", 0, fmt.Errorf("invalid refresh token")
	}
	claims, ok := parsed.(*RefreshClaims)
	if !ok || claims.Type != tokenTypeRefresh {
		return "", 0, fmt.Errorf("invalid refresh token")
	}

	return claims.UserID, claims.TokenVersion, nil
}

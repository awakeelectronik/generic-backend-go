package security

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig se define AQUÍ (local), no importado desde config
// Esto rompe el ciclo: security ya no importa el paquete config
type JWTConfig struct {
	Secret          string
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
	return &JWTProvider{
		config: &JWTConfig{
			Secret:          secret,
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

func (p *JWTProvider) ValidateToken(tokenString string) (userID string, email string, tokenVersion int, err error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(p.config.Secret), nil
	}, p.parserOptions()...)

	if err != nil || !token.Valid {
		return "", "", 0, fmt.Errorf("invalid token")
	}
	if claims.Type != tokenTypeAccess {
		return "", "", 0, fmt.Errorf("invalid token")
	}

	return claims.UserID, claims.Email, claims.TokenVersion, nil
}

func (p *JWTProvider) ValidateRefreshToken(tokenString string) (userID string, tokenVersion int, err error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(p.config.Secret), nil
	}, p.parserOptions()...)

	if err != nil || !token.Valid {
		return "", 0, fmt.Errorf("invalid refresh token")
	}
	if claims.Type != tokenTypeRefresh {
		return "", 0, fmt.Errorf("invalid refresh token")
	}

	return claims.UserID, claims.TokenVersion, nil
}

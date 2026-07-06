package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/awakeelectronik/generic-backend-go/pkg/logmask"
)

// issueTokenPair genera el par access+refresh para un usuario en una versión de
// token dada. Centraliza la rotación de tokens que comparten login, verify-code,
// refresh y los cambios de contraseña, y mapea cualquier fallo de firma a
// ErrInternalServer (un fallo de firma siempre es 500, nunca culpa del cliente).
func issueTokenPair(tp application.TokenProvider, userID, email string, version int) (token, refresh string, err error) {
	token, err = tp.GenerateToken(userID, email, version)
	if err != nil {
		return "", "", appErrors.ErrInternalServer
	}
	refresh, err = tp.GenerateRefreshToken(userID, version)
	if err != nil {
		return "", "", appErrors.ErrInternalServer
	}
	return token, refresh, nil
}

// findUserByEmailOrPhone busca un usuario por email cuando viene informado y, en
// su defecto, por teléfono. Devuelve (nil, nil) si no hay coincidencia para que
// cada caso de uso decida la respuesta (404, no-enumeración, etc.).
func findUserByEmailOrPhone(ctx context.Context, repo application.UserRepository, email, phone string) (*domain.User, error) {
	if strings.TrimSpace(email) != "" {
		return repo.GetByEmail(ctx, email)
	}
	if strings.TrimSpace(phone) != "" {
		return repo.GetByPhone(ctx, phone)
	}
	return nil, nil
}

// userDestinations returns the user's non-empty contact channels (email first,
// then phone) — the targets a verification/reset code is delivered to. Shared by
// register, resend-verification and forgot-password, which all fan a single code
// out to whatever channels the user has.
func userDestinations(u *domain.User) []string {
	var dests []string
	if strings.TrimSpace(u.Email) != "" {
		dests = append(dests, u.Email)
	}
	if strings.TrimSpace(u.Phone) != "" {
		dests = append(dests, u.Phone)
	}
	return dests
}

// maskEmail / maskPhone delegan en pkg/logmask (compartido con el servicio de
// verificación) para que TODO el proyecto enmascare PII igual en logs.
func maskEmail(email string) string { return logmask.Email(email) }

func maskPhone(phone string) string { return logmask.Phone(phone) }

// normalizeEmail canonicaliza un correo para almacenamiento y búsqueda:
// trim + minúsculas. Sin esto, "Ana@X.com" y "ana@x.com" son strings distintos
// en Go aunque la collation de MySQL los trate igual, lo que produce
// comparaciones inconsistentes (p. ej. en el AdminChecker o en pre-checks de
// duplicados).
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// loginThrottleKey deriva la clave de lockout del IDENTIFICADOR presentado (no
// del user.ID), para que un identificador inexistente se pueda bloquear igual
// que uno real. Si se contara el fallo solo cuando el usuario existe, el 429 de
// lockout sería un oráculo de enumeración (429 ⇒ la cuenta existe). Prefiere el
// email (normalizado) igual que findUserByEmailOrPhone; si no hay, usa el
// teléfono. Validate ya garantiza que al menos uno viene informado.
func loginThrottleKey(email, phone string) string {
	if e := normalizeEmail(email); e != "" {
		return "login:email:" + e
	}
	return "login:phone:" + strings.TrimSpace(phone)
}

// SessionOutput is the authenticated-session payload returned by every flow that
// logs a user in: login, verify-code, and password change/reset. They all return
// the same shape, so they share one type instead of four identical structs.
type SessionOutput struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

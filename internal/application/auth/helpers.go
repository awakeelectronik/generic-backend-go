package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
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

// maskEmail reduce un correo a primera letra + dominio para logs. Los logs se
// replican a sistemas con menos control de acceso que la BD; el contacto
// completo de un usuario no debe viajar ahí (PII).
func maskEmail(email string) string {
	if email == "" {
		return ""
	}
	at := strings.Index(email, "@")
	if at <= 0 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}

// maskPhone deja visibles solo los últimos 4 dígitos.
func maskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(phone)-4) + phone[len(phone)-4:]
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

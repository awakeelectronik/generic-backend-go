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

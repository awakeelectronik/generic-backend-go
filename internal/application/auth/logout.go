package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type LogoutOutput struct {
	Message string `json:"message"`
}

// LogoutUseCase revoca la sesión del lado del SERVIDOR subiendo token_version:
// todos los access y refresh tokens emitidos hasta ahora quedan inválidos en la
// siguiente petición. Sin esto, "cerrar sesión" solo borra el token del cliente
// y un token robado sigue siendo válido hasta expirar.
//
// Nota: token_version es global por usuario, así que el logout cierra TODAS las
// sesiones/dispositivos — coherente con el diseño existente (cualquier refresh
// ya invalida los tokens de otros dispositivos).
type LogoutUseCase struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewLogoutUseCase(userRepo application.UserRepository, logger *logrus.Logger) *LogoutUseCase {
	return &LogoutUseCase{userRepo: userRepo, logger: logger}
}

func (uc *LogoutUseCase) Execute(ctx context.Context, userID string) (*LogoutOutput, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, appErrors.ErrUnauthorized
	}
	if _, err := uc.userRepo.BumpTokenVersion(ctx, userID); err != nil {
		uc.logger.WithError(err).WithField("user_id", userID).Error("Failed to revoke session on logout")
		return nil, appErrors.ErrInternalServer
	}
	uc.logger.WithField("user_id", userID).Info("Session revoked (logout)")
	return &LogoutOutput{Message: "Sesión cerrada. Todos los tokens fueron revocados."}, nil
}

package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ChangePasswordInput struct {
	UserID          string `json:"-"`
	CurrentPassword string `json:"current_password" binding:"required,min=5,max=20"`
	NewPassword     string `json:"new_password" binding:"required,min=5,max=20"`
}

func (c ChangePasswordInput) Validate() error {
	if strings.TrimSpace(c.UserID) == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Usuario inválido", 400)
	}
	if len(c.CurrentPassword) < 5 || len(c.CurrentPassword) > 20 {
		return appErrors.NewAppError("VALIDATION_ERROR", "La contraseña actual debe tener entre 5 y 20 caracteres", 400)
	}
	if len(c.NewPassword) < 5 || len(c.NewPassword) > 20 {
		return appErrors.NewAppError("VALIDATION_ERROR", "La nueva contraseña debe tener entre 5 y 20 caracteres", 400)
	}
	return nil
}

type ChangePasswordUseCase struct {
	userRepo       application.UserRepository
	passwordHasher application.PasswordHasher
	tokenProvider  application.TokenProvider
	logger         *logrus.Logger
}

func NewChangePasswordUseCase(
	userRepo application.UserRepository,
	passwordHasher application.PasswordHasher,
	tokenProvider application.TokenProvider,
	logger *logrus.Logger,
) *ChangePasswordUseCase {
	return &ChangePasswordUseCase{
		userRepo:       userRepo,
		passwordHasher: passwordHasher,
		tokenProvider:  tokenProvider,
		logger:         logger,
	}
}

func (uc *ChangePasswordUseCase) Execute(ctx context.Context, input ChangePasswordInput) (*SessionOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	user, err := uc.userRepo.GetByID(ctx, input.UserID)
	if err != nil {
		uc.logger.WithError(err).Warn("User not found during password change")
		return nil, err
	}

	if err := uc.passwordHasher.Compare(user.Password, input.CurrentPassword); err != nil {
		return nil, appErrors.NewAppError("INVALID_PASSWORD", "Contraseña actual incorrecta", 400)
	}

	newHash, err := uc.passwordHasher.Hash(input.NewPassword)
	if err != nil {
		uc.logger.WithError(err).Error("Password hashing failed")
		return nil, appErrors.ErrInternalServer
	}

	newTokenVersion, err := uc.userRepo.UpdatePasswordAndBumpTokenVersion(ctx, user.ID, newHash)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to update password")
		return nil, err
	}
	token, refreshToken, err := issueTokenPair(uc.tokenProvider, user.ID, user.Email, newTokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to issue tokens after password change")
		return nil, err
	}

	uc.logger.WithField("user_id", user.ID).Info("Password changed successfully")

	return &SessionOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}

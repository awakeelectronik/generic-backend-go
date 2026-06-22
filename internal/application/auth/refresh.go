package auth

import (
	"context"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type RefreshInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (r RefreshInput) Validate() error {
	if r.RefreshToken == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "refresh_token es obligatorio", 400)
	}
	return nil
}

type RefreshOutput struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshUseCase struct {
	userRepo      application.UserRepository
	tokenProvider application.TokenProvider
	logger        *logrus.Logger
}

func NewRefreshUseCase(
	userRepo application.UserRepository,
	tp application.TokenProvider,
	logger *logrus.Logger,
) *RefreshUseCase {
	return &RefreshUseCase{
		userRepo:      userRepo,
		tokenProvider: tp,
		logger:        logger,
	}
}

func (uc *RefreshUseCase) Execute(ctx context.Context, input RefreshInput) (*RefreshOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	uc.logger.Info("Token refresh attempt")

	userID, tokenVersion, err := uc.tokenProvider.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		uc.logger.WithError(err).Warn("Invalid refresh token")
		return nil, appErrors.ErrUnauthorized
	}

	user, err := uc.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		uc.logger.WithError(err).Warn("User not found during refresh")
		return nil, appErrors.ErrUnauthorized
	}
	if user.TokenVersion != tokenVersion {
		uc.logger.WithField("user_id", userID).Warn("Refresh token revoked")
		return nil, appErrors.ErrUnauthorized
	}

	// Rotación real: subir token_version invalida el refresh recién consumido
	// (y cualquier access token aún vivo). Un replay del refresh anterior
	// fallará en la comparación de version arriba.
	newTokenVersion, err := uc.userRepo.BumpTokenVersion(ctx, user.ID)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to bump token version on refresh")
		return nil, appErrors.ErrInternalServer
	}

	token, err := uc.tokenProvider.GenerateToken(user.ID, user.Email, newTokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate new token")
		return nil, appErrors.ErrInternalServer
	}

	newRefreshToken, err := uc.tokenProvider.GenerateRefreshToken(user.ID, newTokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate new refresh token")
		return nil, appErrors.ErrInternalServer
	}

	uc.logger.WithField("user_id", userID).Info("Token refreshed successfully")

	return &RefreshOutput{Token: token, RefreshToken: newRefreshToken}, nil
}

package auth

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/sirupsen/logrus"
)

type RefreshInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshOutput struct {
	Token string `json:"token"`
}

type RefreshUseCase struct {
	tokenProvider application.TokenProvider
	logger        *logrus.Logger
}

func NewRefreshUseCase(
	tp application.TokenProvider,
	logger *logrus.Logger,
) *RefreshUseCase {
	return &RefreshUseCase{
		tokenProvider: tp,
		logger:        logger,
	}
}

func (uc *RefreshUseCase) Execute(ctx context.Context, input RefreshInput) (*RefreshOutput, error) {
	uc.logger.Info("Token refresh attempt")

	userID, err := uc.tokenProvider.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		uc.logger.WithError(err).Warn("Invalid refresh token")
		return nil, appErrors.ErrUnauthorized
	}

	token, err := uc.tokenProvider.GenerateToken(userID, "")
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate new token")
		return nil, appErrors.ErrInternalServer
	}

	uc.logger.WithField("user_id", userID).Info("Token refreshed successfully")

	return &RefreshOutput{Token: token}, nil
}

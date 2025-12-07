package auth

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/sirupsen/logrus"
)

type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginOutput struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

type LoginUseCase struct {
	userRepo       application.UserRepository
	passwordHasher application.PasswordHasher
	tokenProvider  application.TokenProvider
	logger         *logrus.Logger
}

func NewLoginUseCase(
	userRepo application.UserRepository,
	ph application.PasswordHasher,
	tp application.TokenProvider,
	logger *logrus.Logger,
) *LoginUseCase {
	return &LoginUseCase{
		userRepo:       userRepo,
		passwordHasher: ph,
		tokenProvider:  tp,
		logger:         logger,
	}
}

func (uc *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	uc.logger.WithField("email", input.Email).Info("Login attempt")

	// Find user
	user, err := uc.userRepo.GetByEmail(ctx, input.Email)
	if err != nil || user == nil {
		uc.logger.WithField("email", input.Email).Warn("Login failed: user not found")
		return nil, appErrors.ErrUnauthorized
	}

	// Verify password
	if err := uc.passwordHasher.Compare(user.Password, input.Password); err != nil {
		uc.logger.WithField("email", input.Email).Warn("Login failed: invalid password")
		return nil, appErrors.ErrUnauthorized
	}

	// Generate tokens
	token, err := uc.tokenProvider.GenerateToken(user.ID, user.Email)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate token")
		return nil, appErrors.ErrInternalServer
	}

	refreshToken, err := uc.tokenProvider.GenerateRefreshToken(user.ID)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate refresh token")
		return nil, appErrors.ErrInternalServer
	}

	uc.logger.WithField("user_id", user.ID).Info("User logged in successfully")

	return &LoginOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}

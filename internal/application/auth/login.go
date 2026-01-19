package auth

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/sirupsen/logrus"
)

type LoginInput struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Phone    string `json:"phone" binding:"omitempty,len=10,numeric"`
	Password string `json:"password" binding:"required"`
}

func (li LoginInput) Validate() error {
	if li.Email == "" && li.Phone == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	return nil
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
	uc.logger.WithFields(logrus.Fields{"email": input.Email, "phone": input.Phone}).Info("Login attempt")

	// Find user by email or phone
	var user *domain.User
	var err error

	// prefer email if provided
	if input.Email != "" {
		user, err = uc.userRepo.GetByEmail(ctx, input.Email)
	} else if input.Phone != "" {
		user, err = uc.userRepo.GetByPhone(ctx, input.Phone)
	}

	if err != nil || user == nil {
		uc.logger.WithFields(logrus.Fields{"email": input.Email, "phone": input.Phone}).Warn("Login failed: user not found")
		return nil, appErrors.ErrUnauthorized
	}

	// Verify password
	if err := uc.passwordHasher.Compare(user.Password, input.Password); err != nil {
		uc.logger.WithFields(logrus.Fields{"email": input.Email, "phone": input.Phone}).Warn("Login failed: invalid password")
		return nil, appErrors.ErrUnauthorized
	}

	// Check if user is verified
	if !user.Verified {
		uc.logger.WithFields(logrus.Fields{"user_id": user.ID, "email": input.Email, "phone": input.Phone}).Warn("Login failed: user not verified")
		return nil, appErrors.NewAppError("UNVERIFIED_USER", "Usuario no verificado. Complete la verificación primero.", 403)
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

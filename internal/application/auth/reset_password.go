package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ResetPasswordInput struct {
	Email       string `json:"email" binding:"omitempty,email"`
	Phone       string `json:"phone" binding:"omitempty,len=10,numeric"`
	Code        string `json:"code" binding:"required,len=4"`
	NewPassword string `json:"new_password" binding:"required,min=5,max=20"`
}

type ResetPasswordOutput struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

type ResetPasswordUseCase struct {
	userRepo        application.UserRepository
	passwordHasher  application.PasswordHasher
	verificationSvc application.VerificationService
	tokenProvider   application.TokenProvider
	logger          *logrus.Logger
}

func NewResetPasswordUseCase(
	userRepo application.UserRepository,
	passwordHasher application.PasswordHasher,
	verificationSvc application.VerificationService,
	tokenProvider application.TokenProvider,
	logger *logrus.Logger,
) *ResetPasswordUseCase {
	return &ResetPasswordUseCase{
		userRepo:        userRepo,
		passwordHasher:  passwordHasher,
		verificationSvc: verificationSvc,
		tokenProvider:   tokenProvider,
		logger:          logger,
	}
}

func (uc *ResetPasswordUseCase) Execute(ctx context.Context, input ResetPasswordInput) (*ResetPasswordOutput, error) {
	if strings.TrimSpace(input.Email) == "" && strings.TrimSpace(input.Phone) == "" {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}

	var (
		user *domain.User
		err  error
	)

	if strings.TrimSpace(input.Email) != "" {
		user, err = uc.userRepo.GetByEmail(ctx, input.Email)
	} else {
		user, err = uc.userRepo.GetByPhone(ctx, input.Phone)
	}

	if err != nil {
		uc.logger.WithError(err).Error("Failed to fetch user for password reset")
		return nil, err
	}
	if user == nil {
		return nil, appErrors.NewNotFoundError("Usuario")
	}

	if err := uc.verificationSvc.VerifyCode(user.ID, input.Code); err != nil {
		return nil, err
	}

	newHash, err := uc.passwordHasher.Hash(input.NewPassword)
	if err != nil {
		uc.logger.WithError(err).Error("Password hashing failed")
		return nil, appErrors.ErrInternalServer
	}

	if err := uc.userRepo.UpdatePasswordAndBumpTokenVersion(ctx, user.ID, newHash); err != nil {
		uc.logger.WithError(err).Error("Failed to update password")
		return nil, err
	}

	newTokenVersion := user.TokenVersion + 1
	token, err := uc.tokenProvider.GenerateToken(user.ID, user.Email, newTokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate token after password reset")
		return nil, appErrors.ErrInternalServer
	}

	refreshToken, err := uc.tokenProvider.GenerateRefreshToken(user.ID, newTokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate refresh token after password reset")
		return nil, appErrors.ErrInternalServer
	}

	return &ResetPasswordOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}

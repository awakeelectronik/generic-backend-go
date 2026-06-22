package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ResetPasswordInput struct {
	Email       string `json:"email" binding:"omitempty,email"`
	Phone       string `json:"phone" binding:"omitempty,len=10,numeric"`
	Code        string `json:"code" binding:"required,len=4"`
	NewPassword string `json:"new_password" binding:"required,min=5,max=20"`
}

func (r ResetPasswordInput) Validate() error {
	if strings.TrimSpace(r.Email) == "" && strings.TrimSpace(r.Phone) == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	if len(r.Code) != 4 {
		return appErrors.NewAppError("VALIDATION_ERROR", "El código debe tener 4 caracteres", 400)
	}
	if len(r.NewPassword) < 5 || len(r.NewPassword) > 20 {
		return appErrors.NewAppError("VALIDATION_ERROR", "La contraseña debe tener entre 5 y 20 caracteres", 400)
	}
	return nil
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
	if err := input.Validate(); err != nil {
		return nil, err
	}

	user, err := findUserByEmailOrPhone(ctx, uc.userRepo, input.Email, input.Phone)
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

	newTokenVersion, err := uc.userRepo.UpdatePasswordAndBumpTokenVersion(ctx, user.ID, newHash)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to update password")
		return nil, err
	}
	token, refreshToken, err := issueTokenPair(uc.tokenProvider, user.ID, user.Email, newTokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to issue tokens after password reset")
		return nil, err
	}

	return &ResetPasswordOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}

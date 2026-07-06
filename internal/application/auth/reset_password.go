package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ResetPasswordInput struct {
	Email       string `json:"email" binding:"omitempty,email,max=254"`
	Phone       string `json:"phone" binding:"omitempty,len=10,numeric"`
	Code        string `json:"code" binding:"required,len=6"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

func (r ResetPasswordInput) Validate() error {
	if strings.TrimSpace(r.Email) == "" && strings.TrimSpace(r.Phone) == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	if len(r.Code) != 6 {
		return appErrors.NewAppError("VALIDATION_ERROR", "El código debe tener 6 caracteres", 400)
	}
	// len() cuenta bytes (no runas): es el límite real de bcrypt (72 bytes),
	// más estricto que el binding `max=72` que cuenta runas.
	if len(r.NewPassword) < 8 || len(r.NewPassword) > 72 {
		return appErrors.NewAppError("VALIDATION_ERROR", "La contraseña debe tener entre 8 y 72 caracteres", 400)
	}
	return nil
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

func (uc *ResetPasswordUseCase) Execute(ctx context.Context, input ResetPasswordInput) (*SessionOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	user, err := findUserByEmailOrPhone(ctx, uc.userRepo, normalizeEmail(input.Email), input.Phone)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to fetch user for password reset")
		return nil, err
	}
	if user == nil {
		// Anti-enumeración: un 404 aquí revelaría qué correos/teléfonos tienen
		// cuenta, contradiciendo el mensaje genérico de forgot-password. Se
		// responde exactamente igual que una cuenta real SIN código pendiente
		// (el estado en que está cualquier cuenta que no pidió reset), así ambos
		// casos son indistinguibles para quien sondea.
		return nil, appErrors.ErrVerificationCodeNotFound
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

	return &SessionOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}

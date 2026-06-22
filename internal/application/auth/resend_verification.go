package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

// ResendVerificationInput requiere user_id y contraseña para evitar abuso del endpoint.
type ResendVerificationInput struct {
	UserID   string `json:"user_id" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (r ResendVerificationInput) Validate() error {
	if strings.TrimSpace(r.UserID) == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "user_id es obligatorio", 400)
	}
	if r.Password == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "La contraseña es obligatoria", 400)
	}
	return nil
}

type ResendVerificationOutput struct {
	Message string `json:"message"`
}

type ResendVerificationUseCase struct {
	userRepo        application.UserRepository
	passwordHasher  application.PasswordHasher
	verificationSvc application.VerificationService
	logger          *logrus.Logger
}

func NewResendVerificationUseCase(
	userRepo application.UserRepository,
	ph application.PasswordHasher,
	verificationSvc application.VerificationService,
	logger *logrus.Logger,
) *ResendVerificationUseCase {
	return &ResendVerificationUseCase{
		userRepo:        userRepo,
		passwordHasher:  ph,
		verificationSvc: verificationSvc,
		logger:          logger,
	}
}

func (uc *ResendVerificationUseCase) Execute(ctx context.Context, input ResendVerificationInput) (*ResendVerificationOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	user, err := uc.userRepo.GetByID(ctx, strings.TrimSpace(input.UserID))
	if err != nil || user == nil {
		uc.logger.WithField("user_id", input.UserID).Warn("Resend verification: user not found")
		return nil, appErrors.ErrUnauthorized
	}

	if err := uc.passwordHasher.Compare(user.Password, input.Password); err != nil {
		uc.logger.WithField("user_id", user.ID).Warn("Resend verification: invalid password")
		return nil, appErrors.ErrUnauthorized
	}

	if user.Verified {
		return nil, appErrors.NewAppError("ALREADY_VERIFIED", "Tu contacto ya está verificado. Inicia sesión.", 400)
	}

	destinations := userDestinations(user)
	if len(destinations) == 0 {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", "No hay correo ni teléfono para enviar el código", 400)
	}

	if err := uc.verificationSvc.SendVerificationCodeToDestinations(user.ID, destinations); err != nil {
		if errors.Is(err, appErrors.ErrVerificationRateLimited) {
			return nil, appErrors.NewAppError(
				"RATE_LIMIT_VERIFICATION",
				"Espera unos segundos antes de solicitar otro código (máximo 5 por hora).",
				429,
			)
		}
		uc.logger.WithError(err).WithField("user_id", user.ID).Warn("Resend verification: send failed")
		return nil, appErrors.NewAppError("SEND_FAILED", "No se pudo enviar el código. Intenta más tarde.", 502)
	}

	uc.logger.WithField("user_id", user.ID).Info("Verification code resent")
	return &ResendVerificationOutput{Message: "Código de verificación enviado"}, nil
}

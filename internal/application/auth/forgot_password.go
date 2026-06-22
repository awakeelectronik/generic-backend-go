package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"omitempty,email"`
	Phone string `json:"phone" binding:"omitempty,len=10,numeric"`
}

func (f ForgotPasswordInput) Validate() error {
	if strings.TrimSpace(f.Email) == "" && strings.TrimSpace(f.Phone) == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	return nil
}

type ForgotPasswordOutput struct {
	Message string `json:"message"`
}

// genericResponseMessage is returned regardless of whether the user exists, the
// send succeeded, or the lookup errored. This avoids leaking which emails/phones
// are registered (account enumeration). Real failures are logged server-side.
const genericResponseMessage = "Si tu cuenta existe, recibirás un código de verificación"

type ForgotPasswordUseCase struct {
	userRepo        application.UserRepository
	verificationSvc application.VerificationService
	logger          *logrus.Logger
}

func NewForgotPasswordUseCase(
	userRepo application.UserRepository,
	verificationSvc application.VerificationService,
	logger *logrus.Logger,
) *ForgotPasswordUseCase {
	return &ForgotPasswordUseCase{
		userRepo:        userRepo,
		verificationSvc: verificationSvc,
		logger:          logger,
	}
}

func (uc *ForgotPasswordUseCase) Execute(ctx context.Context, input ForgotPasswordInput) (*ForgotPasswordOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	user, err := findUserByEmailOrPhone(ctx, uc.userRepo, input.Email, input.Phone)
	if err != nil {
		uc.logger.WithError(err).Warn("forgot password: user lookup failed")
		return &ForgotPasswordOutput{Message: genericResponseMessage}, nil
	}
	if user == nil {
		// No revelar inexistencia.
		return &ForgotPasswordOutput{Message: genericResponseMessage}, nil
	}

	// Enviar a todos los contactos del usuario, igual que register/resend, para
	// que el código llegue por cualquier canal disponible.
	var destinations []string
	if strings.TrimSpace(user.Email) != "" {
		destinations = append(destinations, user.Email)
	}
	if strings.TrimSpace(user.Phone) != "" {
		destinations = append(destinations, user.Phone)
	}
	if len(destinations) == 0 {
		return &ForgotPasswordOutput{Message: genericResponseMessage}, nil
	}

	if err := uc.verificationSvc.SendVerificationCodeToDestinations(user.ID, destinations); err != nil {
		// Rate-limit interno se silencia con el mismo mensaje genérico para
		// preservar la no-enumeración. Cualquier otro fallo se loguea.
		if !errors.Is(err, appErrors.ErrVerificationRateLimited) {
			uc.logger.WithError(err).WithField("user_id", user.ID).Warn("forgot password: send failed")
		}
	}

	return &ForgotPasswordOutput{Message: genericResponseMessage}, nil
}

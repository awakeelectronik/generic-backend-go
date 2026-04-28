package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"omitempty,email"`
	Phone string `json:"phone" binding:"omitempty,len=10,numeric"`
}

type ForgotPasswordOutput struct {
	Message string `json:"message"`
}

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
	if strings.TrimSpace(input.Email) == "" && strings.TrimSpace(input.Phone) == "" {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}

	var (
		user        *domain.User
		err         error
		destination string
	)

	if strings.TrimSpace(input.Email) != "" {
		user, err = uc.userRepo.GetByEmail(ctx, input.Email)
		destination = input.Email
	} else {
		user, err = uc.userRepo.GetByPhone(ctx, input.Phone)
		destination = input.Phone
	}
	if err != nil {
		uc.logger.WithError(err).Error("Failed to fetch user for password reset")
		return nil, err
	}
	if user == nil {
		return nil, appErrors.NewNotFoundError("Usuario")
	}

	if err := uc.verificationSvc.SendVerificationCode(user.ID, destination); err != nil {
		uc.logger.WithError(err).Error("Failed to send verification code for password reset")
		return nil, appErrors.ErrInternalServer
	}

	return &ForgotPasswordOutput{
		Message: "Código de verificación enviado",
	}, nil
}

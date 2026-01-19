package auth

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/sirupsen/logrus"
)

type CheckAvailabilityInput struct {
	Email string `json:"email" binding:"omitempty,email"`
	Phone string `json:"phone" binding:"omitempty,len=10,numeric"`
}

// Validate ensures at least email or phone is provided
func (c *CheckAvailabilityInput) Validate() error {
	if c.Email == "" && c.Phone == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	return nil
}

type CheckAvailabilityOutput struct {
	Available bool `json:"available"`
}

type CheckAvailabilityUseCase struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewCheckAvailabilityUseCase(
	userRepo application.UserRepository,
	logger *logrus.Logger,
) *CheckAvailabilityUseCase {
	return &CheckAvailabilityUseCase{
		userRepo: userRepo,
		logger:   logger,
	}
}

func (uc *CheckAvailabilityUseCase) Execute(ctx context.Context, input CheckAvailabilityInput) (*CheckAvailabilityOutput, error) {
	// Validate input
	if err := input.Validate(); err != nil {
		return nil, err
	}

	uc.logger.WithFields(logrus.Fields{
		"email":  input.Email,
		"phone":  input.Phone,
		"action": "check_availability",
	}).Info("Checking email/phone availability")

	var checkType string
	var available bool

	// Check email if provided
	if input.Email != "" {
		user, err := uc.userRepo.GetByEmail(ctx, input.Email)
		if err != nil {
			uc.logger.WithError(err).Error("Error checking email availability")
			return &CheckAvailabilityOutput{Available: true}, nil
		}
		available = user == nil
		checkType = "email"
	} else if input.Phone != "" {
		user, err := uc.userRepo.GetByPhone(ctx, input.Phone)
		if err != nil {
			uc.logger.WithError(err).Error("Error checking phone availability")
			return &CheckAvailabilityOutput{Available: true}, nil
		}
		available = user == nil
		checkType = "phone"
	}

	uc.logger.WithFields(logrus.Fields{
		"email":     input.Email,
		"phone":     input.Phone,
		"type":      checkType,
		"available": available,
	}).Info("Availability checked")

	return &CheckAvailabilityOutput{Available: available}, nil
}

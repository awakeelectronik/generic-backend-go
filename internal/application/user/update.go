package user

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

// UpdateUserInput holds the mutable fields of a user profile.
// Phone uses the same shape as registration (10 digits) so both flows agree.
type UpdateUserInput struct {
	Name  string `json:"name"  binding:"required,min=2,max=100"`
	Phone string `json:"phone" binding:"omitempty,len=10,numeric"`
}

type UpdateUserUseCase struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewUpdateUserUseCase(userRepo application.UserRepository, logger *logrus.Logger) *UpdateUserUseCase {
	return &UpdateUserUseCase{userRepo: userRepo, logger: logger}
}

// Execute updates the user. Enforces ownership and, when phone changes,
// rejects values already taken by another user (would otherwise hit the
// MySQL UNIQUE on phone with a confusing 500).
func (uc *UpdateUserUseCase) Execute(ctx context.Context, requesterID, targetID string, input UpdateUserInput) (*UserOutput, error) {
	requesterID = strings.TrimSpace(requesterID)
	targetID = strings.TrimSpace(targetID)
	if requesterID == "" || targetID == "" {
		return nil, appErrors.ErrUnauthorized
	}
	if requesterID != targetID {
		return nil, appErrors.ErrForbidden
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, appErrors.NewValidationError("name", "es obligatorio")
	}

	user, err := uc.userRepo.GetByID(ctx, targetID)
	if err != nil {
		return nil, err
	}

	newPhone := strings.TrimSpace(input.Phone)
	if newPhone != "" && newPhone != user.Phone {
		other, err := uc.userRepo.GetByPhone(ctx, newPhone)
		if err != nil {
			return nil, err
		}
		if other != nil && other.ID != user.ID {
			return nil, appErrors.NewConflictError("El teléfono")
		}
	}

	user.Name = strings.TrimSpace(input.Name)
	user.Phone = newPhone

	if err := uc.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	uc.logger.WithField("user_id", user.ID).Info("User updated")
	out := toUserOutput(user)
	return &out, nil
}

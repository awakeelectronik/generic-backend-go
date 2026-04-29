package user

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type DeleteUserUseCase struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewDeleteUserUseCase(userRepo application.UserRepository, logger *logrus.Logger) *DeleteUserUseCase {
	return &DeleteUserUseCase{userRepo: userRepo, logger: logger}
}

// Execute soft-deletes the user. Ownership enforced. The user's outstanding
// JWTs become unusable on the next request because AuthMiddleware loads the
// row with deleted_at IS NULL and rejects when not found.
func (uc *DeleteUserUseCase) Execute(ctx context.Context, requesterID, targetID string) error {
	requesterID = strings.TrimSpace(requesterID)
	targetID = strings.TrimSpace(targetID)
	if requesterID == "" || targetID == "" {
		return appErrors.ErrUnauthorized
	}
	if requesterID != targetID {
		return appErrors.ErrForbidden
	}
	if err := uc.userRepo.Delete(ctx, targetID); err != nil {
		return err
	}
	uc.logger.WithField("user_id", targetID).Info("User deleted")
	return nil
}

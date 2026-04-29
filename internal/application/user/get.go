package user

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/awakeelectronik/generic-backend-go/pkg/httptime"
	"github.com/sirupsen/logrus"
)

// UserOutput is the public projection of a user (no password / token_version).
type UserOutput struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
}

func toUserOutput(u *domain.User) UserOutput {
	return UserOutput{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Phone:     u.Phone,
		Verified:  u.Verified,
		CreatedAt: httptime.FormatRFC3339(u.CreatedAt),
	}
}

type GetUserUseCase struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewGetUserUseCase(userRepo application.UserRepository, logger *logrus.Logger) *GetUserUseCase {
	return &GetUserUseCase{userRepo: userRepo, logger: logger}
}

// Execute returns the targetID user. Ownership is enforced: a user can only
// fetch its own profile. Admin-side listing has its own use case.
func (uc *GetUserUseCase) Execute(ctx context.Context, requesterID, targetID string) (*UserOutput, error) {
	requesterID = strings.TrimSpace(requesterID)
	targetID = strings.TrimSpace(targetID)
	if requesterID == "" || targetID == "" {
		return nil, appErrors.ErrUnauthorized
	}
	if requesterID != targetID {
		return nil, appErrors.ErrForbidden
	}

	user, err := uc.userRepo.GetByID(ctx, targetID)
	if err != nil {
		return nil, err
	}
	out := toUserOutput(user)
	return &out, nil
}

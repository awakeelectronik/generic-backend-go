package user

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/awakeelectronik/generic-backend-go/pkg/httptime"
	"github.com/sirupsen/logrus"
)

// ListUsersOutputItem representa un usuario en la lista (sin datos sensibles).
type ListUsersOutputItem struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
}

type ListUsersPagination struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

type ListUsersSummary struct {
	TotalUsers    int `json:"total_users"`
	ActiveUsers   int `json:"active_users"`
	InactiveUsers int `json:"inactive_users"`
}

// ListUsersOutput respuesta del listado de usuarios.
type ListUsersOutput struct {
	Users      []ListUsersOutputItem `json:"users"`
	Pagination ListUsersPagination   `json:"pagination"`
	Summary    ListUsersSummary      `json:"summary"`
}

// ListUsersUseCase lista usuarios con paginación (uso interno/admin).
type ListUsersUseCase struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewListUsersUseCase(
	userRepo application.UserRepository,
	logger *logrus.Logger,
) *ListUsersUseCase {
	return &ListUsersUseCase{
		userRepo: userRepo,
		logger:   logger,
	}
}

// Execute ejecuta el listado paginado. No expone password ni token_version.
func (uc *ListUsersUseCase) Execute(ctx context.Context, page, pageSize int, q string) (*ListUsersOutput, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > application.MaxPageSize {
		pageSize = application.MaxPageSize
	}
	offset := (page - 1) * pageSize
	q = strings.TrimSpace(q)

	uc.logger.WithFields(logrus.Fields{
		"page":      page,
		"page_size": pageSize,
		"q":         q,
		"action":    "list_users",
	}).Info("Listing users")

	users, totalUsers, activeUsers, inactiveUsers, err := uc.userRepo.ListWithSummary(ctx, pageSize, offset, q)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to list users")
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error al listar usuarios", 500, err)
	}

	items := make([]ListUsersOutputItem, 0, len(users))
	for _, u := range users {
		items = append(items, ListUsersOutputItem{
			ID:        u.ID,
			Email:     u.Email,
			Name:      u.Name,
			Phone:     u.Phone,
			Verified:  u.Verified,
			CreatedAt: httptime.FormatRFC3339(u.CreatedAt),
		})
	}

	return &ListUsersOutput{
		Users: items,
		Pagination: ListUsersPagination{
			Page:     page,
			PageSize: pageSize,
			Total:    totalUsers,
		},
		Summary: ListUsersSummary{
			TotalUsers:    totalUsers,
			ActiveUsers:   activeUsers,
			InactiveUsers: inactiveUsers,
		},
	}, nil
}

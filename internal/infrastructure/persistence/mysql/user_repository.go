package mysql

import (
	"context"
	"database/sql"
	"time"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, email, password, name, phone, verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Email, user.Password, user.Name, user.Phone,
		user.Verified, user.CreatedAt, user.UpdatedAt,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error creating user", 500, err)
	}

	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, created_at, updated_at, deleted_at
		FROM users WHERE id = ? AND deleted_at IS NULL
	`

	var user domain.User
	var deletedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name, &user.Phone,
		&user.Verified, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, appErrors.NewNotFoundError("User")
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user", 500, err)
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, created_at, updated_at, deleted_at
		FROM users WHERE email = ? AND deleted_at IS NULL
	`

	var user domain.User
	var deletedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name, &user.Phone,
		&user.Verified, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user", 500, err)
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE users 
		SET email = ?, name = ?, phone = ?, verified = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query,
		user.Email, user.Name, user.Phone, user.Verified, time.Now(), user.ID,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error updating user", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error checking changes", 500, err)
	}

	if rows == 0 {
		return appErrors.NewNotFoundError("User")
	}

	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `UPDATE users SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error deleting user", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return appErrors.NewNotFoundError("User")
	}

	return nil
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, created_at, updated_at, deleted_at
		FROM users 
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listing users", 500, err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		var user domain.User
		var deletedAt sql.NullTime

		err := rows.Scan(
			&user.ID, &user.Email, &user.Password, &user.Name, &user.Phone,
			&user.Verified, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
		)
		if err != nil {
			return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error scanning user", 500, err)
		}

		if deletedAt.Valid {
			user.DeletedAt = &deletedAt.Time
		}

		users = append(users, &user)
	}

	return users, nil
}

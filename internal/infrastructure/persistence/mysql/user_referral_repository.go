package mysql

import (
	"context"
	"database/sql"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

type UserReferralRepository struct {
	db *sql.DB
}

func NewUserReferralRepository(db *sql.DB) *UserReferralRepository {
	return &UserReferralRepository{db: db}
}

func (r *UserReferralRepository) Create(ctx context.Context, referral *domain.UserReferral) error {
	query := `
		INSERT INTO user_referrals (id, user_id, referrer_user_id, code_used, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err := execContextFrom(ctx, r.db).ExecContext(ctx, query,
		referral.ID, referral.UserID, referral.ReferrerUserID, referral.CodeUsed, referral.CreatedAt,
	)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error creating user referral", 500, err)
	}

	return nil
}

func (r *UserReferralRepository) GetByUserID(ctx context.Context, userID string) (*domain.UserReferral, error) {
	query := `
		SELECT id, user_id, referrer_user_id, code_used, created_at
		FROM user_referrals
		WHERE user_id = ?
	`

	var referral domain.UserReferral
	err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, userID).Scan(
		&referral.ID, &referral.UserID, &referral.ReferrerUserID, &referral.CodeUsed, &referral.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user referral", 500, err)
	}

	return &referral, nil
}

func (r *UserReferralRepository) CountByReferrer(ctx context.Context, referrerUserID string) (int, error) {
	query := `
		SELECT COUNT(1)
		FROM user_referrals
		WHERE referrer_user_id = ?
	`

	var count int
	if err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, referrerUserID).Scan(&count); err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error counting referrals", 500, err)
	}

	return count, nil
}

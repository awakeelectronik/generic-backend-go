package mysql

import (
	"context"
	"database/sql"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

type ReferralCodeRepository struct {
	db *sql.DB
}

func NewReferralCodeRepository(db *sql.DB) *ReferralCodeRepository {
	return &ReferralCodeRepository{db: db}
}

func (r *ReferralCodeRepository) GetByCode(ctx context.Context, code string) (*domain.ReferralCode, error) {
	query := `
		SELECT user_id, code, max_referrals, created_at
		FROM user_referral_codes
		WHERE code = ?
	`

	var referral domain.ReferralCode
	err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, code).Scan(
		&referral.UserID, &referral.Code, &referral.MaxReferrals, &referral.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching referral code", 500, err)
	}

	return &referral, nil
}

func (r *ReferralCodeRepository) GetByUserID(ctx context.Context, userID string) (*domain.ReferralCode, error) {
	query := `
		SELECT user_id, code, max_referrals, created_at
		FROM user_referral_codes
		WHERE user_id = ?
	`

	var referral domain.ReferralCode
	err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, userID).Scan(
		&referral.UserID, &referral.Code, &referral.MaxReferrals, &referral.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching referral code by user", 500, err)
	}

	return &referral, nil
}

func (r *ReferralCodeRepository) Create(ctx context.Context, code *domain.ReferralCode) error {
	query := `
		INSERT INTO user_referral_codes (user_id, code, max_referrals, created_at)
		VALUES (?, ?, ?, ?)
	`

	_, err := execContextFrom(ctx, r.db).ExecContext(ctx, query, code.UserID, code.Code, code.MaxReferrals, code.CreatedAt)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error creating referral code", 500, err)
	}

	return nil
}

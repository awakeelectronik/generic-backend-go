package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type CheckReferralInput struct {
	Code string `json:"code" binding:"required,len=6,alphanum"`
}

type CheckReferralOutput struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type CheckReferralUseCase struct {
	userRepo         application.UserRepository
	referralCodeRepo application.ReferralCodeRepository
	userReferralRepo application.UserReferralRepository
	logger           *logrus.Logger
}

func NewCheckReferralUseCase(
	userRepo application.UserRepository,
	referralCodeRepo application.ReferralCodeRepository,
	userReferralRepo application.UserReferralRepository,
	logger *logrus.Logger,
) *CheckReferralUseCase {
	return &CheckReferralUseCase{
		userRepo:         userRepo,
		referralCodeRepo: referralCodeRepo,
		userReferralRepo: userReferralRepo,
		logger:           logger,
	}
}

func (uc *CheckReferralUseCase) Execute(ctx context.Context, input CheckReferralInput) (*CheckReferralOutput, error) {
	code := strings.ToUpper(strings.TrimSpace(input.Code))
	if code == "" {
		return nil, appErrors.NewValidationError("code", "es obligatorio")
	}

	codeEntry, err := uc.referralCodeRepo.GetByCode(ctx, code)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error validando código de referido", 500, err)
	}
	if codeEntry == nil {
		return &CheckReferralOutput{Available: false, Reason: "Código inválido"}, nil
	}

	referrer, err := uc.userRepo.GetByID(ctx, codeEntry.UserID)
	if err != nil || referrer == nil {
		return &CheckReferralOutput{Available: false, Reason: "Código inválido"}, nil
	}

	count, err := uc.userReferralRepo.CountByReferrer(ctx, referrer.ID)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error validando cupo de referidos", 500, err)
	}
	if count >= codeEntry.MaxReferrals {
		return &CheckReferralOutput{Available: false, Reason: "Cupo de referidos agotado"}, nil
	}

	return &CheckReferralOutput{Available: true}, nil
}

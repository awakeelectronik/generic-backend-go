package auth

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/sirupsen/logrus"
)

type VerifyCodeInput struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required,len=4"`
}

type VerifyCodeOutput struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

type VerifyCodeUseCase struct {
	userRepo        application.UserRepository
	tokenProvider   application.TokenProvider
	verificationSvc application.VerificationService
	logger          *logrus.Logger
}

func NewVerifyCodeUseCase(
	userRepo application.UserRepository,
	tokenProvider application.TokenProvider,
	verificationSvc application.VerificationService,
	logger *logrus.Logger,
) *VerifyCodeUseCase {
	return &VerifyCodeUseCase{
		userRepo:        userRepo,
		tokenProvider:   tokenProvider,
		verificationSvc: verificationSvc,
		logger:          logger,
	}
}

func (uc *VerifyCodeUseCase) Execute(ctx context.Context, input VerifyCodeInput) (*VerifyCodeOutput, error) {
	uc.logger.WithField("user_id", input.UserID).Info("Verifying code")

	// Verify the code
	if err := uc.verificationSvc.VerifyCode(input.UserID, input.Code); err != nil {
		uc.logger.WithFields(logrus.Fields{
			"user_id": input.UserID,
			"error":   err.Error(),
		}).Warn("Code verification failed")
		return nil, err
	}

	// Get user
	user, err := uc.userRepo.GetByID(ctx, input.UserID)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to get user after verification")
		return nil, err
	}

	// Mark user as verified
	user.Verified = true
	if err := uc.userRepo.Update(ctx, user); err != nil {
		uc.logger.WithError(err).Error("Failed to update user verification status")
		return nil, err
	}

	// Generate tokens
	token, err := uc.tokenProvider.GenerateToken(user.ID, user.Email)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate token after verification")
		return nil, err
	}

	refreshToken, err := uc.tokenProvider.GenerateRefreshToken(user.ID)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate refresh token after verification")
		return nil, err
	}

	uc.logger.WithField("user_id", user.ID).Info("User verified and logged in successfully")

	return &VerifyCodeOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}


package auth

import (
	"context"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type LoginInput struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Phone    string `json:"phone" binding:"omitempty,len=10,numeric"`
	Password string `json:"password" binding:"required"`
}

// Validate only checks inter-field rules (at least one of email/phone).
// Field shape (password required, email format, phone shape) lives in the
// binding tags above so there's a single source of truth.
func (li LoginInput) Validate() error {
	if li.Email == "" && li.Phone == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	return nil
}

type LoginUseCase struct {
	userRepo       application.UserRepository
	passwordHasher application.PasswordHasher
	tokenProvider  application.TokenProvider
	logger         *logrus.Logger
}

func NewLoginUseCase(
	userRepo application.UserRepository,
	ph application.PasswordHasher,
	tp application.TokenProvider,
	logger *logrus.Logger,
) *LoginUseCase {
	return &LoginUseCase{
		userRepo:       userRepo,
		passwordHasher: ph,
		tokenProvider:  tp,
		logger:         logger,
	}
}

func (uc *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*SessionOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	uc.logger.WithFields(logrus.Fields{"email": input.Email, "phone": input.Phone}).Info("Login attempt")

	// Find user by email or phone (email preferred).
	user, err := findUserByEmailOrPhone(ctx, uc.userRepo, input.Email, input.Phone)
	if err != nil || user == nil {
		uc.logger.WithFields(logrus.Fields{"email": input.Email, "phone": input.Phone}).Warn("Login failed: user not found")
		return nil, appErrors.ErrUnauthorized
	}

	// Verify password
	if err := uc.passwordHasher.Compare(user.Password, input.Password); err != nil {
		uc.logger.WithFields(logrus.Fields{"email": input.Email, "phone": input.Phone}).Warn("Login failed: invalid password")
		return nil, appErrors.ErrUnauthorized
	}

	// Check if user is verified
	if !user.Verified {
		uc.logger.WithFields(logrus.Fields{"user_id": user.ID, "email": input.Email, "phone": input.Phone}).Warn("Login failed: user not verified")
		return nil, appErrors.NewAppErrorWithData(
			"UNVERIFIED_USER",
			"Usuario no verificado. Verifica tu correo o teléfono primero.",
			403,
			map[string]string{
				"user_id": user.ID,
				"email":   user.Email,
			},
		)
	}

	// Generate tokens
	token, refreshToken, err := issueTokenPair(uc.tokenProvider, user.ID, user.Email, user.TokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to issue tokens on login")
		return nil, err
	}

	uc.logger.WithField("user_id", user.ID).Info("User logged in successfully")

	return &SessionOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}

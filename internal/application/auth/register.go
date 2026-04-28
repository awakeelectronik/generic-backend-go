package auth

import (
	"context"
	"strings"
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type RegisterInput struct {
	Email        string `json:"email" binding:"omitempty,email"`
	Password     string `json:"password" binding:"required,min=5,max=20"`
	Name         string `json:"name" binding:"required,min=2"`
	Phone        string `json:"phone" binding:"omitempty,len=10,numeric"`
	ReferralCode string `json:"referral_code" binding:"omitempty,len=6,alphanum"`
}

// Validate checks that at least email or phone is provided. Referral code
// requirement is enforced in Execute based on the use case configuration so
// the same struct works for both REQUIRE_REFERRAL=true and =false deployments.
func (r *RegisterInput) Validate() error {
	if r.Email == "" && r.Phone == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	return nil
}

type RegisterOutput struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type RegisterUseCase struct {
	userRepo         application.UserRepository
	referralCodeRepo application.ReferralCodeRepository
	userReferralRepo application.UserReferralRepository
	passwordHasher   application.PasswordHasher
	verificationSvc  application.VerificationService
	requireReferral  bool
	logger           *logrus.Logger
}

// NewRegisterUseCase wires the registration flow.
//
// requireReferral toggles the referral_code requirement at runtime:
//   - true:  every register call must include a valid, non-exhausted code.
//   - false: referral_code is optional; if provided and valid, the link is
//     recorded; if provided and invalid, register fails (avoid silent loss).
//
// The referral repos may be passed as functioning implementations even when
// requireReferral is false; they remain idle until a code shows up in the
// request.
func NewRegisterUseCase(
	userRepo application.UserRepository,
	referralCodeRepo application.ReferralCodeRepository,
	userReferralRepo application.UserReferralRepository,
	ph application.PasswordHasher,
	verificationSvc application.VerificationService,
	requireReferral bool,
	logger *logrus.Logger,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepo:         userRepo,
		referralCodeRepo: referralCodeRepo,
		userReferralRepo: userReferralRepo,
		passwordHasher:   ph,
		verificationSvc:  verificationSvc,
		requireReferral:  requireReferral,
		logger:           logger,
	}
}

func (uc *RegisterUseCase) Execute(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	uc.logger.WithFields(logrus.Fields{
		"email":  input.Email,
		"action": "register",
	}).Info("User registration attempt")

	// Check if user exists (only if email is provided)
	if input.Email != "" {
		existing, _ := uc.userRepo.GetByEmail(ctx, input.Email)
		if existing != nil {
			uc.logger.WithField("email", input.Email).Warn("Registration failed: email already exists")
			return nil, appErrors.NewConflictError("El correo electrónico")
		}
	}
	// Check if user exists (only if phone is provided)
	if input.Phone != "" {
		existing, _ := uc.userRepo.GetByPhone(ctx, input.Phone)
		if existing != nil {
			uc.logger.WithField("phone", input.Phone).Warn("Registration failed: phone already exists")
			return nil, appErrors.NewConflictError("El teléfono")
		}
	}

	// Resolve referral (required vs optional vs absent).
	referralCode := strings.ToUpper(strings.TrimSpace(input.ReferralCode))
	var referrerID string
	if uc.requireReferral && referralCode == "" {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar un código de referido", 400)
	}
	if referralCode != "" {
		codeEntry, err := uc.referralCodeRepo.GetByCode(ctx, referralCode)
		if err != nil {
			uc.logger.WithError(err).Error("Failed to validate referral code")
			return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error validando código de referido", 500, err)
		}
		if codeEntry == nil {
			return nil, appErrors.NewAppError("VALIDATION_ERROR", "El código de referido no es válido", 400)
		}
		referrer, err := uc.userRepo.GetByID(ctx, codeEntry.UserID)
		if err != nil || referrer == nil {
			return nil, appErrors.NewAppError("VALIDATION_ERROR", "El código de referido no es válido", 400)
		}
		referralCount, err := uc.userReferralRepo.CountByReferrer(ctx, referrer.ID)
		if err != nil {
			uc.logger.WithError(err).Error("Failed to count referrals")
			return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error validando referidos", 500, err)
		}
		if referralCount >= codeEntry.MaxReferrals {
			return nil, appErrors.NewAppError("CONFLICT", "El código de referido ya alcanzó su límite", 409)
		}
		referrerID = referrer.ID
	}

	// Hash password
	hashedPassword, err := uc.passwordHasher.Hash(input.Password)
	if err != nil {
		uc.logger.WithError(err).Error("Password hashing failed")
		return nil, appErrors.NewAppErrorWithInternal("HASH_ERROR", "Error processing password", 500, err)
	}

	// Create user
	user := domain.NewUser(input.Email, hashedPassword, input.Name, input.Phone)

	if err := uc.userRepo.Create(ctx, user); err != nil {
		uc.logger.WithError(err).Error("Failed to create user")
		return nil, appErrors.NewAppErrorWithInternal("CREATE_ERROR", "Error creating user", 500, err)
	}

	// Record the referral link if a code was used. If this fails, roll back the
	// user so we don't end up with an orphan signup that bypassed the cap.
	if referrerID != "" {
		referral := &domain.UserReferral{
			ID:             uuid.NewString(),
			UserID:         user.ID,
			ReferrerUserID: referrerID,
			CodeUsed:       referralCode,
			CreatedAt:      time.Now(),
		}
		if err := uc.userReferralRepo.Create(ctx, referral); err != nil {
			uc.logger.WithError(err).Warn("Failed to create user referral")
			_ = uc.userRepo.Delete(ctx, user.ID)
			return nil, appErrors.NewAppErrorWithInternal("CREATE_ERROR", "Error creando referido", 500, err)
		}
	}

	// Send verification code (mismo código a correo y teléfono si ambos existen).
	var destinations []string
	if strings.TrimSpace(user.Email) != "" {
		destinations = append(destinations, user.Email)
	}
	if strings.TrimSpace(user.Phone) != "" {
		destinations = append(destinations, user.Phone)
	}

	if err := uc.verificationSvc.SendVerificationCodeToDestinations(user.ID, destinations); err != nil {
		// Log error but don't fail registration - user can request new code later
		uc.logger.WithError(err).WithField("user_id", user.ID).Warn("Failed to send verification code during registration")
	}

	uc.logger.WithField("user_id", user.ID).Info("User registered successfully")

	return &RegisterOutput{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Name,
	}, nil
}

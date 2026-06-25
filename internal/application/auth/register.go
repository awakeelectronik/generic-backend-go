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
	Password     string `json:"password" binding:"required,min=8,max=72"`
	Name         string `json:"name" binding:"required,min=2"`
	Phone        string `json:"phone" binding:"omitempty,len=10,numeric"`
	ReferralCode string `json:"referral_code" binding:"omitempty,len=6,alphanum"`
}

// Validate enforces inter-field rules that binding tags can't express
// (at least one of email/phone must be present) plus the password byte bound.
// Per-field shape rules (formats) live in the binding tags above.
//
// El binding `max=72` cuenta RUNAS, pero bcrypt trunca a 72 BYTES: una
// contraseña de runas multibyte podría pasar el binding y aun así exceder los
// 72 bytes (perdiendo el final de forma silenciosa). Por eso aquí se valida con
// len() —que en Go cuenta bytes— el mismo límite efectivo de bcrypt.
func (r *RegisterInput) Validate() error {
	if r.Email == "" && r.Phone == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	if n := len(r.Password); n < 8 || n > 72 {
		return appErrors.NewAppError("VALIDATION_ERROR", "La contraseña debe tener entre 8 y 72 caracteres", 400)
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
	txRunner         application.TransactionRunner
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
// The user-create + referral-link inserts run inside a single transaction
// (txRunner): if anything in the chain fails, both rows are rolled back
// atomically — no orphan signups, no soft-deleted rows squatting the email
// UNIQUE index. The referral row is also gated by SELECT ... FOR UPDATE on
// the code, so concurrent registers can't both pass MaxReferrals at the limit.
func NewRegisterUseCase(
	userRepo application.UserRepository,
	referralCodeRepo application.ReferralCodeRepository,
	userReferralRepo application.UserReferralRepository,
	txRunner application.TransactionRunner,
	ph application.PasswordHasher,
	verificationSvc application.VerificationService,
	requireReferral bool,
	logger *logrus.Logger,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepo:         userRepo,
		referralCodeRepo: referralCodeRepo,
		userReferralRepo: userReferralRepo,
		txRunner:         txRunner,
		passwordHasher:   ph,
		verificationSvc:  verificationSvc,
		requireReferral:  requireReferral,
		logger:           logger,
	}
}

func (uc *RegisterUseCase) Execute(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	uc.logger.WithFields(logrus.Fields{
		"email":  input.Email,
		"action": "register",
	}).Info("User registration attempt")

	// Pre-check de duplicados (rápido, antes de hashear). El UNIQUE de la BD
	// es el guardia final para race conditions.
	if input.Email != "" {
		existing, _ := uc.userRepo.GetByEmail(ctx, input.Email)
		if existing != nil {
			return nil, appErrors.NewConflictError("El correo electrónico")
		}
	}
	if input.Phone != "" {
		existing, _ := uc.userRepo.GetByPhone(ctx, input.Phone)
		if existing != nil {
			return nil, appErrors.NewConflictError("El teléfono")
		}
	}

	// Resolución del referido fuera de tx — solo para feedback temprano
	// (existencia del código). El chequeo definitivo del cupo ocurre dentro
	// de la tx con FOR UPDATE.
	referralCode := strings.ToUpper(strings.TrimSpace(input.ReferralCode))
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
	}

	hashedPassword, err := uc.passwordHasher.Hash(input.Password)
	if err != nil {
		uc.logger.WithError(err).Error("Password hashing failed")
		return nil, appErrors.NewAppErrorWithInternal("HASH_ERROR", "Error processing password", 500, err)
	}

	user, err := domain.NewUser(input.Email, hashedPassword, input.Name, input.Phone)
	if err != nil {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", err.Error(), 400)
	}

	// Inserta user y (si aplica) la fila de referido en una sola transacción.
	// Si el INSERT del referido falla, el INSERT del user hace rollback real,
	// no soft-delete: el correo queda libre para un siguiente intento.
	txErr := uc.txRunner.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := uc.userRepo.Create(txCtx, user); err != nil {
			return err
		}
		if referralCode == "" {
			return nil
		}

		// Lock del código para que dos registros simultáneos no rebasen el cupo.
		codeEntry, err := uc.referralCodeRepo.GetByCodeForUpdate(txCtx, referralCode)
		if err != nil {
			return err
		}
		if codeEntry == nil {
			return appErrors.NewAppError("VALIDATION_ERROR", "El código de referido no es válido", 400)
		}
		count, err := uc.userReferralRepo.CountByReferrer(txCtx, codeEntry.UserID)
		if err != nil {
			return err
		}
		if count >= codeEntry.MaxReferrals {
			return appErrors.NewAppError("CONFLICT", "El código de referido ya alcanzó su límite", 409)
		}

		referral := &domain.UserReferral{
			ID:             uuid.NewString(),
			UserID:         user.ID,
			ReferrerUserID: codeEntry.UserID,
			CodeUsed:       referralCode,
			CreatedAt:      time.Now(),
		}
		return uc.userReferralRepo.Create(txCtx, referral)
	})
	if txErr != nil {
		uc.logger.WithError(txErr).Warn("Register transaction rolled back")
		return nil, txErr
	}

	// Send verification code (mismo código a correo y teléfono si ambos existen).
	destinations := userDestinations(user)

	if err := uc.verificationSvc.SendVerificationCodeToDestinations(user.ID, destinations); err != nil {
		// No falla el registro: el user puede pedir reenvío con resend-verification-code.
		uc.logger.WithError(err).WithField("user_id", user.ID).Warn("Failed to send verification code during registration")
	}

	uc.logger.WithField("user_id", user.ID).Info("User registered successfully")

	return &RegisterOutput{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Name,
	}, nil
}

package auth

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/sirupsen/logrus"
)

type RegisterInput struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Password string `json:"password" binding:"required,min=5"`
	Name     string `json:"name" binding:"required,min=2"`
	Phone    string `json:"phone" binding:"omitempty,len=10,numeric"`
}

// Validate checks that at least email or phone is provided
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
	userRepo       application.UserRepository
	passwordHasher application.PasswordHasher
	verificationSvc application.VerificationService
	logger         *logrus.Logger
}

func NewRegisterUseCase(
	userRepo application.UserRepository,
	ph application.PasswordHasher,
	verificationSvc application.VerificationService,
	logger *logrus.Logger,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepo:       userRepo,
		passwordHasher: ph,
		verificationSvc: verificationSvc,
		logger:         logger,
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

	// Hash password
	hashedPassword, err := uc.passwordHasher.Hash(input.Password)
	if err != nil {
		uc.logger.WithError(err).Error("Password hashing failed")
		return nil, appErrors.NewAppErrorWithInternal("HASH_ERROR", "Error processing password", 500, err)
	}

	// Create user
	user := domain.NewUser(input.Email, hashedPassword, input.Name, input.Phone)

	// Persist
	if err := uc.userRepo.Create(ctx, user); err != nil {
		uc.logger.WithError(err).Error("Failed to create user")
		return nil, appErrors.NewAppErrorWithInternal("CREATE_ERROR", "Error creating user", 500, err)
	}

	// Send verification code
	destination := user.Email
	if user.Phone != "" {
		destination = user.Phone
	}

	if err := uc.verificationSvc.SendVerificationCode(user.ID, destination); err != nil {
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

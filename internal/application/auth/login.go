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

// fallbackDummyHash es un bcrypt válido (cost 10) usado solo si el hasher no
// logra generar el dummy de timing en el arranque. Garantiza que siempre haya
// algo contra qué comparar; no corresponde a ninguna contraseña real.
const fallbackDummyHash = "$2a$10$.T41y66gcvsVNa8Q4VpzG.KONyddOsVJEZUPKs41HPdjVkMoBsk3O"

type LoginUseCase struct {
	userRepo       application.UserRepository
	passwordHasher application.PasswordHasher
	tokenProvider  application.TokenProvider
	logger         *logrus.Logger
	// dummyHash se compara cuando el usuario no existe para que el coste bcrypt
	// (y por tanto el tiempo de respuesta) sea indistinguible de un login con
	// usuario real pero contraseña incorrecta. Sin esto, "usuario no existe"
	// responde mucho más rápido y permite enumerar cuentas por timing.
	dummyHash string
}

func NewLoginUseCase(
	userRepo application.UserRepository,
	ph application.PasswordHasher,
	tp application.TokenProvider,
	logger *logrus.Logger,
) *LoginUseCase {
	// Pre-calculamos un hash con el mismo hasher (mismo coste) que los reales,
	// para que el trabajo de bcrypt en el camino de usuario-inexistente sea
	// equivalente al de un usuario real.
	dummy, err := ph.Hash("timing-equalizer-dummy-secret")
	if err != nil || dummy == "" {
		dummy = fallbackDummyHash
	}
	return &LoginUseCase{
		userRepo:       userRepo,
		passwordHasher: ph,
		tokenProvider:  tp,
		logger:         logger,
		dummyHash:      dummy,
	}
}

func (uc *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*SessionOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	uc.logger.WithFields(logrus.Fields{"email": maskEmail(input.Email), "phone": maskPhone(input.Phone)}).Info("Login attempt")

	// Find user by email or phone (email preferred).
	user, err := findUserByEmailOrPhone(ctx, uc.userRepo, input.Email, input.Phone)
	if err != nil || user == nil {
		// Comparamos contra el hash dummy aunque no haya usuario: igualamos el
		// coste bcrypt para no filtrar por timing si la cuenta existe o no.
		_ = uc.passwordHasher.Compare(uc.dummyHash, input.Password)
		uc.logger.WithFields(logrus.Fields{"email": maskEmail(input.Email), "phone": maskPhone(input.Phone)}).Warn("Login failed: user not found")
		return nil, appErrors.ErrUnauthorized
	}

	// Verify password
	if err := uc.passwordHasher.Compare(user.Password, input.Password); err != nil {
		uc.logger.WithFields(logrus.Fields{"email": maskEmail(input.Email), "phone": maskPhone(input.Phone)}).Warn("Login failed: invalid password")
		return nil, appErrors.ErrUnauthorized
	}

	// Check if user is verified
	if !user.Verified {
		uc.logger.WithFields(logrus.Fields{"user_id": user.ID, "email": maskEmail(input.Email), "phone": maskPhone(input.Phone)}).Warn("Login failed: user not verified")
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

package auth

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ResetPasswordInput struct {
	Email       string `json:"email" binding:"omitempty,email,max=254"`
	Phone       string `json:"phone" binding:"omitempty,len=10,numeric"`
	Code        string `json:"code" binding:"required,len=6"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

func (r ResetPasswordInput) Validate() error {
	if strings.TrimSpace(r.Email) == "" && strings.TrimSpace(r.Phone) == "" {
		return appErrors.NewAppError("VALIDATION_ERROR", "Debes proporcionar correo electrónico o teléfono", 400)
	}
	if len(r.Code) != 6 {
		return appErrors.NewAppError("VALIDATION_ERROR", "El código debe tener 6 caracteres", 400)
	}
	// len() cuenta bytes (no runas): es el límite real de bcrypt (72 bytes),
	// más estricto que el binding `max=72` que cuenta runas.
	if len(r.NewPassword) < 8 || len(r.NewPassword) > 72 {
		return appErrors.NewAppError("VALIDATION_ERROR", "La contraseña debe tener entre 8 y 72 caracteres", 400)
	}
	return nil
}

// errResetInvalid es la única respuesta de fallo de reset-password. Mensaje y
// código estables e independientes del estado real, para no filtrar existencia
// de cuenta ni de código pendiente.
func errResetInvalid() *appErrors.AppError {
	return appErrors.NewAppError("RESET_INVALID", "El código es inválido o ha expirado. Solicita uno nuevo.", 400)
}

type ResetPasswordUseCase struct {
	userRepo        application.UserRepository
	passwordHasher  application.PasswordHasher
	verificationSvc application.VerificationService
	tokenProvider   application.TokenProvider
	logger          *logrus.Logger
}

func NewResetPasswordUseCase(
	userRepo application.UserRepository,
	passwordHasher application.PasswordHasher,
	verificationSvc application.VerificationService,
	tokenProvider application.TokenProvider,
	logger *logrus.Logger,
) *ResetPasswordUseCase {
	return &ResetPasswordUseCase{
		userRepo:        userRepo,
		passwordHasher:  passwordHasher,
		verificationSvc: verificationSvc,
		tokenProvider:   tokenProvider,
		logger:          logger,
	}
}

func (uc *ResetPasswordUseCase) Execute(ctx context.Context, input ResetPasswordInput) (*SessionOutput, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	user, err := findUserByEmailOrPhone(ctx, uc.userRepo, normalizeEmail(input.Email), input.Phone)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to fetch user for password reset")
		return nil, err
	}

	// Anti-enumeración robusta: TODOS los fallos de reset —cuenta inexistente,
	// sin código pendiente, código incorrecto, expirado o usado— colapsan en una
	// ÚNICA respuesta genérica. Devolver errores distintos (NotFound vs Invalid)
	// reabría la enumeración: un atacante primea el estado "con código" con un
	// forgot-password previo y distingue cuenta real de inexistente por el
	// mensaje. Un reset endpoint no necesita decir POR QUÉ falló; el usuario
	// legítimo con el código correcto igual pasa.
	if user == nil {
		uc.logger.Warn("Reset password: unknown account (respuesta genérica)")
		return nil, errResetInvalid()
	}

	if err := uc.verificationSvc.VerifyCode(user.ID, input.Code); err != nil {
		uc.logger.WithError(err).WithField("user_id", user.ID).Warn("Reset password: code check failed (respuesta genérica)")
		return nil, errResetInvalid()
	}

	newHash, err := uc.passwordHasher.Hash(input.NewPassword)
	if err != nil {
		uc.logger.WithError(err).Error("Password hashing failed")
		return nil, appErrors.ErrInternalServer
	}

	newTokenVersion, err := uc.userRepo.UpdatePasswordAndBumpTokenVersion(ctx, user.ID, newHash)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to update password")
		return nil, err
	}
	token, refreshToken, err := issueTokenPair(uc.tokenProvider, user.ID, user.Email, newTokenVersion)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to issue tokens after password reset")
		return nil, err
	}

	return &SessionOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}

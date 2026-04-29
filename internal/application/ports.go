package application

import (
	"context"
	"io"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
)

// === REPOSITORIES ===

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByPhone(ctx context.Context, phone string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	UpdatePasswordAndBumpTokenVersion(ctx context.Context, userID, passwordHash string) error
	// BumpTokenVersion incrementa token_version en 1, invalidando todos los
	// access/refresh tokens previos del usuario. Lo usa /auth/refresh para
	// rotar el refresh: el que acaba de presentarse queda revocado.
	BumpTokenVersion(ctx context.Context, userID string) error
	Delete(ctx context.Context, id string) error
	// ListWithSummary devuelve la página filtrada por q (sobre name, email, phone) más
	// totales agregados (totalUsers, activeUsers, inactiveUsers). q vacío = sin filtro.
	ListWithSummary(ctx context.Context, limit, offset int, q string) (users []*domain.User, total int, active int, inactive int, err error)
}

type ReferralCodeRepository interface {
	GetByCode(ctx context.Context, code string) (*domain.ReferralCode, error)
	// GetByCodeForUpdate is the same lookup with SELECT ... FOR UPDATE.
	// Only meaningful inside a TransactionRunner.WithTransaction call:
	// it locks the row so concurrent registers using the same code can't
	// both pass the MaxReferrals check at the limit.
	GetByCodeForUpdate(ctx context.Context, code string) (*domain.ReferralCode, error)
	GetByUserID(ctx context.Context, userID string) (*domain.ReferralCode, error)
	Create(ctx context.Context, code *domain.ReferralCode) error
}

type UserReferralRepository interface {
	Create(ctx context.Context, referral *domain.UserReferral) error
	GetByUserID(ctx context.Context, userID string) (*domain.UserReferral, error)
	CountByReferrer(ctx context.Context, referrerUserID string) (int, error)
}

type DocumentRepository interface {
	Create(ctx context.Context, doc *domain.Document) error
	GetByID(ctx context.Context, id string) (*domain.Document, error)
	GetByUserID(ctx context.Context, userID string, limit, offset int) ([]*domain.Document, error)
	CountByUserID(ctx context.Context, userID string) (int, error)
	Update(ctx context.Context, doc *domain.Document) error
	Delete(ctx context.Context, id string) error
}

// === STORAGE ===

type FileStorage interface {
	// Save guarda un archivo y retorna (storedPath, originalName, error)
	Save(
		ctx context.Context,
		userID string,
		fileName string,
		file io.Reader,
		size int64,
	) (string, string, error)
	Get(ctx context.Context, filePath string) (io.ReadCloser, error)
	GetURL(filePath string) string
}

// === SECURITY ===

type TokenProvider interface {
	GenerateToken(userID, email string, tokenVersion int) (string, error)
	GenerateRefreshToken(userID string, tokenVersion int) (string, error)
	ValidateToken(tokenString string) (userID string, email string, tokenVersion int, err error)
	ValidateRefreshToken(tokenString string) (userID string, tokenVersion int, err error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}



type VerificationService interface {
	SendVerificationCode(userID, destination string) error
	// SendVerificationCodeToDestinations genera un único código y lo entrega a cada destino (correo y/o teléfono).
	SendVerificationCodeToDestinations(userID string, destinations []string) error
	VerifyCode(userID, code string) error
}

// EmailSender abstracts email delivery so tests can inject a NoopSender
// and production can plug in any concrete implementation.
type EmailSender interface {
	Send(to, subject, body string) error
}

// TransactionRunner ejecuta una función dentro de una transacción de BD.
// Si fn retorna error se hace rollback; si no, commit.
type TransactionRunner interface {
	WithTransaction(ctx context.Context, fn func(context.Context) error) error
}

// AdminChecker indica si un usuario es administrador de la aplicación.
// La implementación concreta (p. ej. por email+teléfono) vive en infraestructura.
type AdminChecker interface {
	IsAdmin(user *domain.User) bool
}
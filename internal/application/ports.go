package application

import (
	"context"
	"io"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
)

// === REPOSITORIES ===

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByPhone(ctx context.Context, phone string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, limit, offset int) ([]*domain.User, error)
}

type DocumentRepository interface {
	Create(ctx context.Context, doc *domain.Document) error
	GetByID(ctx context.Context, id string) (*domain.Document, error)
	GetByUserID(ctx context.Context, userID string, limit, offset int) ([]*domain.Document, error)
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
	GenerateToken(userID, email string) (string, error)
	GenerateRefreshToken(userID string) (string, error)
	ValidateToken(tokenString string) (userID string, email string, err error)
	ValidateRefreshToken(tokenString string) (userID string, err error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

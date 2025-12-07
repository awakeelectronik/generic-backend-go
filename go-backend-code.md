# Clean Architecture Backend - Go
## Guía Completa de Archivos (Sin Docker ni S3)

---

## 1. go.mod

```go
module github.com/awakeelectronik/sumabitcoin-backend

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/go-sql-driver/mysql v1.7.1
	golang.org/x/crypto v0.16.0
	github.com/joho/godotenv v1.5.1
	github.com/google/uuid v1.5.0
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/bytedance/sonic v1.9.10
	github.com/chenzhuoyu/x86 v0.0.0-20230321173325-e6f059ecb569
	github.com/gabriel-vasile/mimetype v1.4.2
	github.com/gin-contrib/sse v0.1.0
	github.com/go-playground/locales v0.14.1
	github.com/go-playground/universal-translator v0.18.1
	github.com/go-playground/validator/v10 v10.15.4
	github.com/goccy/go-json v0.10.2
	github.com/json-iterator/go v1.1.12
	github.com/klauspost/cpuid/v2 v2.2.5
	github.com/leodido/go-urn v1.2.4
	github.com/mattn/go-isatty v0.0.20
	github.com/modern-go/concurrent v0.0.0-20230330173713-942fedbb3226
	github.com/modern-go/reflect2 v1.0.2
	github.com/pelletier/go-toml/v2 v2.1.0
	github.com/ugorji/go/codec v1.2.12
	golang.org/x/net v0.19.0
	golang.org/x/sys v0.15.0
	golang.org/x/text v0.14.0
	google.golang.org/protobuf v1.31.0
	gopkg.in/yaml.v3 v3.0.1
)
```

---

## 2. cmd/main.go

```go
package main

import (
	"database/sql"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/config"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http/middleware"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/persistence/mysql"
)

func main() {
	// Load .env
	_ = godotenv.Load()

	// Load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Setup logger
	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)

	// Connect to database
	db, err := mysql.NewConnection(cfg.Database)
	if err != nil {
		logger.Fatalf("Database connection failed: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := mysql.RunMigrations(db); err != nil {
		logger.Fatalf("Migration failed: %v", err)
	}

	logger.Info("✅ Database connected and migrated")

	// Build dependencies
	deps := config.BuildDependencies(db, cfg, logger)

	// Setup router
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Middleware
	router.Use(middleware.CORSMiddleware())
	router.Use(middleware.LoggingMiddleware(logger))
	router.Use(middleware.ErrorHandlingMiddleware())

	// Routes
	http.SetupRoutes(router, deps, logger)

	// Start server
	logger.Infof("🚀 Server starting on http://localhost:%s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		logger.Fatalf("Error starting server: %v", err)
	}
}
```

---

## 3. internal/config/config.go

```go
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Storage  StorageConfig
}

type ServerConfig struct {
	Port        string
	Environment string
	BaseURL     string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	MaxConn  int
	IdleConn int
	MaxLife  time.Duration
}

type JWTConfig struct {
	Secret          string
	ExpirationHours int
	RefreshHours    int
	IssuerName      string
}

type StorageConfig struct {
	Type        string
	LocalPath   string
	MaxFileSize int64
	AllowedMimes []string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		Server: ServerConfig{
			Port:        getEnv("PORT", "8080"),
			Environment: getEnv("ENVIRONMENT", "development"),
			BaseURL:     getEnv("BASE_URL", "http://localhost:8080"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "3306"),
			User:     getEnv("DB_USER", "root"),
			Password: getEnv("DB_PASSWORD", ""),
			Name:     getEnv("DB_NAME", "identity_db"),
			MaxConn:  getEnvInt("DB_MAX_CONN", 25),
			IdleConn: getEnvInt("DB_IDLE_CONN", 5),
			MaxLife:  time.Hour,
		},
		JWT: JWTConfig{
			Secret:          getEnv("JWT_SECRET", ""),
			ExpirationHours: getEnvInt("JWT_EXPIRATION", 24),
			RefreshHours:    getEnvInt("JWT_REFRESH", 168),
			IssuerName:      "sumabitcoin",
		},
		Storage: StorageConfig{
			Type:        "local",
			LocalPath:   getEnv("STORAGE_PATH", "./uploads"),
			MaxFileSize: int64(getEnvInt("MAX_FILE_SIZE", 5*1024*1024)),
			AllowedMimes: []string{"image/jpeg", "image/jpg"},
		},
	}

	if cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET not configured")
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
```

---

## 4. internal/config/dependencies.go

```go
package config

import (
	"database/sql"

	"github.com/sirupsen/logrus"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	authUC "github.com/awakeelectronik/sumabitcoin-backend/internal/application/auth"
	docUC "github.com/awakeelectronik/sumabitcoin-backend/internal/application/document"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http/handlers"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/persistence/mysql"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/persistence/storage"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/security"
)

type Dependencies struct {
	// Repositories
	UserRepo     application.UserRepository
	DocumentRepo application.DocumentRepository

	// Storage
	FileStorage application.FileStorage

	// Security
	PasswordHasher application.PasswordHasher
	TokenProvider  application.TokenProvider

	// Handlers
	AuthHandler     *handlers.AuthHandler
	UserHandler     *handlers.UserHandler
	DocumentHandler *handlers.DocumentHandler

	// Logger
	Logger *logrus.Logger
}

func BuildDependencies(db *sql.DB, cfg *Config, logger *logrus.Logger) *Dependencies {
	// Repositories
	userRepo := mysql.NewUserRepository(db)
	documentRepo := mysql.NewDocumentRepository(db)

	// Storage
	fileStorage := storage.NewLocalStorage(cfg.Storage.LocalPath, cfg.Server.BaseURL)

	// Security
	passwordHasher := security.NewPasswordHasher()
	tokenProvider := security.NewJWTProvider(&cfg.JWT)

	// Use Cases
	registerUC := authUC.NewRegisterUseCase(userRepo, passwordHasher, logger)
	loginUC := authUC.NewLoginUseCase(userRepo, passwordHasher, tokenProvider, logger)
	refreshUC := authUC.NewRefreshUseCase(tokenProvider, logger)

	uploadDocUC := docUC.NewUploadDocumentUseCase(documentRepo, fileStorage, cfg.Storage.MaxFileSize, logger)
	getDocUC := docUC.NewGetDocumentUseCase(documentRepo, logger)
	listDocsUC := docUC.NewListDocumentsUseCase(documentRepo, logger)

	// Handlers
	authHandler := handlers.NewAuthHandler(registerUC, loginUC, refreshUC, logger)
	userHandler := handlers.NewUserHandler(userRepo, logger)
	documentHandler := handlers.NewDocumentHandler(uploadDocUC, getDocUC, listDocsUC, logger)

	return &Dependencies{
		UserRepo:        userRepo,
		DocumentRepo:    documentRepo,
		FileStorage:     fileStorage,
		PasswordHasher:   passwordHasher,
		TokenProvider:   tokenProvider,
		AuthHandler:     authHandler,
		UserHandler:     userHandler,
		DocumentHandler: documentHandler,
		Logger:          logger,
	}
}
```

---

## 5. pkg/errors/errors.go

```go
package errors

import (
	"fmt"
	"net/http"
)

type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Internal   error  `json:"-"`
}

func (e *AppError) Error() string {
	return e.Message
}

var (
	ErrUnauthorized   = &AppError{Code: "UNAUTHORIZED", Message: "Unauthorized", StatusCode: http.StatusUnauthorized}
	ErrForbidden      = &AppError{Code: "FORBIDDEN", Message: "Forbidden", StatusCode: http.StatusForbidden}
	ErrNotFound       = &AppError{Code: "NOT_FOUND", Message: "Resource not found", StatusCode: http.StatusNotFound}
	ErrInvalidInput   = &AppError{Code: "INVALID_INPUT", Message: "Invalid input", StatusCode: http.StatusBadRequest}
	ErrConflict       = &AppError{Code: "CONFLICT", Message: "Resource conflict", StatusCode: http.StatusConflict}
	ErrInternalServer = &AppError{Code: "INTERNAL_ERROR", Message: "Internal server error", StatusCode: http.StatusInternalServerError}
)

func NewAppError(code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

func NewAppErrorWithInternal(code, message string, statusCode int, internal error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Internal:   internal,
	}
}

func NewNotFoundError(resource string) *AppError {
	return NewAppError("NOT_FOUND", fmt.Sprintf("%s not found", resource), http.StatusNotFound)
}

func NewConflictError(resource string) *AppError {
	return NewAppError("CONFLICT", fmt.Sprintf("%s already exists", resource), http.StatusConflict)
}

func NewValidationError(field, reason string) *AppError {
	return NewAppError("VALIDATION_ERROR", fmt.Sprintf("Field '%s': %s", field, reason), http.StatusBadRequest)
}
```

---

## 6. internal/domain/user.go

```go
package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        string
	Email     string
	Password  string
	Name    string
	Phone   string
	Verified  bool
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

func NewUser(email, password, name, phone string) *User {
	return &User{
		ID:        uuid.New().String(),
		Email:     email,
		Password:  password,
		Name:    name,
		Phone:   phone,
		Verified:  false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (u *User) IsActive() bool {
	return u.DeletedAt == nil
}

func (u *User) Delete() {
	now := time.Now()
	u.DeletedAt = &now
}
```

---

## 7. internal/domain/document.go

```go
package domain

import (
	"time"

	"github.com/google/uuid"
)

type DocumentStatus string

const (
	StatusPending  DocumentStatus = "pending"
	StatusVerified DocumentStatus = "verified"
	StatusRejected DocumentStatus = "rejected"
)

type Document struct {
	ID        string
	UserID    string
	FileName  string
	FilePath  string
	FileSize  int64
	MimeType  string
	Status    DocumentStatus
	Metadata  map[string]interface{}
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewDocument(userID, fileName, filePath, mimeType string, fileSize int64) *Document {
	return &Document{
		ID:        uuid.New().String(),
		UserID:    userID,
		FileName:  fileName,
		FilePath:  filePath,
		MimeType:  mimeType,
		FileSize:  fileSize,
		Status:    StatusPending,
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (d *Document) Verify() {
	d.Status = StatusVerified
	d.UpdatedAt = time.Now()
}

func (d *Document) Reject() {
	d.Status = StatusRejected
	d.UpdatedAt = time.Now()
}
```

---

## 8. internal/application/ports.go

```go
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
	Save(ctx context.Context, fileName string, file io.Reader, size int64) (filePath string, err error)
	Delete(ctx context.Context, filePath string) error
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
```

---

## 9. internal/application/auth/register.go

```go
package auth

import (
	"context"

	"github.com/sirupsen/logrus"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
)

type RegisterInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Name   string `json:"name" binding:"required,min=2"`
	Phone  string `json:"phone" binding:"required"`
}

type RegisterOutput struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Name string `json:"name"`
}

type RegisterUseCase struct {
	userRepo       application.UserRepository
	passwordHasher application.PasswordHasher
	logger         *logrus.Logger
}

func NewRegisterUseCase(
	userRepo application.UserRepository,
	ph application.PasswordHasher,
	logger *logrus.Logger,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepo:       userRepo,
		passwordHasher: ph,
		logger:         logger,
	}
}

func (uc *RegisterUseCase) Execute(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	uc.logger.WithFields(logrus.Fields{
		"email":  input.Email,
		"action": "register",
	}).Info("User registration attempt")

	// Check if user exists
	existing, _ := uc.userRepo.GetByEmail(ctx, input.Email)
	if existing != nil {
		uc.logger.WithField("email", input.Email).Warn("Registration failed: email already exists")
		return nil, appErrors.NewConflictError("Email")
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

	uc.logger.WithField("user_id", user.ID).Info("User registered successfully")

	return &RegisterOutput{
		ID:     user.ID,
		Email:  user.Email,
		Name: user.Name,
	}, nil
}
```

---

## 10. internal/application/auth/login.go

```go
package auth

import (
	"context"

	"github.com/sirupsen/logrus"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
)

type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginOutput struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
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

func (uc *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	uc.logger.WithField("email", input.Email).Info("Login attempt")

	// Find user
	user, err := uc.userRepo.GetByEmail(ctx, input.Email)
	if err != nil || user == nil {
		uc.logger.WithField("email", input.Email).Warn("Login failed: user not found")
		return nil, appErrors.ErrUnauthorized
	}

	// Verify password
	if err := uc.passwordHasher.Compare(user.Password, input.Password); err != nil {
		uc.logger.WithField("email", input.Email).Warn("Login failed: invalid password")
		return nil, appErrors.ErrUnauthorized
	}

	// Generate tokens
	token, err := uc.tokenProvider.GenerateToken(user.ID, user.Email)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate token")
		return nil, appErrors.ErrInternalServer
	}

	refreshToken, err := uc.tokenProvider.GenerateRefreshToken(user.ID)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate refresh token")
		return nil, appErrors.ErrInternalServer
	}

	uc.logger.WithField("user_id", user.ID).Info("User logged in successfully")

	return &LoginOutput{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
	}, nil
}
```

---

## 11. internal/application/auth/refresh.go

```go
package auth

import (
	"context"

	"github.com/sirupsen/logrus"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
)

type RefreshInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshOutput struct {
	Token string `json:"token"`
}

type RefreshUseCase struct {
	tokenProvider application.TokenProvider
	logger        *logrus.Logger
}

func NewRefreshUseCase(
	tp application.TokenProvider,
	logger *logrus.Logger,
) *RefreshUseCase {
	return &RefreshUseCase{
		tokenProvider: tp,
		logger:        logger,
	}
}

func (uc *RefreshUseCase) Execute(ctx context.Context, input RefreshInput) (*RefreshOutput, error) {
	uc.logger.Info("Token refresh attempt")

	userID, err := uc.tokenProvider.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		uc.logger.WithError(err).Warn("Invalid refresh token")
		return nil, appErrors.ErrUnauthorized
	}

	token, err := uc.tokenProvider.GenerateToken(userID, "")
	if err != nil {
		uc.logger.WithError(err).Error("Failed to generate new token")
		return nil, appErrors.ErrInternalServer
	}

	uc.logger.WithField("user_id", userID).Info("Token refreshed successfully")

	return &RefreshOutput{Token: token}, nil
}
```

---

## 12. internal/application/document/upload.go

```go
package document

import (
	"context"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
)

type UploadDocumentInput struct {
	UserID   string
	FileName string
	File     io.Reader
	FileSize int64
	MimeType string
}

type UploadDocumentOutput struct {
	DocumentID string `json:"document_id"`
	FileName   string `json:"file_name"`
	Status     string `json:"status"`
}

type UploadDocumentUseCase struct {
	docRepo     application.DocumentRepository
	fileStorage application.FileStorage
	maxFileSize int64
	logger      *logrus.Logger
}

func NewUploadDocumentUseCase(
	docRepo application.DocumentRepository,
	fileStorage application.FileStorage,
	maxFileSize int64,
	logger *logrus.Logger,
) *UploadDocumentUseCase {
	return &UploadDocumentUseCase{
		docRepo:     docRepo,
		fileStorage: fileStorage,
		maxFileSize: maxFileSize,
		logger:      logger,
	}
}

func (uc *UploadDocumentUseCase) Execute(ctx context.Context, input UploadDocumentInput) (*UploadDocumentOutput, error) {
	uc.logger.WithFields(logrus.Fields{
		"user_id":    input.UserID,
		"file_name":  input.FileName,
		"file_size":  input.FileSize,
		"mime_type":  input.MimeType,
		"action":     "upload_document",
	}).Info("Document upload started")

	// Validate file size
	if input.FileSize > uc.maxFileSize {
		err := appErrors.NewValidationError("file_size", fmt.Sprintf("Max %d bytes", uc.maxFileSize))
		uc.logger.WithError(err).Warn("File size validation failed")
		return nil, err
	}

	// Validate MIME type
	if input.MimeType != "image/jpeg" && input.MimeType != "image/jpg" {
		err := appErrors.NewValidationError("mime_type", "Only JPG files allowed")
		uc.logger.WithError(err).Warn("MIME type validation failed")
		return nil, err
	}

	// Save file
	fileName := fmt.Sprintf("%s_%s", input.UserID, input.FileName)
	filePath, err := uc.fileStorage.Save(ctx, fileName, input.File, input.FileSize)
	if err != nil {
		uc.logger.WithError(err).Error("File storage failed")
		return nil, appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error saving document", 500, err)
	}

	// Create database record
	doc := domain.NewDocument(input.UserID, input.FileName, filePath, input.MimeType, input.FileSize)
	if err := uc.docRepo.Create(ctx, doc); err != nil {
		_ = uc.fileStorage.Delete(ctx, filePath)
		uc.logger.WithError(err).Error("Failed to save document record")
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error saving document reference", 500, err)
	}

	uc.logger.WithFields(logrus.Fields{
		"document_id": doc.ID,
		"user_id":     input.UserID,
	}).Info("Document uploaded successfully")

	return &UploadDocumentOutput{
		DocumentID: doc.ID,
		FileName:   doc.FileName,
		Status:     string(doc.Status),
	}, nil
}
```

---

## 13. internal/application/document/get.go

```go
package document

import (
	"context"

	"github.com/sirupsen/logrus"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
)

type GetDocumentOutput struct {
	ID        string `json:"id"`
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	Status    string `json:"status"`
	FileURL   string `json:"file_url"`
	CreatedAt string `json:"created_at"`
}

type GetDocumentUseCase struct {
	docRepo application.DocumentRepository
	logger  *logrus.Logger
}

func NewGetDocumentUseCase(
	docRepo application.DocumentRepository,
	logger *logrus.Logger,
) *GetDocumentUseCase {
	return &GetDocumentUseCase{
		docRepo: docRepo,
		logger:  logger,
	}
}

func (uc *GetDocumentUseCase) Execute(ctx context.Context, documentID, userID string) (*GetDocumentOutput, error) {
	uc.logger.WithFields(logrus.Fields{
		"document_id": documentID,
		"user_id":     userID,
		"action":      "get_document",
	}).Info("Fetching document")

	doc, err := uc.docRepo.GetByID(ctx, documentID)
	if err != nil {
		uc.logger.WithError(err).Warn("Document not found")
		return nil, appErrors.NewNotFoundError("Document")
	}

	if doc.UserID != userID {
		uc.logger.WithFields(logrus.Fields{
			"document_id": documentID,
			"user_id":     userID,
		}).Warn("Unauthorized access to document")
		return nil, appErrors.ErrForbidden
	}

	return &GetDocumentOutput{
		ID:       doc.ID,
		FileName: doc.FileName,
		FileSize: doc.FileSize,
		Status:   string(doc.Status),
		FileURL:  doc.FilePath,
		CreatedAt: doc.CreatedAt.String(),
	}, nil
}
```

---

## 14. internal/application/document/list.go

```go
package document

import (
	"context"

	"github.com/sirupsen/logrus"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
)

type ListDocumentsOutput struct {
	Documents []GetDocumentOutput `json:"documents"`
	Total     int                 `json:"total"`
}

type ListDocumentsUseCase struct {
	docRepo application.DocumentRepository
	logger  *logrus.Logger
}

func NewListDocumentsUseCase(
	docRepo application.DocumentRepository,
	logger *logrus.Logger,
) *ListDocumentsUseCase {
	return &ListDocumentsUseCase{
		docRepo: docRepo,
		logger:  logger,
	}
}

func (uc *ListDocumentsUseCase) Execute(ctx context.Context, userID string, limit, offset int) (*ListDocumentsOutput, error) {
	uc.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"limit":   limit,
		"offset":  offset,
		"action":  "list_documents",
	}).Info("Listing documents")

	docs, err := uc.docRepo.GetByUserID(ctx, userID, limit, offset)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to list documents")
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching documents", 500, err)
	}

	documents := make([]GetDocumentOutput, 0)
	for _, doc := range docs {
		documents = append(documents, GetDocumentOutput{
			ID:        doc.ID,
			FileName:  doc.FileName,
			FileSize:  doc.FileSize,
			Status:    string(doc.Status),
			FileURL:   doc.FilePath,
			CreatedAt: doc.CreatedAt.String(),
		})
	}

	return &ListDocumentsOutput{
		Documents: documents,
		Total:     len(documents),
	}, nil
}
```

---

## 15. internal/infrastructure/security/jwt.go

```go
package security

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/config"
)

type JWTProvider struct {
	config *config.JWTConfig
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func NewJWTProvider(cfg *config.JWTConfig) *JWTProvider {
	return &JWTProvider{config: cfg}
}

func (p *JWTProvider) GenerateToken(userID, email string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(p.config.ExpirationHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    p.config.IssuerName,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(p.config.Secret))
}

func (p *JWTProvider) GenerateRefreshToken(userID string) (string, error) {
	claims := RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(p.config.RefreshHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    p.config.IssuerName,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(p.config.Secret))
}

func (p *JWTProvider) ValidateToken(tokenString string) (userID string, email string, err error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(p.config.Secret), nil
	})

	if err != nil || !token.Valid {
		return "", "", fmt.Errorf("invalid token")
	}

	return claims.UserID, claims.Email, nil
}

func (p *JWTProvider) ValidateRefreshToken(tokenString string) (userID string, err error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(p.config.Secret), nil
	})

	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid refresh token")
	}

	return claims.UserID, nil
}
```

---

## 16. internal/infrastructure/security/password.go

```go
package security

import "golang.org/x/crypto/bcrypt"

type PasswordHasher struct {
	cost int
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		cost: bcrypt.DefaultCost,
	}
}

func (ph *PasswordHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), ph.cost)
	return string(hash), err
}

func (ph *PasswordHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
```

---

## 17. internal/infrastructure/persistence/mysql/connection.go

```go
package mysql

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/config"
)

func NewConnection(cfg config.DatabaseConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(cfg.MaxConn)
	db.SetMaxIdleConns(cfg.IdleConn)
	db.SetConnMaxLifetime(cfg.MaxLife)

	return db, nil
}

func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(36) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			phone VARCHAR(20),
			verified BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			INDEX idx_email (email),
			INDEX idx_deleted_at (deleted_at)
		)`,
		`CREATE TABLE IF NOT EXISTS documents (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL,
			file_name VARCHAR(255) NOT NULL,
			file_path VARCHAR(500) NOT NULL,
			file_size BIGINT NOT NULL,
			mime_type VARCHAR(50) NOT NULL,
			status VARCHAR(50) DEFAULT 'pending',
			metadata JSON,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_user_id (user_id),
			INDEX idx_status (status),
			INDEX idx_created_at (created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36),
			action VARCHAR(255) NOT NULL,
			resource VARCHAR(255),
			resource_id VARCHAR(36),
			changes JSON,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_user_id (user_id),
			INDEX idx_action (action),
			INDEX idx_created_at (created_at)
		)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return err
		}
	}

	return nil
}
```

---

## 18. internal/infrastructure/persistence/mysql/user_repository.go

```go
package mysql

import (
	"context"
	"database/sql"
	"time"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, email, password, name, phone, verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Email, user.Password, user.Name, user.Phone,
		user.Verified, user.CreatedAt, user.UpdatedAt,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error creating user", 500, err)
	}

	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, created_at, updated_at, deleted_at
		FROM users WHERE id = ? AND deleted_at IS NULL
	`

	var user domain.User
	var deletedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name, &user.Phone,
		&user.Verified, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, appErrors.NewNotFoundError("User")
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user", 500, err)
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, created_at, updated_at, deleted_at
		FROM users WHERE email = ? AND deleted_at IS NULL
	`

	var user domain.User
	var deletedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name, &user.Phone,
		&user.Verified, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user", 500, err)
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE users 
		SET email = ?, name = ?, phone = ?, verified = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query,
		user.Email, user.Name, user.Phone, user.Verified, time.Now(), user.ID,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error updating user", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error checking changes", 500, err)
	}

	if rows == 0 {
		return appErrors.NewNotFoundError("User")
	}

	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `UPDATE users SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error deleting user", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return appErrors.NewNotFoundError("User")
	}

	return nil
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, created_at, updated_at, deleted_at
		FROM users 
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listing users", 500, err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		var user domain.User
		var deletedAt sql.NullTime

		err := rows.Scan(
			&user.ID, &user.Email, &user.Password, &user.Name, &user.Phone,
			&user.Verified, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
		)
		if err != nil {
			return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error scanning user", 500, err)
		}

		if deletedAt.Valid {
			user.DeletedAt = &deletedAt.Time
		}

		users = append(users, &user)
	}

	return users, nil
}
```

---

## 19. internal/infrastructure/persistence/mysql/document_repository.go

```go
package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

type DocumentRepository struct {
	db *sql.DB
}

func NewDocumentRepository(db *sql.DB) *DocumentRepository {
	return &DocumentRepository{db: db}
}

func (r *DocumentRepository) Create(ctx context.Context, doc *domain.Document) error {
	metadataJSON, _ := json.Marshal(doc.Metadata)

	query := `
		INSERT INTO documents (id, user_id, file_name, file_path, file_size, mime_type, status, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		doc.ID, doc.UserID, doc.FileName, doc.FilePath, doc.FileSize,
		doc.MimeType, doc.Status, metadataJSON, doc.CreatedAt, doc.UpdatedAt,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error saving document", 500, err)
	}

	return nil
}

func (r *DocumentRepository) GetByID(ctx context.Context, id string) (*domain.Document, error) {
	query := `
		SELECT id, user_id, file_name, file_path, file_size, mime_type, status, metadata, created_at, updated_at
		FROM documents WHERE id = ?
	`

	var doc domain.Document
	var metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&doc.ID, &doc.UserID, &doc.FileName, &doc.FilePath, &doc.FileSize,
		&doc.MimeType, &doc.Status, &metadataJSON, &doc.CreatedAt, &doc.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, appErrors.NewNotFoundError("Document")
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching document", 500, err)
	}

	json.Unmarshal(metadataJSON, &doc.Metadata)
	return &doc, nil
}

func (r *DocumentRepository) GetByUserID(ctx context.Context, userID string, limit, offset int) ([]*domain.Document, error) {
	query := `
		SELECT id, user_id, file_name, file_path, file_size, mime_type, status, metadata, created_at, updated_at
		FROM documents 
		WHERE user_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listing documents", 500, err)
	}
	defer rows.Close()

	var documents []*domain.Document
	for rows.Next() {
		var doc domain.Document
		var metadataJSON []byte

		err := rows.Scan(
			&doc.ID, &doc.UserID, &doc.FileName, &doc.FilePath, &doc.FileSize,
			&doc.MimeType, &doc.Status, &metadataJSON, &doc.CreatedAt, &doc.UpdatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal(metadataJSON, &doc.Metadata)
		documents = append(documents, &doc)
	}

	return documents, nil
}

func (r *DocumentRepository) Update(ctx context.Context, doc *domain.Document) error {
	metadataJSON, _ := json.Marshal(doc.Metadata)

	query := `
		UPDATE documents 
		SET status = ?, metadata = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query, doc.Status, metadataJSON, time.Now(), doc.ID)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error updating document", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return appErrors.NewNotFoundError("Document")
	}

	return nil
}

func (r *DocumentRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM documents WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error deleting document", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return appErrors.NewNotFoundError("Document")
	}

	return nil
}
```

---

## 20. internal/infrastructure/persistence/storage/local_storage.go

```go
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

type LocalStorage struct {
	basePath string
	baseURL  string
}

func NewLocalStorage(basePath, baseURL string) *LocalStorage {
	os.MkdirAll(basePath, 0755)
	return &LocalStorage{
		basePath: basePath,
		baseURL:  baseURL,
	}
}

func (ls *LocalStorage) Save(ctx context.Context, fileName string, file io.Reader, size int64) (string, error) {
	fileName = filepath.Base(fileName)
	filePath := filepath.Join(ls.basePath, fileName)

	outFile, err := os.Create(filePath)
	if err != nil {
		return "", appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error creating file", 500, err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, file); err != nil {
		os.Remove(filePath)
		return "", appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error writing file", 500, err)
	}

	return filepath.Join("documents", fileName), nil
}

func (ls *LocalStorage) Delete(ctx context.Context, filePath string) error {
	fullPath := filepath.Join(ls.basePath, filePath)
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error deleting file", 500, err)
	}
	return nil
}

func (ls *LocalStorage) Get(ctx context.Context, filePath string) (io.ReadCloser, error) {
	fullPath := filepath.Join(ls.basePath, filePath)
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, appErrors.NewNotFoundError("File")
	}
	return file, nil
}

func (ls *LocalStorage) GetURL(filePath string) string {
	return fmt.Sprintf("%s/%s", ls.baseURL, filePath)
}
```

---

## 21. internal/infrastructure/http/handlers/auth_handler.go

```go
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application/auth"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

type AuthHandler struct {
	registerUC *auth.RegisterUseCase
	loginUC    *auth.LoginUseCase
	refreshUC  *auth.RefreshUseCase
	logger     *logrus.Logger
}

func NewAuthHandler(
	registerUC *auth.RegisterUseCase,
	loginUC *auth.LoginUseCase,
	refreshUC *auth.RefreshUseCase,
	logger *logrus.Logger,
) *AuthHandler {
	return &AuthHandler{
		registerUC: registerUC,
		loginUC:    loginUC,
		refreshUC:  refreshUC,
		logger:     logger,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req auth.RegisterInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Registration validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	output, err := h.registerUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusCreated, output)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req auth.LoginInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Login validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	output, err := h.loginUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req auth.RefreshInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Refresh validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	output, err := h.refreshUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}
```

---

## 22. internal/infrastructure/http/handlers/user_handler.go

```go
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

type UserHandler struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewUserHandler(
	userRepo application.UserRepository,
	logger *logrus.Logger,
) *UserHandler {
	return &UserHandler{
		userRepo: userRepo,
		logger:   logger,
	}
}

type UserOutput struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name    string `json:"name"`
	Phone   string `json:"phone"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
}

func (h *UserHandler) GetByID(c *gin.Context) {
	userID := c.Param("id")
	currentUserID := c.GetString("user_id")

	if userID != currentUserID {
		h.logger.WithFields(logrus.Fields{
			"user_id":         userID,
			"current_user_id": currentUserID,
		}).Warn("Unauthorized user access")
		ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", "Cannot access other user's profile")
		return
	}

	user, err := h.userRepo.GetByID(c.Request.Context(), userID)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, UserOutput{
		ID:        user.ID,
		Email:     user.Email,
		Name:    user.Name,
		Phone:   user.Phone,
		Verified:  user.Verified,
		CreatedAt: user.CreatedAt.String(),
	})
}

type UpdateUserInput struct {
	Name  string `json:"name"`
	Phone string `json:"phone"`
}

func (h *UserHandler) Update(c *gin.Context) {
	userID := c.Param("id")
	currentUserID := c.GetString("user_id")

	if userID != currentUserID {
		ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", "Cannot update other user's profile")
		return
	}

	var req UpdateUserInput
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Update validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	user, err := h.userRepo.GetByID(c.Request.Context(), userID)
	if err != nil {
		HandleError(c, err)
		return
	}

	user.Name = req.Name
	user.Phone = req.Phone

	if err := h.userRepo.Update(c.Request.Context(), user); err != nil {
		HandleError(c, err)
		return
	}

	h.logger.WithField("user_id", userID).Info("User updated successfully")

	SuccessResponse(c, http.StatusOK, UserOutput{
		ID:        user.ID,
		Email:     user.Email,
		Name:    user.Name,
		Phone:   user.Phone,
		Verified:  user.Verified,
		CreatedAt: user.CreatedAt.String(),
	})
}

func (h *UserHandler) Delete(c *gin.Context) {
	userID := c.Param("id")
	currentUserID := c.GetString("user_id")

	if userID != currentUserID {
		ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", "Cannot delete other user")
		return
	}

	if err := h.userRepo.Delete(c.Request.Context(), userID); err != nil {
		HandleError(c, err)
		return
	}

	h.logger.WithField("user_id", userID).Info("User deleted successfully")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User deleted successfully",
	})
}
```

---

## 23. internal/infrastructure/http/handlers/document_handler.go

```go
package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application/document"
)

type DocumentHandler struct {
	uploadUC *document.UploadDocumentUseCase
	getUC    *document.GetDocumentUseCase
	listUC   *document.ListDocumentsUseCase
	logger   *logrus.Logger
}

func NewDocumentHandler(
	uploadUC *document.UploadDocumentUseCase,
	getUC *document.GetDocumentUseCase,
	listUC *document.ListDocumentsUseCase,
	logger *logrus.Logger,
) *DocumentHandler {
	return &DocumentHandler{
		uploadUC: uploadUC,
		getUC:    getUC,
		listUC:   listUC,
		logger:   logger,
	}
}

func (h *DocumentHandler) Upload(c *gin.Context) {
	userID := c.GetString("user_id")

	file, header, err := c.Request.FormFile("document")
	if err != nil {
		h.logger.WithError(err).Warn("File form error")
		ErrorResponse(c, http.StatusBadRequest, "INVALID_FILE", "No file provided")
		return
	}
	defer file.Close()

	mimeType := header.Header.Get("Content-Type")
	if mimeType != "image/jpeg" && mimeType != "image/jpg" {
		ErrorResponse(c, http.StatusBadRequest, "INVALID_MIME", "Only JPG files allowed")
		return
	}

	input := document.UploadDocumentInput{
		UserID:   userID,
		FileName: header.Filename,
		File:     file,
		FileSize: header.Size,
		MimeType: mimeType,
	}

	output, err := h.uploadUC.Execute(c.Request.Context(), input)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusCreated, output)
}

func (h *DocumentHandler) Get(c *gin.Context) {
	documentID := c.Param("id")
	userID := c.GetString("user_id")

	output, err := h.getUC.Execute(c.Request.Context(), documentID, userID)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *DocumentHandler) List(c *gin.Context) {
	userID := c.GetString("user_id")

	limitStr := c.DefaultQuery("limit", "10")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	output, err := h.listUC.Execute(c.Request.Context(), userID, limit, offset)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}
```

---

## 24. internal/infrastructure/http/handlers/response.go

```go
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

type SuccessResponseBody struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

type ErrorResponseBody struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func SuccessResponse(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, SuccessResponseBody{
		Success: true,
		Data:    data,
	})
}

func ErrorResponse(c *gin.Context, statusCode int, code, message string) {
	c.JSON(statusCode, ErrorResponseBody{
		Success: false,
		Code:    code,
		Message: message,
	})
}

func HandleError(c *gin.Context, err error) {
	if appErr, ok := err.(*appErrors.AppError); ok {
		c.JSON(appErr.StatusCode, ErrorResponseBody{
			Success: false,
			Code:    appErr.Code,
			Message: appErr.Message,
		})
		return
	}

	c.JSON(http.StatusInternalServerError, ErrorResponseBody{
		Success: false,
		Code:    "INTERNAL_ERROR",
		Message: "Internal server error",
	})
}
```

---

## 25. internal/infrastructure/http/middleware/auth.go

```go
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
)

func AuthMiddleware(tokenProvider application.TokenProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "NO_AUTH",
				"message": "Authorization header required",
			})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "INVALID_AUTH",
				"message": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		userID, email, err := tokenProvider.ValidateToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "INVALID_TOKEN",
				"message": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Set("email", email)
		c.Next()
	}
}
```

---

## 26. internal/infrastructure/http/middleware/cors.go

```go
package middleware

import "github.com/gin-gonic/gin"

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
```

---

## 27. internal/infrastructure/http/middleware/logging.go

```go
package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func LoggingMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		c.Next()

		duration := time.Since(startTime)
		statusCode := c.Writer.Status()

		logger.WithFields(logrus.Fields{
			"method":     c.Request.Method,
			"path":       c.Request.RequestURI,
			"status":     statusCode,
			"duration":   duration.Milliseconds(),
			"user_id":    c.GetString("user_id"),
			"ip":         c.ClientIP(),
		}).Info("HTTP Request")
	}
}
```

---

## 28. internal/infrastructure/http/middleware/error_handling.go

```go
package middleware

import (
	"github.com/gin-gonic/gin"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
)

func ErrorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		for _, err := range c.Errors {
			if appErr, ok := err.Err.(*appErrors.AppError); ok {
				c.JSON(appErr.StatusCode, gin.H{
					"success": false,
					"code":    appErr.Code,
					"message": appErr.Message,
				})
			}
		}
	}
}
```

---

## 29. internal/infrastructure/http/routes.go

```go
package http

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/config"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http/middleware"
)

func SetupRoutes(router *gin.Engine, deps *config.Dependencies, logger *logrus.Logger) {
	// Public routes
	api := router.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", deps.AuthHandler.Register)
			auth.POST("/login", deps.AuthHandler.Login)
			auth.POST("/refresh", deps.AuthHandler.Refresh)
		}
	}

	// Protected routes
	protected := api.Group("")
	protected.Use(middleware.AuthMiddleware(deps.TokenProvider))
	{
		users := protected.Group("/users")
		{
			users.GET("/:id", deps.UserHandler.GetByID)
			users.PUT("/:id", deps.UserHandler.Update)
			users.DELETE("/:id", deps.UserHandler.Delete)
		}

		documents := protected.Group("/documents")
		{
			documents.POST("/upload", deps.DocumentHandler.Upload)
			documents.GET("", deps.DocumentHandler.List)
			documents.GET("/:id", deps.DocumentHandler.Get)
		}
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	logger.Info("✅ Routes configured")
}
```

---

## 30. .env.example

```env
# Environment
ENVIRONMENT=development
PORT=8080
BASE_URL=http://localhost:8080

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=password
DB_NAME=identity_db
DB_MAX_CONN=25
DB_IDLE_CONN=5

# JWT
JWT_SECRET=your-super-secret-jwt-key-min-32-chars-long-please!!!
JWT_EXPIRATION=24
JWT_REFRESH=168

# Storage
STORAGE_PATH=./uploads
MAX_FILE_SIZE=5242880
```

---

## 31. Makefile

```makefile
.PHONY: help install run build test lint clean

help:
	@echo "Commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make run        - Run application"
	@echo "  make build      - Build binary"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linter"
	@echo "  make clean      - Clean build"

install:
	go mod download
	go mod tidy

run:
	go run ./cmd/main.go

build:
	go build -o sumabitcoin ./cmd/main.go

test:
	go test ./... -v -cover

lint:
	golangci-lint run ./...

clean:
	rm -f sumabitcoin
	go clean
	rm -rf uploads/*
```

---

## 32. README.md

```markdown
# Identity Verification API - Clean Architecture Backend

Backend en Go con Clean Architecture para verificación de documentos de identidad.

## Estructura del Proyecto

```
.
├── cmd/
│   └── main.go
├── internal/
│   ├── application/       # Casos de uso
│   ├── config/           # Configuración
│   ├── domain/           # Entidades
│   └── infrastructure/   # Implementaciones
├── pkg/
│   └── errors/          # Errores personalizados
├── go.mod
├── go.sum
├── Makefile
├── .env.example
└── README.md
```

## Instalación

### Requisitos
- Go 1.21+
- MySQL 8.0+

### Pasos

1. **Clonar y configurar**
```bash
git clone <repositorio>
cd sumabitcoin-backend
cp .env.example .env
```

2. **Instalar dependencias**
```bash
make install
```

3. **Configurar BD**
```bash
# Crear base de datos MySQL
mysql -u root -p
> CREATE DATABASE sumabitcoin;
```

4. **Ejecutar**
```bash
make run
```

## API Endpoints

### Autenticación

**Registro**
```bash
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "name": "Juan Pérez",
  "phone": "+573001234567"
}
```

**Login**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" -d '{ "email": "user@example.com",  "password": "SecurePass123!" }'
```

**Refresh Token**
curl -X POST http://localhost:8080/api/v1/auth/refresh -H "Content-Type: application/json" -d '{ "refresh_token":  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNDAyZTU5Y2ItY2ZlMC00YzhhLTg2MzQtMzYxNGQyOWNmNDUwIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaXNzIjoiaWRlbnRpdHktYXBpIiwiZXhwIjoxNzY1MDYzNTMyLCJpYXQiOjE3NjQ5NzcxMzJ9.ToQt6njH1bIjMukpJDld-TCYd-z3uB3KAwlNaQmIZPI" }'
```bash
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "your-refresh-token"
}
```

### Usuarios (Protegidos)

**Obtener perfil**
curl -v -X GET http://localhost:8080/api/v1/users/402e59cb-cfe0-4c8a-8634-3614d29cf450   -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNDAyZTU5Y2ItY2ZlMC00YzhhLTg2MzQtMzYxNGQyOWNmNDUwIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaXNzIjoiaWRlbnRpdHktYXBpIiwiZXhwIjoxNzY1MDY1NDMzLCJpYXQiOjE3NjQ5NzkwMzN9.Vl-56SfZcrrmRR3ztiQPrq0KnIDN_7irH8DIWVLIfFk"
```bash
GET /api/v1/users/:id
Authorization: Bearer <token>
```

**Actualizar perfil**
```bash
PUT /api/v1/users/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Nuevo Name",
  "phone": "+573009876543"
}
```

**Eliminar cuenta**
```bash
DELETE /api/v1/users/:id
Authorization: Bearer <token>
```

### Documentos (Protegidos)

**Subir documento**
```bash
POST /api/v1/documents/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

Form Data:
- document: <archivo.jpg>
```

**Listar documentos**
```bash
GET /api/v1/documents?limit=10&offset=0
Authorization: Bearer <token>
```

**Obtener documento**
```bash
GET /api/v1/documents/:id
Authorization: Bearer <token>
```

## Testing con cURL

```bash
# Health check
curl http://localhost:8080/health

# Registrarse
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "name": "Test User",
    "phone": "+573001234567"
  }'

# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }' | jq -r '.data.token')

# Subir documento
curl -X POST http://localhost:8080/api/v1/documents/upload -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMDEwMzhmMGItYWI1NC00M2U1LTgxNzYtOTJhZjNiMzlmOGNkIiwiZW1haWwiOiJ1c2VyMUBleGFtcGxlLmNvbSIsImlzcyI6ImlkZW50aXR5LWFwaSIsImV4cCI6MTc2NTE2MDQxOCwiaWF0IjoxNzY1MDc0MDE4fQ.7te_8oFfTsCqvXQ4Kk6_76o4WTBcoZZs1Sfi-KEtd7A" -F "document=@a.jpeg"

curl -X POST http://localhost:8080/api/v1/documents/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "document=@/ruta/documento.jpg"

# Listar documentos
curl -X GET "http://localhost:8080/api/v1/documents?limit=10&offset=0" \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMDEwMzhmMGItYWI1NC00M2U1LTgxNzYtOTJhZjNiMzlmOGNkIiwiZW1haWwiOiJ1c2VyMUBleGFtcGxlLmNvbSIsImlzcyI6ImlkZW50aXR5LWFwaSIsImV4cCI6MTc2NTE2MDQxOCwiaWF0IjoxNzY1MDc0MDE4fQ.7te_8oFfTsCqvXQ4Kk6_76o4WTBcoZZs1Sfi-KEtd7A"
```

## Características

✅ Clean Architecture
✅ JWT con Refresh Tokens
✅ Validación multicapa
✅ Error handling robusto
✅ Logging estructurado
✅ Almacenamiento local de archivos
✅ Soft deletes
✅ CORS habilitado

## Variables de Entorno

```env
ENVIRONMENT=development          # development, production
PORT=8080
BASE_URL=http://localhost:8080

DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=password
DB_NAME=identity_db

JWT_SECRET=secret-key-min-32-chars
JWT_EXPIRATION=24                # horas
JWT_REFRESH=168                  # horas (7 días)

STORAGE_PATH=./uploads
MAX_FILE_SIZE=5242880            # 5MB en bytes
```

## Desarrollo

```bash
# Ejecutar tests
make test

# Linting
make lint

# Compilar
make build

# Ejecutar binario compilado
./sumabitcoin
```

## Notas

- Los archivos se guardan en `./uploads`
- Los logs se muestran en stdout
- Las contraseñas se hashean con bcrypt
- Los tokens JWT expiran en 24 horas
- Los refresh tokens expiran en 7 días

---

Creado con ❤️ usando Go y Clean Architecture
```

---

## Instrucciones Finales

1. **Crear estructura de carpetas:**
```bash
mkdir -p server/{cmd,internal,pkg}
mkdir -p server/internal/{application,config,domain,infrastructure}
mkdir -p server/internal/application/{auth,document}
mkdir -p server/internal/infrastructure/{http,persistence,security}
mkdir -p server/internal/infrastructure/http/{handlers,middleware}
mkdir -p server/internal/infrastructure/persistence/{mysql,storage}
mkdir -p server/pkg/{errors,logger,validator}
mkdir -p server/uploads
```

2. **Copiar todos los archivos a sus ubicaciones correspondientes**

3. **Instalar dependencias:**
```bash
go mod download
go mod tidy
```

4. **Configurar .env:**
```bash
cp .env.example .env
# Editar .env con tus datos
```

5. **Ejecutar:**
```bash
go run ./cmd/main.go
```


package config

import (
	"time"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	authUC "github.com/awakeelectronik/sumabitcoin-backend/internal/application/auth"
	docUC "github.com/awakeelectronik/sumabitcoin-backend/internal/application/document"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http/handlers"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/persistence/mysql"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/persistence/storage"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/security"
	"github.com/sirupsen/logrus"
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
	VerificationService application.VerificationService

	// Handlers
	AuthHandler     *handlers.AuthHandler
	UserHandler     *handlers.UserHandler
	DocumentHandler *handlers.DocumentHandler

	// Logger
	Logger *logrus.Logger
}

func BuildDependencies(cfg *Config, logger *logrus.Logger) (*Dependencies, error) {
	// ========== DATABASE CONNECTION ==========
	// Crea la conexión BD con parámetros sueltos
	db, err := mysql.NewConnection(
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.MaxConn,
		cfg.Database.IdleConn,
		time.Duration(cfg.Database.MaxLife)*time.Second, // Convierte a time.Duration
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to database")
		return nil, err
	}

	// Ejecuta las migraciones
	if err = mysql.RunMigrations(db); err != nil {
		logger.WithError(err).Fatal("Failed to run migrations")
		return nil, err
	}

	logger.Info("✅ Database connected and migrated")

	// ========== REPOSITORIES ==========
	userRepo := mysql.NewUserRepository(db)
	documentRepo := mysql.NewDocumentRepository(db)

	// ========== STORAGE ==========
	fileStorage := storage.NewLocalStorage(cfg.Storage.LocalPath, cfg.Server.BaseURL)

	// ========== SECURITY ==========
	passwordHasher := security.NewPasswordHasher()
	tokenProvider := security.NewJWTProvider(
		cfg.JWT.Secret,
		cfg.JWT.ExpirationHours,
		cfg.JWT.RefreshHours,
		cfg.JWT.IssuerName,
	)
	verificationService := security.NewVerificationService(logger)

	// ========== USE CASES ==========
	registerUC := authUC.NewRegisterUseCase(userRepo, passwordHasher, verificationService, logger)
	loginUC := authUC.NewLoginUseCase(userRepo, passwordHasher, tokenProvider, logger)
	refreshUC := authUC.NewRefreshUseCase(tokenProvider, logger)
	checkAvailabilityUC := authUC.NewCheckAvailabilityUseCase(userRepo, logger)
	verifyCodeUC := authUC.NewVerifyCodeUseCase(userRepo, tokenProvider, verificationService, logger)

	uploadDocUC := docUC.NewUploadDocumentUseCase(documentRepo, fileStorage, cfg.Storage.MaxFileSize, logger)
	listDocUC := docUC.NewListDocumentsUseCase(documentRepo, logger)

	// ========== HANDLERS ==========
	authHandler := handlers.NewAuthHandler(registerUC, loginUC, refreshUC, checkAvailabilityUC, verifyCodeUC, logger)
	userHandler := handlers.NewUserHandler(userRepo, logger)
	documentHandler := handlers.NewDocumentHandlerWithList(uploadDocUC, listDocUC, logger)

	// ========== RETURN DEPENDENCIES ==========
	return &Dependencies{
		UserRepo:        userRepo,
		DocumentRepo:    documentRepo,
		FileStorage:     fileStorage,
		PasswordHasher:  passwordHasher,
		TokenProvider:   tokenProvider,
		VerificationService: verificationService,
		AuthHandler:     authHandler,
		UserHandler:     userHandler,
		DocumentHandler: documentHandler,
		Logger:          logger,
	}, nil
}

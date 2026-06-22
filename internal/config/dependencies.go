package config

import (
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	authUC "github.com/awakeelectronik/generic-backend-go/internal/application/auth"
	docUC "github.com/awakeelectronik/generic-backend-go/internal/application/document"
	userUC "github.com/awakeelectronik/generic-backend-go/internal/application/user"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/email"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/http/handlers"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/persistence/mysql"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/persistence/storage"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/security"
	"github.com/sirupsen/logrus"
)

type Dependencies struct {
	// Repositories
	UserRepo         application.UserRepository
	DocumentRepo     application.DocumentRepository
	ReferralCodeRepo application.ReferralCodeRepository
	UserReferralRepo application.UserReferralRepository

	// Storage
	FileStorage application.FileStorage

	// Security
	PasswordHasher      application.PasswordHasher
	TokenProvider       application.TokenProvider
	VerificationService application.VerificationService
	AdminChecker        application.AdminChecker

	// External services
	EmailSender application.EmailSender

	// Persistence helpers
	TxRunner application.TransactionRunner

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

	// Optional admin seed: only when all three envs (email, phone, password_hash)
	// are configured. No hardcoded fallback password.
	if cfg.Admin.Email != "" && cfg.Admin.Phone != "" && cfg.Admin.PasswordHash != "" {
		created, err := mysql.SeedAdminUser(db, cfg.Admin.Email, cfg.Admin.Phone, cfg.Admin.Name, cfg.Admin.PasswordHash)
		if err != nil {
			logger.WithError(err).Warn("Failed to seed admin user")
		} else if created {
			logger.WithField("email", cfg.Admin.Email).Info("✅ Admin user seeded")
		}
	} else {
		logger.Warn("Admin not seeded: set ADMIN_EMAIL, ADMIN_PHONE and ADMIN_PASSWORD_HASH to enable")
	}

	// ========== REPOSITORIES ==========
	userRepo := mysql.NewUserRepository(db)
	documentRepo := mysql.NewDocumentRepository(db)
	referralCodeRepo := mysql.NewReferralCodeRepository(db)
	userReferralRepo := mysql.NewUserReferralRepository(db)

	// ========== PERSISTENCE HELPERS ==========
	txRunner := mysql.NewTransactionRunner(db)

	// ========== STORAGE ==========
	fileStorage := storage.NewLocalStorage(cfg.Storage.LocalPath, cfg.Server.BaseURL)

	// ========== EMAIL ==========
	var emailSender application.EmailSender
	if cfg.Email.Noop {
		emailSender = email.NewNoopSender()
	} else {
		emailSender = email.NewSMTPSender(cfg.Email.From, cfg.Brand.AppName, cfg.Email.Host, cfg.Email.Port)
	}

	// ========== SECURITY ==========
	passwordHasher := security.NewPasswordHasher()
	tokenProvider := security.NewJWTProvider(
		cfg.JWT.Secret,
		cfg.JWT.ExpirationHours,
		cfg.JWT.RefreshHours,
		cfg.JWT.IssuerName,
	)
	verificationService := security.NewVerificationService(emailSender, cfg.Brand.AppName, cfg.Brand.BrandHex, logger)
	adminChecker := security.NewAdminChecker(cfg.Admin.Email, cfg.Admin.Phone)

	// ========== USE CASES ==========
	registerUC := authUC.NewRegisterUseCase(userRepo, referralCodeRepo, userReferralRepo, txRunner, passwordHasher, verificationService, cfg.Auth.RequireReferral, logger)
	checkReferralUC := authUC.NewCheckReferralUseCase(userRepo, referralCodeRepo, userReferralRepo, logger)
	loginUC := authUC.NewLoginUseCase(userRepo, passwordHasher, tokenProvider, logger)
	refreshUC := authUC.NewRefreshUseCase(userRepo, tokenProvider, logger)
	checkAvailabilityUC := authUC.NewCheckAvailabilityUseCase(userRepo, logger)
	verifyCodeUC := authUC.NewVerifyCodeUseCase(userRepo, tokenProvider, verificationService, logger)
	resendVerificationUC := authUC.NewResendVerificationUseCase(userRepo, passwordHasher, verificationService, logger)
	forgotPasswordUC := authUC.NewForgotPasswordUseCase(userRepo, verificationService, logger)
	resetPasswordUC := authUC.NewResetPasswordUseCase(userRepo, passwordHasher, verificationService, tokenProvider, logger)
	changePasswordUC := authUC.NewChangePasswordUseCase(userRepo, passwordHasher, tokenProvider, logger)

	uploadDocUC := docUC.NewUploadDocumentUseCase(documentRepo, fileStorage, cfg.Storage.MaxFileSize, cfg.Storage.AllowedMimes, logger)
	listDocUC := docUC.NewListDocumentsUseCase(documentRepo, logger)
	downloadDocUC := docUC.NewDownloadDocumentUseCase(documentRepo, fileStorage, logger)

	listUsersUC := userUC.NewListUsersUseCase(userRepo, logger)
	getUserUC := userUC.NewGetUserUseCase(userRepo, logger)
	updateUserUC := userUC.NewUpdateUserUseCase(userRepo, logger)
	deleteUserUC := userUC.NewDeleteUserUseCase(userRepo, logger)

	// ========== HANDLERS ==========
	authHandler := handlers.NewAuthHandler(
		registerUC,
		loginUC,
		refreshUC,
		checkAvailabilityUC,
		checkReferralUC,
		verifyCodeUC,
		resendVerificationUC,
		forgotPasswordUC,
		resetPasswordUC,
		changePasswordUC,
		logger,
	)
	userHandler := handlers.NewUserHandler(listUsersUC, getUserUC, updateUserUC, deleteUserUC, logger)
	// Holgura de 1 MiB sobre el tamaño máx de archivo para el sobre multipart
	// (boundary, headers de parte, otros campos del form).
	maxUploadBytes := cfg.Storage.MaxFileSize + (1 << 20)
	documentHandler := handlers.NewDocumentHandler(uploadDocUC, listDocUC, downloadDocUC, maxUploadBytes, logger)

	// ========== RETURN DEPENDENCIES ==========
	return &Dependencies{
		UserRepo:            userRepo,
		DocumentRepo:        documentRepo,
		ReferralCodeRepo:    referralCodeRepo,
		UserReferralRepo:    userReferralRepo,
		FileStorage:         fileStorage,
		PasswordHasher:      passwordHasher,
		TokenProvider:       tokenProvider,
		VerificationService: verificationService,
		AdminChecker:        adminChecker,
		EmailSender:         emailSender,
		TxRunner:            txRunner,
		AuthHandler:         authHandler,
		UserHandler:         userHandler,
		DocumentHandler:     documentHandler,
		Logger:              logger,
	}, nil
}

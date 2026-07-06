package config

import (
	"github.com/awakeelectronik/generic-backend-go/internal/application"
	authUC "github.com/awakeelectronik/generic-backend-go/internal/application/auth"
	docUC "github.com/awakeelectronik/generic-backend-go/internal/application/document"
	userUC "github.com/awakeelectronik/generic-backend-go/internal/application/user"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/cache"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/email"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/http/handlers"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/http/middleware"
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

	// Audit
	AuditLogger application.AuditLogger

	// Handlers
	AuthHandler     *handlers.AuthHandler
	UserHandler     *handlers.UserHandler
	DocumentHandler *handlers.DocumentHandler
	AuditHandler    *handlers.AuditHandler

	// Logger
	Logger *logrus.Logger
}

func BuildDependencies(cfg *Config, logger *logrus.Logger) (*Dependencies, error) {
	// ========== DATABASE CONNECTION ==========
	// Crea la conexión BD con parámetros sueltos
	// MaxLife ya es time.Duration: multiplicarlo otra vez por time.Second lo
	// desbordaba (int64) y dejaba conexiones prácticamente sin rotación.
	db, err := mysql.NewConnection(
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.TLSMode,
		cfg.Database.MaxConn,
		cfg.Database.IdleConn,
		cfg.Database.MaxLife,
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
	var fileStorage application.FileStorage = storage.NewLocalStorage(cfg.Storage.LocalPath, cfg.Server.BaseURL)
	// Cifrado at-rest opt-in: con STORAGE_ENC_KEY los archivos se guardan
	// sellados con AES-256-GCM; los previos (sin cifrar) se siguen sirviendo.
	if len(cfg.Storage.EncKey) > 0 {
		encStorage, err := storage.NewEncryptedStorage(fileStorage, cfg.Storage.EncKey)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize storage encryption")
			return nil, err
		}
		fileStorage = encStorage
		logger.Info("✅ Storage encryption at rest enabled (AES-256-GCM)")
	}

	// ========== EMAIL ==========
	var emailSender application.EmailSender
	if cfg.Email.Noop {
		emailSender = email.NewNoopSender()
	} else {
		emailSender = email.NewSMTPSender(cfg.Email.From, cfg.Brand.AppName, cfg.Email.Host, cfg.Email.Port)
	}

	// ========== SECURITY ==========
	passwordHasher := security.NewPasswordHasherWithCost(cfg.Auth.BcryptCost)
	tokenProvider := security.NewJWTProviderWithPrevious(
		cfg.JWT.Secret,
		cfg.JWT.PreviousSecret,
		cfg.JWT.ExpirationHours,
		cfg.JWT.RefreshHours,
		cfg.JWT.IssuerName,
	)
	adminChecker := security.NewAdminChecker(cfg.Admin.Email, cfg.Admin.Phone)

	// ========== SHARED STORE: opt-in Redis ==========
	// Sin REDIS_URL, el rate-limiter y los códigos de verificación viven en
	// memoria del proceso: válido para una sola instancia, pero se pierden al
	// reiniciar y no se comparten entre réplicas. Con Redis, ambos pasan a un
	// store compartido y restart-safe (necesario al escalar horizontalmente).
	var verificationService *security.VerificationService
	var loginThrottle application.LoginThrottle
	if cfg.Redis.URL != "" {
		redisClient, err := cache.NewClient(cfg.Redis.URL)
		if err != nil {
			logger.WithError(err).Fatal("Failed to connect to Redis")
			return nil, err
		}
		logger.Info("✅ Redis connected: rate limiting and verification codes are shared and restart-safe")
		verificationService = security.NewVerificationServiceWithStore(
			security.NewRedisVerificationStore(redisClient, security.DefaultVerificationPolicy()),
			emailSender, cfg.Brand.AppName, cfg.Brand.BrandHex, logger,
		)
		middleware.SetRateStore(middleware.NewRedisRateStore(redisClient, cfg.Server.RateLimitFailClosed, logger))
		loginThrottle = security.NewRedisLoginThrottle(redisClient, security.DefaultLoginThrottlePolicy(), logger)
	} else {
		logger.Warn("REDIS_URL not set: rate limiting and verification codes are in-memory (single-instance, lost on restart)")
		verificationService = security.NewVerificationService(emailSender, cfg.Brand.AppName, cfg.Brand.BrandHex, logger)
		loginThrottle = security.NewMemoryLoginThrottle(security.DefaultLoginThrottlePolicy())
	}
	// Volcado de códigos a consola/logs SOLO fuera de producción: en producción
	// un código en los logs equivale a la contraseña del usuario.
	if cfg.Server.Environment != "production" {
		verificationService.EnableDevCodeLogging()
	}

	// ========== AUDIT ==========
	auditLogger := mysql.NewAuditRepository(db)

	// ========== USE CASES ==========
	registerUC := authUC.NewRegisterUseCase(userRepo, referralCodeRepo, userReferralRepo, txRunner, passwordHasher, verificationService, cfg.Auth.RequireReferral, logger)
	checkReferralUC := authUC.NewCheckReferralUseCase(userRepo, referralCodeRepo, userReferralRepo, logger)
	loginUC := authUC.NewLoginUseCase(userRepo, passwordHasher, tokenProvider, loginThrottle, logger)
	logoutUC := authUC.NewLogoutUseCase(userRepo, logger)
	refreshUC := authUC.NewRefreshUseCase(userRepo, tokenProvider, logger)
	checkAvailabilityUC := authUC.NewCheckAvailabilityUseCase(userRepo, logger)
	verifyCodeUC := authUC.NewVerifyCodeUseCase(userRepo, tokenProvider, verificationService, logger)
	resendVerificationUC := authUC.NewResendVerificationUseCase(userRepo, passwordHasher, verificationService, logger)
	forgotPasswordUC := authUC.NewForgotPasswordUseCase(userRepo, verificationService, logger)
	resetPasswordUC := authUC.NewResetPasswordUseCase(userRepo, passwordHasher, verificationService, tokenProvider, logger)
	changePasswordUC := authUC.NewChangePasswordUseCase(userRepo, passwordHasher, tokenProvider, logger)

	uploadDocUC := docUC.NewUploadDocumentUseCase(documentRepo, fileStorage, cfg.Storage.MaxFileSize, cfg.Storage.MaxDocsPerUser, cfg.Storage.AllowedMimes, logger)
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
		logoutUC,
		logger,
	)
	auditHandler := handlers.NewAuditHandler(auditLogger, logger)
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
		AuditLogger:         auditLogger,
		AuthHandler:         authHandler,
		UserHandler:         userHandler,
		DocumentHandler:     documentHandler,
		AuditHandler:        auditHandler,
		Logger:              logger,
	}, nil
}

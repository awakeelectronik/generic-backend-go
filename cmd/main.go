package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/config"
	apphttp "github.com/awakeelectronik/generic-backend-go/internal/infrastructure/http"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/http/middleware"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
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

	// BuildDependencies crea la BD automáticamente
	deps, err := config.BuildDependencies(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to build dependencies: %v", err)
	}

	// Setup router
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// gin.New + Recovery explícito: Recovery convierte panics en 500 (sin él un
	// panic tumba la conexión); se omite el logger de Gin porque ya existe el
	// LoggingMiddleware estructurado (evita log doble por petición).
	router := gin.New()
	router.Use(gin.Recovery())

	// Trusted proxies: por defecto Gin confía en TODOS los proxies, lo que deja
	// que un cliente falsifique X-Forwarded-For y evada el rate-limit por IP.
	// Restringimos a la allowlist (vacía = no se confía en ninguno, se usa la IP
	// del socket directo).
	if err := router.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
		logger.Fatalf("Invalid TRUSTED_PROXIES: %v", err)
	}

	// Middleware
	router.Use(middleware.SecurityHeadersMiddleware(cfg.Server.HSTSEnabled))
	router.Use(middleware.CORSMiddleware(cfg.Server.AllowedOrigins))
	// Tope global de body para rutas JSON; /documents/upload queda exenta porque
	// impone su propio límite (tamaño máx de archivo + sobre multipart).
	router.Use(middleware.BodySizeLimitMiddleware(cfg.Server.MaxBodyBytes, "/api/v1/documents/upload"))
	router.Use(middleware.LoggingMiddleware(logger))
	router.Use(middleware.ErrorHandlingMiddleware())

	// Routes
	apphttp.SetupRoutes(router, deps, logger)

	// HTTP server con timeouts explícitos: sin ellos, una conexión lenta
	// (Slowloris) puede mantener un descriptor abierto indefinidamente.
	// WriteTimeout holgado para no cortar descargas de archivos (hasta ~5MB).
	srv := &http.Server{
		Addr:              ":" + cfg.Server.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Arrancamos en goroutine para poder escuchar señales de apagado.
	go func() {
		logger.Infof("🚀 Server starting on http://localhost:%s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("Error starting server: %v", err)
		}
	}()

	// Graceful shutdown: ante SIGINT/SIGTERM dejamos terminar las peticiones en
	// vuelo antes de cerrar, en vez de cortarlas en seco al desplegar.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}
	logger.Info("Server exited gracefully")
}

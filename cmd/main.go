package main

import (
	"log"
	"os"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/config"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http/middleware"
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

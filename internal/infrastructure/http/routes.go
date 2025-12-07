package http

import (
	"github.com/awakeelectronik/sumabitcoin-backend/internal/config"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http/middleware"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
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

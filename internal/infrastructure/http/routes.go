package http

import (
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/config"
	"github.com/awakeelectronik/generic-backend-go/internal/infrastructure/http/middleware"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func SetupRoutes(router *gin.Engine, deps *config.Dependencies, logger *logrus.Logger) {
	// Public routes
	api := router.Group("/api/v1")

	// Trail de auditoría para TODA mutación bajo /api/v1 (incluye intentos
	// rechazados por auth/rate-limit: el status queda registrado).
	api.Use(middleware.AuditMiddleware(deps.AuditLogger, logger))
	{
		auth := api.Group("/auth")
		{
			// Brute-force guards on credential endpoints (30/min/IP).
			auth.POST("/register",
				middleware.RateLimitMiddleware(30, time.Minute),
				deps.AuthHandler.Register)
			auth.POST("/login",
				middleware.RateLimitMiddleware(30, time.Minute),
				deps.AuthHandler.Login)
			auth.POST("/refresh",
				middleware.RateLimitMiddleware(30, time.Minute),
				deps.AuthHandler.Refresh)

			auth.POST("/check-availability",
				middleware.RateLimitMiddleware(10, time.Minute),
				deps.AuthHandler.CheckAvailability)

			auth.POST("/check-referral",
				middleware.RateLimitMiddleware(10, time.Minute),
				deps.AuthHandler.CheckReferral)

			auth.POST("/verify-code",
				middleware.RateLimitMiddleware(20, time.Minute),
				deps.AuthHandler.VerifyCode)

			auth.POST("/resend-verification-code",
				middleware.RateLimitMiddleware(10, time.Minute),
				deps.AuthHandler.ResendVerificationCode)

			auth.POST("/forgot-password",
				middleware.RateLimitMiddleware(5, time.Minute),
				deps.AuthHandler.ForgotPassword)
			auth.POST("/reset-password",
				middleware.RateLimitMiddleware(5, time.Minute),
				deps.AuthHandler.ResetPassword)
		}
	}

	// Protected auth routes (require valid token)
	protectedAuth := api.Group("/auth")
	protectedAuth.Use(middleware.AuthMiddleware(deps.TokenProvider, deps.UserRepo))
	{
		protectedAuth.POST("/change-password", deps.AuthHandler.ChangePassword)
		// Logout con revocación real: sube token_version, todos los tokens
		// (access y refresh) emitidos hasta ahora quedan inválidos.
		protectedAuth.POST("/logout", deps.AuthHandler.Logout)
	}

	// Protected routes
	protected := api.Group("")
	protected.Use(middleware.AuthMiddleware(deps.TokenProvider, deps.UserRepo))
	// Límite por USUARIO además del límite por IP: acota una cuenta abusiva
	// aunque rote IPs, y no castiga a cuentas legítimas detrás del mismo NAT.
	protected.Use(middleware.RateLimitByUserMiddleware(240, time.Minute))
	{
		users := protected.Group("/users")
		{
			users.GET("/profile", deps.UserHandler.GetProfile)
			users.GET("/:id", deps.UserHandler.GetByID)
			users.PUT("/:id", deps.UserHandler.Update)
			users.DELETE("/:id", deps.UserHandler.Delete)
		}

		documents := protected.Group("/documents")
		{
			// Upload escribe a disco: limitarlo evita que una sola cuenta/IP
			// llene el volumen a ráfagas (el resto de rutas GET son baratas).
			documents.POST("/upload",
				middleware.RateLimitMiddleware(20, time.Minute),
				deps.DocumentHandler.Upload)
			documents.GET("", deps.DocumentHandler.List)
			documents.GET("/:id/download", deps.DocumentHandler.Download)
		}

		// Admin routes — gated by AdminChecker (role-based, legacy fallback).
		admin := protected.Group("/admin")
		admin.Use(middleware.AdminMiddleware(deps.AdminChecker))
		{
			admin.GET("/users", deps.UserHandler.List)
			admin.GET("/audit-logs", deps.AuditHandler.List)
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

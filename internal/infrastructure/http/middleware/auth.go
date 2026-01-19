package middleware

import (
	"net/http"
	"strings"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(tokenProvider application.TokenProvider, userRepo application.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "NO_AUTH",
				"message": "Se requiere el header Authorization",
			})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "INVALID_AUTH",
				"message": "Formato inválido del header Authorization",
			})
			c.Abort()
			return
		}

		userID, email, err := tokenProvider.ValidateToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "INVALID_TOKEN",
				"message": "Token inválido o expirado",
			})
			c.Abort()
			return
		}

		// Check if user is verified
		user, err := userRepo.GetByID(c.Request.Context(), userID)
		if err != nil || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "USER_NOT_FOUND",
				"message": "Usuario no encontrado",
			})
			c.Abort()
			return
		}

		if !user.Verified {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"code":    "UNVERIFIED_USER",
				"message": "Usuario no verificado. Complete la verificación primero.",
			})
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Set("email", email)
		c.Next()
	}
}

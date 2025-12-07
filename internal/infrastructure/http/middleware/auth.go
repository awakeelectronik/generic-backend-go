package middleware

import (
	"net/http"
	"strings"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/gin-gonic/gin"
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

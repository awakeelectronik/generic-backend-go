package middleware

import (
	"net/http"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	"github.com/gin-gonic/gin"
)

// AdminMiddleware ensures the authenticated user is the configured admin.
// Must run AFTER AuthMiddleware, which already loaded the user and stashed
// it in the gin context as "user" — we read it back to avoid a duplicate
// DB round-trip.
func AdminMiddleware(adminChecker application.AdminChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := c.Get("user")
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "NO_AUTH",
				"message": "Se requiere autenticación",
			})
			c.Abort()
			return
		}
		user, ok := raw.(*domain.User)
		if !ok || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "USER_NOT_FOUND",
				"message": "Usuario no encontrado",
			})
			c.Abort()
			return
		}

		if !adminChecker.IsAdmin(user) {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"code":    "FORBIDDEN",
				"message": "Acceso restringido al administrador",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

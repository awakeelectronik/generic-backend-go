package middleware

import (
	"net/http"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/gin-gonic/gin"
)

// AdminMiddleware ensures the authenticated user is the configured admin.
// Must run AFTER AuthMiddleware (which sets user_id in context).
func AdminMiddleware(adminChecker application.AdminChecker, userRepo application.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    "NO_AUTH",
				"message": "Se requiere autenticación",
			})
			c.Abort()
			return
		}

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

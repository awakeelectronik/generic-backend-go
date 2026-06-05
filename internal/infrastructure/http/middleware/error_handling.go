package middleware

import (
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/gin-gonic/gin"
)

func ErrorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		for _, err := range c.Errors {
			if appErr, ok := err.Err.(*appErrors.AppError); ok {
				// No filtrar detalles internos en errores 5xx: el mensaje
				// puede contener cadenas de la BD/driver. Códigos 4xx sí se
				// devuelven literales para que el cliente sepa qué corregir.
				if appErr.StatusCode >= 500 {
					c.JSON(appErr.StatusCode, gin.H{
						"success": false,
						"code":    appErr.Code,
						"message": "Error interno del servidor",
					})
					continue
				}
				c.JSON(appErr.StatusCode, gin.H{
					"success": false,
					"code":    appErr.Code,
					"message": appErr.Message,
				})
			}
		}
	}
}

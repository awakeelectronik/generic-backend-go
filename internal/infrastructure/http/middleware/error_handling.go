package middleware

import (
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/gin-gonic/gin"
)

func ErrorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		for _, err := range c.Errors {
			if appErr, ok := err.Err.(*appErrors.AppError); ok {
				c.JSON(appErr.StatusCode, gin.H{
					"success": false,
					"code":    appErr.Code,
					"message": appErr.Message,
				})
			}
		}
	}
}

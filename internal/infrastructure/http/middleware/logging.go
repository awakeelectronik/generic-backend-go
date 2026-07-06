package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func LoggingMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Request-id para correlacionar el log de acceso con los logs de negocio
		// y con el cliente (se devuelve en X-Request-ID). Si el proxy de
		// confianza ya trae uno, se respeta; se acota para que un header
		// malicioso no infle los logs.
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" || len(requestID) > 64 {
			requestID = uuid.NewString()
		}
		c.Set("request_id", requestID)
		c.Writer.Header().Set("X-Request-ID", requestID)

		c.Next()

		duration := time.Since(startTime)
		statusCode := c.Writer.Status()

		logger.WithFields(logrus.Fields{
			"method":     c.Request.Method,
			"path":       c.Request.RequestURI,
			"status":     statusCode,
			"duration":   duration.Milliseconds(),
			"user_id":    c.GetString("user_id"),
			"ip":         c.ClientIP(),
			"request_id": requestID,
		}).Info("HTTP Request")
	}
}

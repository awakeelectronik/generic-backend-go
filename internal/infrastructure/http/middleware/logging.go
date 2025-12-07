package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func LoggingMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		c.Next()

		duration := time.Since(startTime)
		statusCode := c.Writer.Status()

		logger.WithFields(logrus.Fields{
			"method":   c.Request.Method,
			"path":     c.Request.RequestURI,
			"status":   statusCode,
			"duration": duration.Milliseconds(),
			"user_id":  c.GetString("user_id"),
			"ip":       c.ClientIP(),
		}).Info("HTTP Request")
	}
}

package middleware

import (
	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// AuditMiddleware registra en audit_logs toda petición MUTANTE (POST/PUT/
// DELETE) con su resultado: quién (user_id si está autenticado), qué (método +
// ruta + :id), desde dónde (IP) y cómo terminó (status), correlacionable con
// los logs de aplicación vía request_id.
//
// Se registra DESPUÉS de ejecutar el handler para capturar el status real —
// intentos rechazados (401/403/429) también quedan en el trail, que es
// exactamente lo que un forense necesita.
//
// El insert es síncrono (garantía de escritura mientras la petición existe)
// pero NUNCA propaga error: un trail caído no debe tumbar la operación.
func AuditMiddleware(audit application.AuditLogger, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH" {
			c.Next()
			return
		}

		c.Next()

		entry := &application.AuditEntry{
			UserID:     c.GetString("user_id"),
			Action:     method + " " + c.FullPath(),
			Resource:   c.FullPath(),
			ResourceID: c.Param("id"),
			Changes: map[string]any{
				"status":     c.Writer.Status(),
				"ip":         c.ClientIP(),
				"request_id": c.GetString("request_id"),
			},
		}
		if err := audit.Record(c.Request.Context(), entry); err != nil {
			logger.WithError(err).Warn("audit trail: failed to record entry")
		}
	}
}

package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimitByUserMiddleware limita por USUARIO autenticado, no por IP. Debe
// correr DESPUÉS de AuthMiddleware (necesita user_id en el contexto).
//
// Complementa el límite por IP: detrás de un NAT corporativo muchas cuentas
// comparten IP (el límite por IP las castiga juntas), y una misma cuenta puede
// atacar desde muchas IPs (el límite por IP no la ve). Con ambos, cada
// dimensión queda acotada. Si no hay user_id (no debería ocurrir en rutas
// protegidas), cae a la IP como clave defensiva.
func RateLimitByUserMiddleware(rate int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetString("user_id")
		if key == "" {
			key = c.ClientIP()
		}

		if !currentRateStore().Allow(c.Request.Context(), "uid:"+key, rate, window) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"code":    "RATE_LIMIT_EXCEEDED",
				"message": "Demasiadas solicitudes. Intenta de nuevo más tarde.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

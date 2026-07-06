package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSMiddleware aplica una política CORS basada en una allowlist de orígenes.
//
// Importante: la spec de CORS prohíbe combinar "Access-Control-Allow-Origin: *"
// con "Access-Control-Allow-Credentials: true" (los navegadores lo rechazan).
// Por eso:
//   - allowlist == ["*"]  -> se permite cualquier origen pero SIN credenciales.
//   - orígenes concretos  -> se refleja el Origin de la petición y se habilitan
//     credenciales (única forma válida de usarlas cross-origin).
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowAll := false
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			allowAll = true
		}
		if o != "" {
			allowed[o] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		switch {
		case allowAll:
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		case origin != "":
			if _, ok := allowed[origin]; ok {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
				c.Writer.Header().Add("Vary", "Origin")
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Idempotency-Key")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
		// Cachear el preflight 12h: menos OPTIONS de ida y vuelta por cliente.
		c.Writer.Header().Set("Access-Control-Max-Age", "43200")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

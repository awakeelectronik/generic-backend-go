package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeadersMiddleware aplica las cabeceras defensivas estándar para una
// API JSON:
//
//   - X-Content-Type-Options: nosniff — el navegador no reinterpreta respuestas
//     (p. ej. una descarga) como otro tipo; complementa el sniffing de subida.
//   - X-Frame-Options / frame-ancestors — la API no debe poder embeberse en un
//     iframe (clickjacking sobre cualquier UI que se sirva desde aquí).
//   - Content-Security-Policy default-src 'none' — si una respuesta terminara
//     renderizada como HTML (error, descarga), no puede cargar ni ejecutar nada.
//   - Referrer-Policy: no-referrer — que un cliente navegador no filtre URLs
//     internas (ids de documentos, etc.) a terceros.
//   - Cache-Control: no-store — las respuestas llevan tokens y datos personales;
//     ni el navegador ni proxies intermedios deben persistirlas.
//   - Strict-Transport-Security (opt-in vía HSTS_ENABLED) — solo tiene sentido
//     cuando la app se sirve por HTTPS; los navegadores lo ignoran sobre HTTP.
func SecurityHeadersMiddleware(hstsEnabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if hstsEnabled {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

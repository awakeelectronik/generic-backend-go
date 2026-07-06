package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodySizeLimitMiddleware acota el tamaño del body de las peticiones. Sin este
// tope, cualquier endpoint JSON decodifica en memoria un body arbitrariamente
// grande (DoS trivial con una sola conexión).
//
// skipPaths son rutas (el patrón registrado en Gin, ver c.FullPath) exentas del
// límite global porque imponen el suyo propio — hoy, /documents/upload, que
// acota con MaxBytesReader al tamaño máximo de archivo. Si aquí también se
// envolviera el body, ganaría el límite más chico y rompería las subidas.
func BodySizeLimitMiddleware(maxBytes int64, skipPaths ...string) gin.HandlerFunc {
	skip := make(map[string]struct{}, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = struct{}{}
	}

	return func(c *gin.Context) {
		if _, exempt := skip[c.FullPath()]; exempt {
			c.Next()
			return
		}

		// Rechazo temprano cuando el cliente declara el tamaño: 413 claro en vez
		// de un error de parseo a mitad de lectura.
		if c.Request.ContentLength > maxBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"success": false,
				"code":    "BODY_TOO_LARGE",
				"message": "El cuerpo de la petición excede el tamaño máximo permitido",
			})
			c.Abort()
			return
		}

		// Backstop para bodies chunked (sin Content-Length): corta la lectura al
		// exceder el límite y el binding devuelve error en el handler.
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupBodyLimitRouter(maxBytes int64) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodySizeLimitMiddleware(maxBytes, "/upload"))
	echo := func(c *gin.Context) {
		// Leer el body completo dispara el MaxBytesReader si el límite se excede
		// sin Content-Length declarado.
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"code": "BODY_TOO_LARGE"})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	}
	r.POST("/json", echo)
	r.POST("/upload", echo)
	return r
}

func TestBodyLimitAllowsSmallBody(t *testing.T) {
	r := setupBodyLimitRouter(64)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/json", strings.NewReader(`{"a":1}`))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBodyLimitRejectsDeclaredOversize(t *testing.T) {
	r := setupBodyLimitRouter(16)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/json", strings.NewReader(strings.Repeat("x", 64)))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "BODY_TOO_LARGE")
}

func TestBodyLimitRejectsChunkedOversize(t *testing.T) {
	r := setupBodyLimitRouter(16)

	w := httptest.NewRecorder()
	// Sin Content-Length (ContentLength = -1 con un reader anónimo): debe cortar
	// al leer, no al declarar.
	req, _ := http.NewRequest(http.MethodPost, "/json", io.NopCloser(strings.NewReader(strings.Repeat("x", 64))))
	req.ContentLength = -1
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestBodyLimitSkipsExemptPath(t *testing.T) {
	r := setupBodyLimitRouter(16)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 256)))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

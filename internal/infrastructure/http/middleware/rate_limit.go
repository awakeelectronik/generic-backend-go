package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type rateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     int           // requests per window
	window   time.Duration // time window
}

type visitor struct {
	lastSeen time.Time
	count    int
}

// NewRateLimiter creates a new rate limiter
// rate: maximum number of requests per window
// window: time window for rate limiting
func NewRateLimiter(rate int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}

	// Clean up old visitors every minute
	go rl.cleanupVisitors()

	return rl
}

func (rl *rateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > rl.window*2 {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	// Una sola sección crítica: el get-or-create y la actualización del contador
	// deben ser atómicos. Antes se hacían bajo dos locks distintos, dejando una
	// ventana en la que cleanupVisitors podía borrar la entrada entre medias y
	// se perdía la cuenta (TOCTOU que debilitaba el límite).
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{lastSeen: now, count: 1}
		return true
	}

	// Reset count if window has passed
	if now.Sub(v.lastSeen) > rl.window {
		v.count = 0
		v.lastSeen = now
	}

	// Check if rate limit exceeded
	if v.count >= rl.rate {
		return false
	}

	v.count++
	v.lastSeen = now
	return true
}

// limiterKey identifica un limiter por rate y ventana (para reutilizar y evitar una goroutine por ruta).
type limiterKey struct {
	rate   int
	window time.Duration
}

var (
	limitersMu    sync.Mutex
	limitersByKey = make(map[limiterKey]*rateLimiter)
)

// ResetRateLimitersForTests limpia el estado de visitantes acumulado en memoria.
// Solo debe usarse desde tests para evitar contaminación entre casos.
func ResetRateLimitersForTests() {
	limitersMu.Lock()
	defer limitersMu.Unlock()

	for _, rl := range limitersByKey {
		rl.mu.Lock()
		rl.visitors = make(map[string]*visitor)
		rl.mu.Unlock()
	}
}

// getOrCreateLimiter devuelve un limiter compartido por (rate, window) para no crear una goroutine por ruta.
func getOrCreateLimiter(rate int, window time.Duration) *rateLimiter {
	key := limiterKey{rate: rate, window: window}
	limitersMu.Lock()
	defer limitersMu.Unlock()
	if rl, ok := limitersByKey[key]; ok {
		return rl
	}
	rl := NewRateLimiter(rate, window)
	limitersByKey[key] = rl
	return rl
}

// RateLimitMiddleware creates a middleware for rate limiting.
// Reutiliza un limiter por (rate, window) para evitar una goroutine por ruta.
func RateLimitMiddleware(rate int, window time.Duration) gin.HandlerFunc {
	limiter := getOrCreateLimiter(rate, window)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !limiter.allow(ip) {
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

package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// redisRateStore is the shared, restart-safe rate-limit backend. A fixed window
// per (rate, window, ip) is implemented with INCR + PEXPIRE inside a Lua script
// (atomic), so counts are consistent across instances.
type redisRateStore struct {
	client redis.UniversalClient
	logger *logrus.Logger
}

// NewRedisRateStore builds a Redis-backed RateStore. Install it with
// SetRateStore at startup.
func NewRedisRateStore(client redis.UniversalClient, logger *logrus.Logger) RateStore {
	return &redisRateStore{client: client, logger: logger}
}

// rateScript increments the per-key counter and sets the window TTL on the first
// hit. Returns 1 if within the limit, 0 if over.
var rateScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if count > tonumber(ARGV[2]) then
  return 0
end
return 1
`)

func (s *redisRateStore) Allow(ctx context.Context, key string, rate int, window time.Duration) bool {
	// La ventana va en la clave: distintas rutas (distinto rate/window) no
	// comparten contador aunque sea la misma IP.
	redisKey := fmt.Sprintf("rl:%d:%d:%s", rate, int(window.Seconds()), key)

	res, err := rateScript.Run(ctx, s.client, []string{redisKey}, window.Milliseconds(), rate).Int()
	if err != nil {
		// Fail-open: si Redis no responde preferimos servir la petición (perder
		// el límite) antes que tumbar el endpoint. Se registra para alertar.
		s.logger.WithError(err).Warn("rate limiter: Redis unavailable, allowing request (fail-open)")
		return true
	}
	return res == 1
}

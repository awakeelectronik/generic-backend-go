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
	// failClosed invierte la política ante un Redis caído: false = fail-open
	// (se sirve la petición; disponibilidad), true = fail-closed (429 a todo;
	// integridad — preferible en fintech donde el rate-limit protege dinero).
	failClosed bool
	logger     *logrus.Logger
}

// NewRedisRateStore builds a Redis-backed RateStore. Install it with
// SetRateStore at startup.
func NewRedisRateStore(client redis.UniversalClient, failClosed bool, logger *logrus.Logger) RateStore {
	return &redisRateStore{client: client, failClosed: failClosed, logger: logger}
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
	// comparten contador aunque sea la misma IP. Se usa la ventana en
	// milisegundos (no segundos truncados) para que dos ventanas sub-segundo
	// distintas no colapsen a la misma clave.
	redisKey := fmt.Sprintf("rl:%d:%d:%s", rate, window.Milliseconds(), key)

	res, err := rateScript.Run(ctx, s.client, []string{redisKey}, window.Milliseconds(), rate).Int()
	if err != nil {
		// Política ante Redis caído, elegible por despliegue
		// (RATE_LIMIT_FAIL_CLOSED):
		//   - fail-OPEN (default): se sirve la petición perdiendo el límite;
		//     el rate-limit es protección, no control de acceso.
		//   - fail-CLOSED: 429 a todo; en fintech un límite evadido puede costar
		//     dinero y se prefiere degradar disponibilidad.
		// El store de verificación siempre falla CERRADO (500): un código que no
		// se puede registrar/verificar de forma fiable NO debe emitirse ni
		// aceptarse.
		if s.failClosed {
			s.logger.WithError(err).Warn("rate limiter: Redis unavailable, rejecting request (fail-closed)")
			return false
		}
		s.logger.WithError(err).Warn("rate limiter: Redis unavailable, allowing request (fail-open)")
		return true
	}
	return res == 1
}

package security

import (
	"context"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// redisLoginThrottle es el lockout por cuenta compartido entre réplicas y
// restart-safe: ventana fija de fallos con INCR+PEXPIRE (atómico en Lua).
//
// Fail-OPEN ante fallo de Redis (como el rate-limiter por IP): el lockout es
// una defensa adicional sobre bcrypt + rate-limit por IP; ante un Redis caído
// preferimos no bloquear TODOS los logins.
type redisLoginThrottle struct {
	client redis.UniversalClient
	policy LoginThrottlePolicy
	logger *logrus.Logger
}

// NewRedisLoginThrottle construye el throttle respaldado en Redis.
func NewRedisLoginThrottle(client redis.UniversalClient, p LoginThrottlePolicy, logger *logrus.Logger) *redisLoginThrottle {
	return &redisLoginThrottle{client: client, policy: p, logger: logger}
}

func failuresKey(accountID string) string { return "lockout:" + accountID }

// failureScript incrementa el contador de fallos y fija el TTL de la ventana
// en el primer fallo. Si el contador alcanza el máximo, extiende el TTL a la
// duración del bloqueo (la clave ES el bloqueo mientras count >= max).
var failureScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if count >= tonumber(ARGV[2]) then
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
end
return count
`)

func (t *redisLoginThrottle) IsLocked(ctx context.Context, accountID string) bool {
	count, err := t.client.Get(ctx, failuresKey(accountID)).Int()
	if err == redis.Nil {
		return false
	}
	if err != nil {
		t.logger.WithError(err).Warn("login throttle: Redis unavailable, not locking (fail-open)")
		return false
	}
	return count >= t.policy.MaxFailures
}

func (t *redisLoginThrottle) RegisterFailure(ctx context.Context, accountID string) {
	err := failureScript.Run(ctx, t.client,
		[]string{failuresKey(accountID)},
		t.policy.Window.Milliseconds(),
		t.policy.MaxFailures,
		t.policy.LockDuration.Milliseconds(),
	).Err()
	if err != nil {
		t.logger.WithError(err).Warn("login throttle: failed to register failure")
	}
}

func (t *redisLoginThrottle) Reset(ctx context.Context, accountID string) {
	if err := t.client.Del(ctx, failuresKey(accountID)).Err(); err != nil && err != redis.Nil {
		t.logger.WithError(err).Warn("login throttle: failed to reset")
	}
}

package security

import (
	"context"
	"fmt"
	"time"

	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/redis/go-redis/v9"
)

// redisVerificationStore is the restart-safe, multi-instance backend. Codes and
// send-throttle state live in Redis so a code issued by one replica can be
// verified by another, and nothing is lost on restart.
//
// Atomicity: VerifyCode and RegisterSend run as Lua scripts (Redis executes a
// script atomically), so the attempt counter and the send window can't be raced
// by concurrent requests across instances.
type redisVerificationStore struct {
	client redis.UniversalClient
	policy VerificationPolicy
}

// NewRedisVerificationStore builds a Redis-backed VerificationStore. Pass it to
// NewVerificationServiceWithStore to make codes restart-safe and shared.
func NewRedisVerificationStore(client redis.UniversalClient, p VerificationPolicy) VerificationStore {
	return &redisVerificationStore{client: client, policy: p}
}

func codeKey(userID string) string  { return "verif:code:" + userID }
func sendsKey(userID string) string { return "verif:sends:" + userID }

// verifyScript validates a code in one atomic step. Returns a status token that
// Go maps to a typed error. The "exp" field lets us report an expired code
// distinctly from a missing one (the key itself lives a bit longer than the TTL
// so expiry is observable instead of silently becoming "not found").
var verifyScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 'notfound'
end
if redis.call('HGET', KEYS[1], 'used') == '1' then
  return 'used'
end
local exp = tonumber(redis.call('HGET', KEYS[1], 'exp'))
if exp ~= nil and tonumber(ARGV[3]) > exp then
  return 'expired'
end
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts')) or 0
local maxAttempts = tonumber(ARGV[2])
if attempts >= maxAttempts then
  redis.call('HSET', KEYS[1], 'used', '1')
  return 'attempts'
end
if redis.call('HGET', KEYS[1], 'code') ~= ARGV[1] then
  attempts = attempts + 1
  redis.call('HSET', KEYS[1], 'attempts', attempts)
  if attempts >= maxAttempts then
    redis.call('HSET', KEYS[1], 'used', '1')
  end
  return 'invalid'
end
redis.call('HSET', KEYS[1], 'used', '1')
return 'ok'
`)

// registerSendScript enforces the send throttle atomically: trims the sliding
// window, rejects if the per-window cap is hit or the last send is too recent,
// otherwise records the send. Scores are unix milliseconds (within float64's
// exact-integer range, unlike nanoseconds) and the member is a unique token so
// two sends never collide.
var registerSendScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local minInterval = tonumber(ARGV[3])
local maxPer = tonumber(ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
if redis.call('ZCARD', KEYS[1]) >= maxPer then
  return 'limited'
end
local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if last[2] ~= nil and (now - tonumber(last[2])) < minInterval then
  return 'limited'
end
redis.call('ZADD', KEYS[1], now, ARGV[5])
redis.call('PEXPIRE', KEYS[1], window)
return 'ok'
`)

func (s *redisVerificationStore) RegisterSend(ctx context.Context, userID string) error {
	now := time.Now()
	res, err := registerSendScript.Run(ctx, s.client,
		[]string{sendsKey(userID)},
		now.UnixMilli(),
		s.policy.SendWindow.Milliseconds(),
		s.policy.MinResendInterval.Milliseconds(),
		s.policy.MaxSendsPerWindow,
		fmt.Sprintf("%d", now.UnixNano()), // unique member
	).Result()
	if err != nil {
		return appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error verificando límite de envío", 500, err)
	}
	if res == "limited" {
		return appErrors.ErrVerificationRateLimited
	}
	return nil
}

func (s *redisVerificationStore) SaveCode(ctx context.Context, userID, code string) error {
	now := time.Now()
	key := codeKey(userID)
	// El registro vive algo más que el TTL lógico para que VerifyCode pueda
	// distinguir "expirado" de "inexistente" durante una ventana de gracia.
	keyTTL := s.policy.CodeTTL * 2

	pipe := s.client.TxPipeline()
	pipe.Del(ctx, key)
	pipe.HSet(ctx, key, map[string]interface{}{
		"code":     code,
		"attempts": 0,
		"used":     0,
		"exp":      now.Add(s.policy.CodeTTL).UnixMilli(),
	})
	pipe.Expire(ctx, key, keyTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error guardando código", 500, err)
	}
	return nil
}

func (s *redisVerificationStore) VerifyCode(ctx context.Context, userID, code string) error {
	res, err := verifyScript.Run(ctx, s.client,
		[]string{codeKey(userID)},
		code,
		s.policy.MaxAttempts,
		time.Now().UnixMilli(),
	).Result()
	if err != nil {
		return appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error verificando código", 500, err)
	}

	switch res {
	case "ok":
		return nil
	case "notfound":
		return appErrors.ErrVerificationCodeNotFound
	case "used":
		return appErrors.ErrVerificationCodeUsed
	case "expired":
		return appErrors.ErrVerificationCodeExpired
	case "attempts":
		return appErrors.ErrVerificationCodeAttemptsExceeded
	case "invalid":
		return appErrors.ErrVerificationCodeInvalid
	default:
		return appErrors.NewAppError("STORAGE_ERROR", "Respuesta de verificación inesperada", 500)
	}
}

func (s *redisVerificationStore) PeekCode(ctx context.Context, userID string) (string, bool) {
	code, err := s.client.HGet(ctx, codeKey(userID), "code").Result()
	if err != nil || code == "" {
		return "", false
	}
	return code, true
}

func (s *redisVerificationStore) ResetSends(ctx context.Context, userID string) {
	s.client.Del(ctx, sendsKey(userID))
}

// CleanupExpired is a no-op: Redis TTL evicts expired codes automatically.
func (s *redisVerificationStore) CleanupExpired(_ context.Context) {}

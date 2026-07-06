package security

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMemoryLoginThrottleLocksAfterMaxFailures(t *testing.T) {
	th := NewMemoryLoginThrottle(LoginThrottlePolicy{
		MaxFailures:  3,
		Window:       time.Minute,
		LockDuration: time.Minute,
	})
	ctx := context.Background()

	assert.False(t, th.IsLocked(ctx, "acct-1"))
	th.RegisterFailure(ctx, "acct-1")
	th.RegisterFailure(ctx, "acct-1")
	assert.False(t, th.IsLocked(ctx, "acct-1"), "aún bajo el umbral")

	th.RegisterFailure(ctx, "acct-1")
	assert.True(t, th.IsLocked(ctx, "acct-1"), "tercer fallo debe bloquear")

	// Otra cuenta no se ve afectada.
	assert.False(t, th.IsLocked(ctx, "acct-2"))
}

func TestMemoryLoginThrottleResetOnSuccess(t *testing.T) {
	th := NewMemoryLoginThrottle(LoginThrottlePolicy{
		MaxFailures:  2,
		Window:       time.Minute,
		LockDuration: time.Minute,
	})
	ctx := context.Background()

	th.RegisterFailure(ctx, "acct-1")
	th.Reset(ctx, "acct-1")
	th.RegisterFailure(ctx, "acct-1")
	assert.False(t, th.IsLocked(ctx, "acct-1"), "el reset debe limpiar el contador")
}

func TestMemoryLoginThrottleLockExpires(t *testing.T) {
	th := NewMemoryLoginThrottle(LoginThrottlePolicy{
		MaxFailures:  1,
		Window:       10 * time.Millisecond,
		LockDuration: 10 * time.Millisecond,
	})
	ctx := context.Background()

	th.RegisterFailure(ctx, "acct-1")
	assert.True(t, th.IsLocked(ctx, "acct-1"))

	time.Sleep(20 * time.Millisecond)
	assert.False(t, th.IsLocked(ctx, "acct-1"), "el bloqueo debe expirar")
}

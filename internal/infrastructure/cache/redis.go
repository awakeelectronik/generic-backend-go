// Package cache provides the shared Redis client used by the opt-in
// distributed backends (rate limiting and verification codes).
package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewClient parses a redis:// (or rediss://) URL, opens the client and pings it
// so a bad URL or unreachable server fails fast at startup instead of on the
// first request.
func NewClient(url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

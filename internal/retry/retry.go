package retry

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

type Config struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxRetries: 3,
		BaseDelay:  500 * time.Millisecond,
		MaxDelay:   30 * time.Second,
	}
}

func Do(ctx context.Context, cfg Config, fn func(ctx context.Context) error) error {
	var lastErr error
	for attempt := range cfg.MaxRetries + 1 {
		lastErr = fn(ctx)
		if lastErr == nil {
			return nil
		}
		if attempt == cfg.MaxRetries {
			break
		}
		delay := backoff(attempt, cfg.BaseDelay, cfg.MaxDelay)
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	return lastErr
}

func backoff(attempt int, base, max time.Duration) time.Duration {
	exp := math.Pow(2, float64(attempt))
	delay := time.Duration(float64(base) * exp)
	if delay > max {
		delay = max
	}
	jitter := time.Duration(rand.Int64N(int64(delay)/2 + 1))
	return delay/2 + jitter
}

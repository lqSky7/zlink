package zlink

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

type RateLimitInfo struct {
	Limit     int
	Remaining int
	ResetAt   time.Time
}

func ParseRateLimit(h http.Header) RateLimitInfo {
	info := RateLimitInfo{}
	if v := h.Get("X-RateLimit-Limit"); v != "" {
		info.Limit, _ = strconv.Atoi(v)
	}
	if v := h.Get("X-RateLimit-Remaining"); v != "" {
		info.Remaining, _ = strconv.Atoi(v)
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			info.ResetAt = time.Unix(epoch, 0)
		}
	}
	return info
}

func WaitForReset(ctx context.Context, resetAt time.Time) error {
	wait := time.Until(resetAt)
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

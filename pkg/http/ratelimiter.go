package http

import (
	"context"
	"sync"
	"time"
)

// RateLimiter provides simple, leak-free rate limiting
// No background goroutines, no cleanup needed
type RateLimiter struct {
	ratePerSecond int
	mu            sync.Mutex
	lastRequest   time.Time
	minInterval   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(ratePerSecond int) *RateLimiter {
	if ratePerSecond <= 0 {
		ratePerSecond = 10 // Default to 10 requests per second
	}

	return &RateLimiter{
		ratePerSecond: ratePerSecond,
		minInterval:   time.Second / time.Duration(ratePerSecond),
		lastRequest:   time.Now().Add(-time.Second), // Allow immediate first request
	}
}

// Wait blocks until the next request is allowed
// Simple implementation without goroutines
func (r *RateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	timeSinceLastRequest := now.Sub(r.lastRequest)

	if timeSinceLastRequest < r.minInterval {
		waitTime := r.minInterval - timeSinceLastRequest

		// Create a timer for the wait
		timer := time.NewTimer(waitTime)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			// Wait completed
		}
	}

	r.lastRequest = time.Now()
	return nil
}

// UpdateRate updates the rate limit
func (r *RateLimiter) UpdateRate(ratePerSecond int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ratePerSecond <= 0 {
		ratePerSecond = 10
	}

	r.ratePerSecond = ratePerSecond
	r.minInterval = time.Second / time.Duration(ratePerSecond)
}
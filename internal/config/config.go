package config

import "time"



const (
	RateLimitRequests = 20
	RateLimitWindow   = 60 * time.Second

	MaxMaliciousRequests = 3
	BlockDuration        = 1 * time.Minute

	BlockThreshold = 50
)

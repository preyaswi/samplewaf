package interfaces

import (
	"context"
)

type RedisService interface {
	CheckRateLimit(ctx context.Context, ip string) bool
	CheckBlockIp(ctx context.Context, ip string) (int64, error)
	IncrementAttackCount(ctx context.Context, ip string) (int64, error)
	BlockIp(ctx context.Context, ip string)
}

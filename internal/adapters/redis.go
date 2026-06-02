package adapters

import (
	"context"
	"errors"
	"samplewaf/internal/config"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type RedisAdapter struct {
	Client *redis.Client
	Logger zerolog.Logger
}

// func (rd *RedisAdapter) checkRateLimitwithgo(ctx context.Context, ip string) bool {
// 	key := "rate_limit:" + ip

// 	count, err := rd.Client.Incr(ctx, key).Result()

// 	if err != nil {
// 		rd.Logger.Error().Err(err).Str("ip", ip).Msg("error occurred while checking rate limit")
// 		return true
// 	}

// 	if count == 1 {
// 		rd.Client.Expire(ctx, key, config.RateLimitWindow)
// 	}
// 	return count <= config.RateLimitRequests
// }

func (rd *RedisAdapter) CheckRateLimit(ctx context.Context, ip string) bool {
	key := "rate_limit:" + ip

	res, err := rd.Client.Do(
		ctx, "FCALL", "rate_limit", 1, key,
		config.RateLimitRequests, int(config.RateLimitWindow.Seconds())).Int()

	if err != nil {
		rd.Logger.Error().Err(err).Str("ip", ip).Msg("error occurred while checking rate limit")
		return true
	}

	return res == 1
}

func (rd *RedisAdapter) CheckBlockIp(ctx context.Context, ip string) (int64, error) {

	//check temp block
	blocked, err := rd.Client.Exists(ctx, "blocked:"+ip).Result()
	if err != nil {
		return 0, errors.New("redis function error::internal server error when checking the blocked ip")
	}
	return blocked, err

}

func (rd *RedisAdapter) IncrementAttackCount(ctx context.Context, ip string) (int64, error) {
	//track attack count
	attackKey := "attacks:" + ip

	count, err := rd.Client.Incr(ctx, attackKey).Result()

	if err != nil {
		return 0, errors.New("redis function error::internal server error when checking the attack count")
	}

	if count == 1 {

		rd.Client.Expire(ctx, attackKey, 10*time.Minute)
		rd.Logger.Info().Str("ip", ip).Int64("count", count).Msg("First attack detected, starting attack count")
	}

	return count, err

}

func (rd *RedisAdapter) BlockIp(ctx context.Context, ip string) {
	rd.Client.Set(ctx, "blocked:"+ip, "1", config.BlockDuration)
}

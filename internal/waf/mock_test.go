package waf_test

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockRedisService is a mock implementation of the RedisService interface
type MockRedisService struct {
	mock.Mock
}

func (m *MockRedisService) CheckRateLimit(ctx context.Context, ip string) bool {
	args := m.Called(ctx, ip)
	return args.Bool(0)
}

func (m *MockRedisService) CheckBlockIp(ctx context.Context, ip string) (int64, error) {
	args := m.Called(ctx, ip)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockRedisService) IncrementAttackCount(ctx context.Context, ip string) (int64, error) {
	args := m.Called(ctx, ip)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockRedisService) BlockIp(ctx context.Context, ip string) {
	m.Called(ctx, ip)
}

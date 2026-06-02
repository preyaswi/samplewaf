package waf_test

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"samplewaf/internal/models"
	"samplewaf/internal/waf"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestWAFHandler_RateLimitExceeded(t *testing.T) {

	mockRedis := new(MockRedisService)

	mockRedis.
		On("CheckBlockIp", mock.Anything, mock.Anything).
		Return(0, nil)

	mockRedis.
		On("CheckRateLimit", mock.Anything, mock.Anything).
		Return(false)

	handler := &waf.Handler{
		Redis:   mockRedis,
		Logger:  zerolog.Nop(),
		LogChan: make(chan models.WAFEvent, 10),
	}

	req := httptest.NewRequest("GET", "/", nil)

	rec := httptest.NewRecorder()

	handler.WafHandler(rec, req)

	if rec.Code != 429 {
		t.Errorf("expected 429, got %d", rec.Code)
	}

	mockRedis.AssertExpectations(t)
}

func TestWAFHandler_IPBlocked(t *testing.T) {

	mockRedis := new(MockRedisService)

	mockRedis.
		On("CheckBlockIp", mock.Anything, mock.Anything).
		Return(1, nil)

	handler := &waf.Handler{
		Redis:   mockRedis,
		Logger:  zerolog.Nop(),
		LogChan: make(chan models.WAFEvent, 10),
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.WafHandler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	mockRedis.AssertExpectations(t)
}

func TestWAFHandler_SQLInjection(t *testing.T) {

	mockRedis := new(MockRedisService)

	mockRedis.
		On("CheckBlockIp", mock.Anything, mock.Anything).
		Return(0, nil)

	mockRedis.
		On("CheckRateLimit", mock.Anything, mock.Anything).
		Return(true)

	mockRedis.
		On("IncrementAttackCount", mock.Anything, mock.Anything).
		Return(1, nil)

	handler := &waf.Handler{
		Redis:   mockRedis,
		Logger:  zerolog.Nop(),
		LogChan: make(chan models.WAFEvent, 10),
	}

	req := httptest.NewRequest(
		"GET",
		"/?id=%27%20OR%201%3D1",
		nil,
	)

	rec := httptest.NewRecorder()

	handler.WafHandler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	mockRedis.AssertCalled(
		t,
		"IncrementAttackCount",
		mock.Anything,
		mock.Anything,
	)
}

func TestWAFHandler_XSS(t *testing.T) {

	mockRedis := new(MockRedisService)

	mockRedis.
		On("CheckBlockIp", mock.Anything, mock.Anything).
		Return(0, nil)

	mockRedis.
		On("CheckRateLimit", mock.Anything, mock.Anything).
		Return(true)

	mockRedis.
		On("IncrementAttackCount", mock.Anything, mock.Anything).
		Return(1, nil)

	handler := &waf.Handler{
		Redis:   mockRedis,
		Logger:  zerolog.Nop(),
		LogChan: make(chan models.WAFEvent, 10),
	}

	req := httptest.NewRequest(
		"GET",
		"/?search=<script>alert(1)</script>",
		nil,
	)

	rec := httptest.NewRecorder()

	handler.WafHandler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	mockRedis.AssertExpectations(t)
}

func TestWAFHandler_PathTraversal(t *testing.T) {

	mockRedis := new(MockRedisService)

	mockRedis.
		On("CheckBlockIp", mock.Anything, mock.Anything).
		Return(0, nil)

	mockRedis.
		On("CheckRateLimit", mock.Anything, mock.Anything).
		Return(true)

	// mockRedis.
	// 	On("IncrementAttackCount", mock.Anything, mock.Anything).
	// 	Return(1, nil)

	backend := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer backend.Close()

	target, _ := url.Parse(backend.URL)

	proxy := httputil.NewSingleHostReverseProxy(target)

	handler := &waf.Handler{
		Redis:   mockRedis,
		Proxy:   proxy,
		Logger:  zerolog.Nop(),
		LogChan: make(chan models.WAFEvent, 10),
	}
	req := httptest.NewRequest(
		"GET",
		"/?file=../../etc/passwd",
		nil,
	)

	rec := httptest.NewRecorder()

	handler.WafHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	mockRedis.AssertExpectations(t)
}

func TestWAFHandler_NormalRequest(t *testing.T) {

	mockRedis := new(MockRedisService)

	mockRedis.
		On("CheckBlockIp", mock.Anything, mock.Anything).
		Return(0, nil)

	mockRedis.
		On("CheckRateLimit", mock.Anything, mock.Anything).
		Return(true)

	backend := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer backend.Close()

	target, _ := url.Parse(backend.URL)

	proxy := httputil.NewSingleHostReverseProxy(target)

	handler := &waf.Handler{
		Redis:   mockRedis,
		Proxy:   proxy,
		Logger:  zerolog.Nop(),
		LogChan: make(chan models.WAFEvent, 10),
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.WafHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	mockRedis.AssertExpectations(t)
}

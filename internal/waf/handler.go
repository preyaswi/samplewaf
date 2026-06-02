package waf

import (
	"net/http"
	"net/http/httputil"
	"samplewaf/internal/config"
	"samplewaf/internal/interfaces"
	"samplewaf/internal/models"
	"samplewaf/internal/utils"

	"time"

	"github.com/rs/zerolog"
)

type Handler struct {
	Redis interfaces.RedisService
	// Elastic *adapters.ElasticAdapter
	Proxy   *httputil.ReverseProxy
	LogChan chan models.WAFEvent
	Logger  zerolog.Logger
}


func (h *Handler) publishEvent(event models.WAFEvent) {
	select {
	case h.LogChan <- event:
	default:
		h.Logger.Warn().Msg("event queue full")
	}
}

func (h *Handler) WafHandler(w http.ResponseWriter, r *http.Request) {

	ip := utils.GetIp(r)
	ctx := r.Context()

	//check temp block
	blocked, err := h.Redis.CheckBlockIp(ctx, ip)

	if err != nil {
		h.Logger.Error().Err(err).Str("ip", ip).Msg("error occurred while checking the blocked ip")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
	}

	if err == nil && blocked == 1 {

		h.publishEvent(models.WAFEvent{
			Timestamp: time.Now().Format(time.RFC3339),
			IP:        ip,
			Method:    r.Method,
			Path:      r.URL.Path,
			Action:    "block",
		})

		http.Error(w, "403 Forbidden - IP Temporarily Blocked", http.StatusForbidden)
		h.Logger.Warn().
			Str("ip", ip).
			Msg("blocked IP tried access")
		return

	}

	//rate limit
	allowed := h.Redis.CheckRateLimit(ctx, ip)

	if !allowed {
		http.Error(w,
			"429 Too Many Requests",
			http.StatusTooManyRequests,
		)

		h.publishEvent(models.WAFEvent{
			Timestamp: time.Now().Format(time.RFC3339),
			IP:        ip,
			Method:    r.Method,
			Path:      r.URL.Path,
			Action:    "rate_limit",
		})

		h.Logger.Warn().
			Str("ip", ip).
			Msg("rate limit exceeded")
		return
	}

	score, matches := inspectRequest(r)

	action := "allow"

	if score >= config.BlockThreshold {
		action = "block"

		count, err := h.Redis.IncrementAttackCount(ctx, ip)

		if err != nil {
			h.Logger.Error().Err(err).Str("ip", ip).Msg("error occurred while incrementing attack count")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		//temp block after multiple attacks
		if count >= config.MaxMaliciousRequests {
			h.Redis.BlockIp(ctx, ip)
			h.Logger.Warn().
				Str("ip", ip).
				Msg("ip blocked")
		}

	}

	h.Logger.Info().
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Int("score", score).
		Msg("request inspected")

	if len(matches) > 0 {
		h.Logger.Info().
			Interface("matches", matches).
			Msg("matched rules")
	}

	logEntry := models.WAFEvent{

		Timestamp: time.Now().Format(time.RFC3339),
		IP:        r.RemoteAddr,
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Score:     score,
		Action:    action,
		Rules:     matches,
		UserAgent: r.UserAgent(),
		From:      "handler",
	}

	// h.Elastic.SendLogToElasticsearch(logEntry)

	if action == "block" {
		h.publishEvent(logEntry)

		http.Error(w,
			"403 Forbidden - Malicious Request Blocked",
			http.StatusForbidden,
		)

		h.Logger.Info().Str("ip", ip).Msg("Blocked request")
		return
	}

	h.publishEvent(logEntry)

	h.Proxy.ServeHTTP(w, r)
}

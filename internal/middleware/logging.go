package middleware

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

type ResponseRecorder struct {
	http.ResponseWriter
	StatusCode int
}

func (r *ResponseRecorder) WriteHeader(code int) {
	r.StatusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func LoggingMiddleware(next http.Handler, logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			rec := &ResponseRecorder{
				ResponseWriter: w,
				StatusCode:     http.StatusOK,
			}

			start := time.Now()

			next.ServeHTTP(rec, r)

			latency := time.Since(start)

			logger.Info().
				Str("method", r.Method).
				Str("url", r.URL.String()).
				Int("status", rec.StatusCode).
				Dur("latency", latency).
				Msg("Handled request")

		},
	)
}

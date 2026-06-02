package models

type RequestLog struct {
	Method     string
	Path       string
	StatusCode int
	LatencyMS  int64
	IP         string
}

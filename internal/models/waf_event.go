package models

type WAFEvent struct {
	Timestamp string   `json:"timestamp"`
	IP        string   `json:"ip"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Query     string   `json:"query"`
	Score     int      `json:"score"`
	Action    string   `json:"action"`
	Rules     []string `json:"rules"`
	UserAgent string   `json:"user_agent"`
	From      string   `json:"from"`
}

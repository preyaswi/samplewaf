package waf

import (
	"regexp"
	"samplewaf/internal/models"
)

var rules = []models.Rule{
	{
		Name:    "SQL Injection",
		Pattern: regexp.MustCompile(`(?i)(union\s+select|or\s+1=1|drop\s+table)`),
		Score:   50,
	},
	{
		Name:    "XSS",
		Pattern: regexp.MustCompile(`(?i)(<script>|javascript:|onerror=)`),
		Score:   50,
	},
	{
		Name:    "Path Traversal",
		Pattern: regexp.MustCompile(`\.\./`),
		Score:   40,
	},
}

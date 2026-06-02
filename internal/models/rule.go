package models

import "regexp"

type Rule struct {
	Name    string
	Pattern *regexp.Regexp
	Score   int
}

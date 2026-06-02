package waf

import (
	"net/url"
	"strings"
)

func normalize(input string) string {

	decoded, err := url.QueryUnescape(input)
	if err == nil {
		input = decoded
	}

	input = strings.ToLower(input)

	input = strings.TrimSpace(input)

	return input
}

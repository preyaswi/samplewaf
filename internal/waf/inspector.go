package waf

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

func inspectRequest(r *http.Request) (int, []string) {

	var score int
	var matchedRules []string

	var requestData strings.Builder

	requestData.WriteString(r.URL.String())

	for _, values := range r.URL.Query() {
		for _, v := range values {
			requestData.WriteString(v)
		}
	}

	for _, values := range r.Header {
		for _, v := range values {
			requestData.WriteString(v)
		}
	}

	if r.Body != nil {

		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {

			requestData.Write(bodyBytes)

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	normalized := normalize(requestData.String())

	for _, rule := range rules {

		if rule.Pattern.MatchString(normalized) {
			score += rule.Score
			matchedRules = append(matchedRules, rule.Name)
		}
	}

	return score, matchedRules
}

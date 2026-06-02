package waf

import (
	"bytes"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestInspectRequest(t *testing.T) {
	req := httptest.NewRequest("POST", "/test?param=value", bytes.NewBufferString("body content"))
	req.Header.Set("User-Agent", "test-agent")

	score, matchedRules :=inspectRequest(req)

	if score != 5 {
		t.Errorf("expected score 5, got %d", score)
	}

	expectedRules := []string{"SQL Injection", "XSS Attack"}
	if !reflect.DeepEqual(matchedRules, expectedRules) {
		t.Errorf("expected matched rules %v, got %v", expectedRules, matchedRules)
	}
}

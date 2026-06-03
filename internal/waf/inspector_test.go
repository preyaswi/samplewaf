package waf

import (
	"bytes"
	"io"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectRequest_SQLInjection(t *testing.T) {

	values := url.Values{}
	values.Set("q", "' OR 1=1 --")

	req := httptest.NewRequest(
		"GET",
		"/search?"+values.Encode(),
		nil,
	)

	score, matched := inspectRequest(req)

	assert.Equal(t, 50, score)
	assert.Contains(t, matched, "SQL Injection")
}

func TestInspectRequest_XSS(t *testing.T) {
	req := httptest.NewRequest(
		"POST",
		"/comment",
		bytes.NewBufferString("<script>alert(1)</script>"),
	)

	score, matched := inspectRequest(req)

	assert.Equal(t, 50, score)
	assert.Contains(t, matched, "XSS")
}

func TestInspectRequest_NoMatch(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"/home",
		nil,
	)

	score, matched := inspectRequest(req)

	assert.Equal(t, 0, score)
	assert.Empty(t, matched)
}

func TestInspectRequest_RestoresBody(t *testing.T) {
	payload := "hello world"

	req := httptest.NewRequest(
		"POST",
		"/test",
		bytes.NewBufferString(payload),
	)

	inspectRequest(req)

	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)

	assert.Equal(t, payload, string(body))
}

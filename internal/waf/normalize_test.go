package waf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase conversion",
			input:    "Hello, World!",
			expected: "hello, world!",
		},
		{
			name:     "trim spaces",
			input:    "   Hello, World!   ",
			expected: "hello, world!",
		},
		{
			name:     "trim tabs and newlines",
			input:    "\tHello,\nWorld!\t",
			expected: "hello,\nworld!",
		},
		{
			name:     "multiple spaces preserved",
			input:    "Hello,   World!",
			expected: "hello,   world!",
		},
		{
			name:     "url decode space",
			input:    "hello%20world",
			expected: "hello world",
		},
		{
			name:     "url decode encoded payload",
			input:    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
			expected: "<script>alert(1)</script>",
		},
		{
			name:     "invalid url encoding",
			input:    "%ZZ",
			expected: "%zz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalize(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

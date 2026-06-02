package proxy

import (
	"net/http/httputil"
	"net/url"
)

func New(urlStr string) (*httputil.ReverseProxy, error) {

	backendURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	return httputil.NewSingleHostReverseProxy(
		backendURL,
	), nil
}

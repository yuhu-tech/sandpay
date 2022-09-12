package sandpay

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// HTTPClient is the interface for a http client.
type HTTPClient interface {
	// Do sends an HTTP request and returns an HTTP response.
	// Should use context to specify the timeout for request.
	Do(ctx context.Context, method, reqURL string, body []byte) (*http.Response, error)
}

type httpclient struct {
	client *http.Client
}

func (c *httpclient) Do(ctx context.Context, method, reqURL string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewBuffer(body))

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)

	if err != nil {
		// If the context has been canceled, the context's error is probably more useful.
		select {
		case <-ctx.Done():
			err = ctx.Err()
		default:
		}

		return nil, err
	}

	return resp, err
}

// NewDefaultHTTPClient returns a new http client with a default http.Client
func NewDefaultHTTPClient() HTTPClient {
	return &httpclient{
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 60 * time.Second,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:          0,
				MaxIdleConnsPerHost:   1000,
				MaxConnsPerHost:       1000,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}
}

// NewHTTPClient returns a new http client with a http.Client
func NewHTTPClient(client *http.Client) HTTPClient {
	return &httpclient{
		client: client,
	}
}

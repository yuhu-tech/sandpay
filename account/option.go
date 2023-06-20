package account

import "net/http"

// ClientOption 客户端配置项
type ClientOption func(c *Client)

// WithHTTPClient 自定义http.Client
func WithHTTPClient(cli *http.Client) ClientOption {
	return func(c *Client) {
		c.cli = cli
	}
}

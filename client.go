package sandpay

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Client 杉德支付客户端
type Client interface {
	// Do 请求杉德API
	Do(ctx context.Context, reqURL string, form url.Values) (*Data, error)

	// Form 生成统一的POST表单（用于API请求或前端表单提交）
	Form(method, productID string, body X, options ...HeadOption) (url.Values, error)

	// Verify 验证并解析杉德API结果或回调通知
	Verify(form url.Values) (*Data, error)
}

type client struct {
	mid    string
	prvKey *PrivateKey
	pubKey *PublicKey
	cli    HTTPClient
}

func (c *client) Do(ctx context.Context, reqURL string, form url.Values) (*Data, error) {
	resp, err := c.cli.Do(ctx, http.MethodPost, reqURL, []byte(form.Encode()), WithHTTPHeader("Content-Type", "application/x-www-form-urlencoded"))

	if err != nil {
		return nil, errors.Wrap(err, "do http request")
	}

	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, errors.Wrap(err, "read resp body")
	}

	query, err := url.QueryUnescape(string(b))

	if err != nil {
		return nil, errors.Wrap(err, "unescape resp body")
	}

	v, err := url.ParseQuery(query)

	if err != nil {
		return nil, errors.Wrap(err, "parse resp body")
	}

	return c.Verify(v)
}

func (c *client) Form(method, productID string, body X, options ...HeadOption) (url.Values, error) {
	data := &Data{
		Head: c.head(method, productID, options...),
		Body: body,
	}

	b, err := json.Marshal(data)

	if err != nil {
		return nil, errors.Wrap(err, "marshal form data")
	}

	sign, err := c.prvKey.Sign(crypto.SHA1, b)

	if err != nil {
		return nil, errors.Wrap(err, "build form sign")
	}

	form := url.Values{}

	form.Set("charset", "utf-8")
	form.Set("data", string(b))
	form.Set("signType", "01")
	form.Set("sign", base64.StdEncoding.EncodeToString(sign))

	return form, nil
}

func (c *client) Verify(form url.Values) (*Data, error) {
	sign, err := base64.StdEncoding.DecodeString(strings.Replace(form.Get("sign"), " ", "+", -1))

	if err != nil {
		return nil, errors.Wrap(err, "base64 decode form sign")
	}

	if err = c.pubKey.Verify(crypto.SHA1, []byte(form.Get("data")), sign); err != nil {
		return nil, errors.Wrap(err, "verify form sign")
	}

	data := new(Data)

	if err := json.Unmarshal([]byte(form.Get("data")), data); err != nil {
		return nil, errors.Wrap(err, "unmarshal form data")
	}

	return data, nil
}

func (c *client) head(method, productID string, options ...HeadOption) X {
	head := X{
		"version":     "1.0",
		"method":      method,
		"productId":   productID,
		"accessType":  "1",
		"mid":         c.mid,
		"channelType": "07",
		"reqTime":     time.Now().Format("20060102150405"),
	}

	for _, f := range options {
		f(head)
	}

	return head
}

// HeadOption 报文头配置项
type HeadOption func(h X)

// WithVersion 设置版本号：默认：1.0；功能产品号为微信小程序或支付宝生活号，对账单需获取营销优惠金额字段传：3.0
func WithVersion(v string) HeadOption {
	return func(h X) {
		h["version"] = v
	}
}

// WithPLMid 设置平台ID：接入类型为2时必填，在担保支付模式下填写核心商户号；在杉德宝平台终端模式下填写平台商户号
func WithPLMid(id string) HeadOption {
	return func(h X) {
		h["plMid"] = id
	}
}

// WithAccessType 设置接入类型：1 - 普通商户接入（默认）；2 - 平台商户接入
func WithAccessType(at string) HeadOption {
	return func(h X) {
		h["accessType"] = at
	}
}

// WithChannelType 设置渠道类型：07 - 互联网（默认）；08 - 移动端
func WithChannelType(ct string) HeadOption {
	return func(h X) {
		h["channelType"] = ct
	}
}

// ClientOption 客户端配置项
type ClientOption func(c *client)

// WithHTTPClient 自定义http.Client
func WithHTTPClient(cli *http.Client) ClientOption {
	return func(c *client) {
		c.cli = NewHTTPClient(cli)
	}
}

// Config 客户端配置
type Config struct {
	MID      string // 商户ID
	KeyFile  string // PEM格式（商户私钥）
	CertFile string // PEM格式（杉德公钥）
}

func NewClient(cfg *Config, options ...ClientOption) (Client, error) {
	prvKey, err := NewPrivateKeyFromPemFile(cfg.KeyFile)

	if err != nil {
		return nil, err
	}

	pubKey, err := NewPublicKeyFromDerFile(cfg.CertFile)

	if err != nil {
		return nil, err
	}

	c := &client{
		mid:    cfg.MID,
		prvKey: prvKey,
		pubKey: pubKey,
		cli:    NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c, nil
}

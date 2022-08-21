package sandpay

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

// Client 杉德支付客户端
type Client interface {
	// Do 请求杉德API
	Do(ctx context.Context, reqURL string, form url.Values) (X, error)

	// Form 生成统一的POST表单（用于API请求或前端表单提交）
	Form(method, productID string, body X) (url.Values, error)

	// Verify 验证并解析杉德API结果或回调通知
	Verify(result []byte) (X, error)
}

type client struct {
	mid    string
	prvKey *PrivateKey
	pubKey *PublicKey
	cli    HTTPClient
}

func (c *client) Do(ctx context.Context, reqURL string, form url.Values) (X, error) {
	resp, err := c.cli.Do(ctx, http.MethodPost, reqURL, []byte(form.Encode()), WithHTTPHeader("Content-Type", "application/x-www-form-urlencoded"))

	if err != nil {
		return nil, errors.Wrap(err, "do http request")
	}

	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, errors.Wrap(err, "read resp body")
	}

	return c.Verify(b)
}

func (c *client) Form(method, productID string, body X) (url.Values, error) {
	data := &Data{
		Head: c.header(method, productID),
		Body: body,
	}

	b, err := json.Marshal(data)

	if err != nil {
		return nil, errors.Wrap(err, "marshal req data")
	}

	sign, err := c.prvKey.Sign(crypto.SHA1, b)

	if err != nil {
		return nil, errors.Wrap(err, "build req sign")
	}

	form := url.Values{}

	form.Set("charset", "utf-8")
	form.Set("data", string(b))
	form.Set("signType", "01")
	form.Set("sign", base64.StdEncoding.EncodeToString(sign))

	return form, nil
}

func (c *client) Verify(result []byte) (X, error) {
	form, err := url.QueryUnescape(string(result))

	if err != nil {
		return nil, errors.Wrap(err, "unescape resp body")
	}

	v, err := url.ParseQuery(string(form))

	if err != nil {
		return nil, errors.Wrap(err, "parse resp body")
	}

	sign, err := base64.StdEncoding.DecodeString(strings.Replace(v.Get("sign"), " ", "+", -1))

	if err != nil {
		return nil, errors.Wrap(err, "base64 decode resp sign")
	}

	if err = c.pubKey.Verify(crypto.SHA1, []byte(v.Get("data")), sign); err != nil {
		return nil, errors.Wrap(err, "verify resp sign")
	}

	ret := gjson.Get(v.Get("data"), "head")

	if respCode := ret.Get("respCode").String(); respCode != OK {
		return nil, fmt.Errorf("[sandpay] %s | %s", respCode, ret.Get("respMsg").String())
	}

	data := new(Data)

	if err := json.Unmarshal([]byte(v.Get("data")), data); err != nil {
		return nil, errors.Wrap(err, "unmarshal resp data")
	}

	return data.Body, nil
}

func (c *client) header(method, productID string) X {
	return X{
		"version":     "1.0",
		"method":      method,
		"productId":   productID,
		"accessType":  "1",
		"mid":         c.mid,
		"channelType": "07",
		"reqTime":     time.Now().Format("20060102150405"),
	}
}

type ClientOption func(c *client)

func WithHTTPClient(cli *http.Client) ClientOption {
	return func(c *client) {
		c.cli = NewHTTPClient(cli)
	}
}

type Config struct {
	MID      string
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

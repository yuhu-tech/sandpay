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
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

type Client interface {
	Do(ctx context.Context, reqURL string, form url.Values) (X, error)
	Form(method, productID string, body X) (url.Values, error)
	Verify(result []byte) (X, error)
	Realname(ctx context.Context, reqURL, transCode string, data X) (X, error)
}

type client struct {
	mid    string
	aesKey string
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
	v, err := url.ParseQuery(string(result))

	if err != nil {
		return nil, errors.Wrap(err, "parse resp body")
	}

	if err = c.pubKey.Verify(crypto.SHA1, []byte(v.Get("data")), []byte(v.Get("sign"))); err != nil {
		return nil, errors.Wrap(err, "verify resp sign")
	}

	ret := gjson.Get(v.Get("data"), "head")

	if respCode := ret.Get("respCode").String(); respCode != OK {
		return nil, fmt.Errorf("[err] %s | %s", respCode, ret.Get("respMsg").String())
	}

	data := new(Data)

	if err := json.Unmarshal([]byte(v.Get("data")), data); err != nil {
		return nil, errors.Wrap(err, "unmarshal resp data")
	}

	return data.Body, nil
}

func (c *client) Realname(ctx context.Context, reqURL, transCode string, data X) (X, error) {
	encryptKey, err := c.pubKey.Encrypt([]byte(c.aesKey))

	if err != nil {
		return nil, errors.Wrap(err, "encrypt req aesKey")
	}

	b, err := json.Marshal(data)

	if err != nil {
		return nil, errors.Wrap(err, "marshal req data")
	}

	encryptData, err := NewECBCrypto([]byte(c.aesKey), PKCS5).Encrypt(b)

	if err != nil {
		return nil, errors.Wrap(err, "encrypt req data")
	}

	sign, err := c.prvKey.Sign(crypto.SHA1, b)

	if err != nil {
		return nil, errors.Wrap(err, "build req sign")
	}

	form := url.Values{}

	form.Set("transCode", transCode)
	form.Set("accessType", "0")
	form.Set("merId", c.mid)
	form.Set("encryptKey", base64.StdEncoding.EncodeToString(encryptKey))
	form.Set("encryptData", base64.StdEncoding.EncodeToString(encryptData))
	form.Set("sign", base64.StdEncoding.EncodeToString(sign))

	resp, err := c.cli.Do(ctx, http.MethodPost, reqURL, []byte(form.Encode()), WithHTTPHeader("Content-Type", "application/x-www-form-urlencoded"))

	if err != nil {
		return nil, errors.Wrap(err, "do http request")
	}

	defer resp.Body.Close()

	b, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, errors.Wrap(err, "read resp body")
	}

	v, err := url.ParseQuery(string(b))

	if err != nil {
		return nil, errors.Wrap(err, "parse resp body")
	}

	b, err = base64.StdEncoding.DecodeString(v.Get("encryptKey"))

	if err != nil {
		return nil, errors.Wrap(err, "base64 decode resp encryptKey")
	}

	respKey, err := c.prvKey.Decrypt([]byte(b))

	if err != nil {
		return nil, errors.Wrap(err, "decrypt resp aseKey")
	}

	b, err = base64.StdEncoding.DecodeString(v.Get("encryptData"))

	if err != nil {
		return nil, errors.Wrap(err, "base64 decode resp encryptData")
	}

	b, err = NewECBCrypto(respKey, PKCS5).Decrypt(b)

	if err != nil {
		return nil, errors.Wrap(err, "decrypt resp data")
	}

	if err = c.pubKey.Verify(crypto.SHA1, b, []byte(v.Get("sign"))); err != nil {
		return nil, errors.Wrap(err, "verify resp sign")
	}

	ret := gjson.ParseBytes(b)

	if respCode := ret.Get("respCode").String(); respCode != "0000" {
		return nil, fmt.Errorf("[err] %s | %s", respCode, ret.Get("respDesc").String())
	}

	var result X

	if err := json.Unmarshal(b, &result); err != nil {
		return nil, errors.Wrap(err, "unmarshal resp data")
	}

	return result, nil
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

func WithAESKey(aesKey string) ClientOption {
	return func(c *client) {
		c.aesKey = aesKey
	}
}

func WithHTTPClient(cli *http.Client) ClientOption {
	return func(c *client) {
		c.cli = NewHTTPClient(cli)
	}
}

type Config struct {
	MID      string
	PfxCert  string
	PfxPwd   string
	SandCert string
}

func NewClient(cfg *Config, options ...ClientOption) (Client, error) {
	prvKey, err := ParsePrivateKeyFromPfxFile(cfg.PfxCert, cfg.PfxPwd)

	if err != nil {
		return nil, err
	}

	pubKey, err := ParsePublicKeyFromDerFile(cfg.SandCert)

	if err != nil {
		return nil, err
	}

	c := &client{
		mid:    cfg.MID,
		aesKey: MD5(cfg.MID),
		prvKey: prvKey,
		pubKey: pubKey,
		cli:    NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c, nil
}

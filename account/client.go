package account

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/yuhu-tech/sandpay/util"
)

type Client struct {
	mid    string
	prvKey *util.PrivateKey
	pubKey *util.PublicKey
	cli    *http.Client
}

// Config 客户端配置
type Config struct {
	MID      string // 商户ID
	KeyFile  string // 商户私钥（PEM格式）
	KeyMode  util.RSAPaddingMode
	CertFile string // 杉德公钥（base64编码的PEM格式）
}

func NewClient(cfg *Config, options ...ClientOption) (*Client, error) {
	prvKey, err := util.NewPrivateKeyFromPemFile(cfg.KeyMode, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	pubKey, err := util.NewPublicKeyFromDerFile(cfg.CertFile)
	if err != nil {
		return nil, err
	}

	c := &Client{
		mid:    cfg.MID,
		prvKey: prvKey,
		pubKey: pubKey,
		cli: &http.Client{
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

	for _, f := range options {
		f(c)
	}

	return c, nil
}

// SandRequest 表示标准杉德请求体
type SandRequest struct {
	Data            string `json:"data"`
	Sign            string `json:"sign"`
	Mid             string `json:"mid"`
	SignType        string `json:"signType"`
	EncryptKey      string `json:"encryptKey"`
	CustomerOrderNo string `json:"customerOrderNo"`
	EncryptType     string `json:"encryptType"`
}

// SandResponse 杉德接口响应标准结构
type SandResponse struct {
	Data        string        `json:"data,omitempty"`
	Sign        string        `json:"sign,omitempty"`
	EncryptKey  string        `json:"encryptKey,omitempty"`
	Response    *sandResponse `json:"response,omitempty"`
	SignType    string        `json:"signType,omitempty"`
	EncryptType string        `json:"encryptType,omitempty"`
}

// sandResponse 结构内 response 字段的标准结构
type sandResponse struct {
	ResponseDesc    string `json:"responseDesc"`
	ResponseTime    string `json:"responseTime"`
	Mid             string `json:"mid"`
	SandSerialNo    string `json:"sandSerialNo"`
	ResponseStatus  string `json:"responseStatus"`
	CustomerOrderNo string `json:"customerOrderNo"`
	Version         string `json:"version"`
	ResponseCode    string `json:"responseCode"`
}

func (c *Client) buildRequestBody(orderNo string, req interface{}) ([]byte, error) {
	reqStr, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	aesKey := util.GenRandomStringByLength(16)
	plainValue := reqStr
	aesKeyBytes := []byte(aesKey)
	encryptValueBytes := util.AESEncryptECB(plainValue, aesKeyBytes)
	encryptValue := base64.StdEncoding.EncodeToString(encryptValueBytes)
	encrypt, err := c.pubKey.Encrypt(aesKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt aes key: %w", err)
	}
	sandEncryptKey := base64.StdEncoding.EncodeToString(encrypt)

	req2 := SandRequest{
		Data:            encryptValue,
		EncryptKey:      sandEncryptKey,
		EncryptType:     "AES",
		Mid:             c.mid,
		CustomerOrderNo: orderNo,
	}

	// 签名
	signBytes, err := c.prvKey.Sign(crypto.SHA1, []byte(req2.Data))
	if err != nil {
		return nil, fmt.Errorf("faield to sign content: %w", err)
	}
	req2.Sign = base64.StdEncoding.EncodeToString(signBytes)
	req2.SignType = "SHA1WithRSA"
	jsonBody, err := json.Marshal(req2)
	if err != nil {
		return nil, fmt.Errorf("faield to jsonBody signed body: %w", err)
	}
	return jsonBody, nil
}

func (c *Client) verifyResponse(resp *SandResponse) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("response is nil")
	}

	encryptKey, err := base64.StdEncoding.DecodeString(resp.EncryptKey)
	if err != nil {
		return nil, fmt.Errorf("decode response encrypt key error: %w", err)
	}

	aesKey, err := c.prvKey.Decrypt(encryptKey)
	if err != nil {
		return nil, fmt.Errorf("aesKey response data error: %w", err)
	}

	cryptoData, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("decode response data error: %w", err)
	}

	return util.AESDecryptECB(cryptoData, aesKey), nil
}

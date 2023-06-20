package account

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
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

// MemberInfoQueryRequest 用来构建 开户信息查询 接口的请求参数
type MemberInfoQueryRequest struct {
	BizUserNo       string `json:"bizUserNo"`
	CustomerOrderNo string `json:"customerOrderNo"`
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
	Data        json.RawMessage `json:"data,omitempty"`
	Sign        string          `json:"sign,omitempty"`
	EncryptKey  string          `json:"encryptKey,omitempty"`
	Response    *sandResponse   `json:"response,omitempty"`
	SignType    string          `json:"signType,omitempty"`
	EncryptType string          `json:"encryptType,omitempty"`
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

// MemberStatusQueryRequest 用来构建 会员状态查询 的请求参数
type MemberStatusQueryRequest struct {
	BizUserNo       string `json:"bizUserNo"`
	CustomerOrderNo string `json:"customerOrderNo"`
}

// MemberStatusQueryResponse 会员状态查询 响应参数
// UNUSED: 杉德响应的参数没有按照文档上来,该接口并没有返回这些参数
type MemberStatusQueryResponse struct {
	// BizUserNo 会员编号
	BizUserNo string `json:"bizUserNo" json:"bizUserNo"`
	// MemberStatus 会员状态, 00:正常 01:冻结 02:未激活 09:销户 11:风控冻结
	MemberStatus string `json:"memberStatus"`

	// MemberRegisterDate 会员注册日期 yyyyMMdd
	MemberRegisterDate string `json:"memberRegisterDate"`

	// MemberLevel 会员等级 00:普通用户 01:一类账户 02:二类账户 03:三类账户
	MemberLevel string `json:"memberLevel"`

	// PasswordSetupStatus 密码设置状态 00:未设置 01:已设置
	PasswordSetupStatus string `json:"passwordSetupStatus"`

	// FaceStatus 人脸识别状态 01:已识别 00:未识别
	FaceStatus string `json:"faceStatus"`

	// UploadStatus 证件影像上传状态 01:已上传 00:未上传
	UploadStatus string `json:"uploadStatus"`

	// CloseAccountInfo 销户域
	CloseAccountInfo string `json:"closeAccountInfo"`

	// CloseAccountTime 销户时间 yyyyMMddHHmmss
	CloseAccountTime string `json:"closeAccountTime"`

	// Remark 销户备注, 用户销户时填写的备注
	Remark string `json:"remark"`
}

// MemberStatusQuery 会员状态查询
// doc: https://open.sandpay.com.cn/product/detail/44241/44246/44407
func (c *Client) MemberStatusQuery(ctx context.Context, req MemberStatusQueryRequest) (*sandResponse, error) {
	jsonBody, err := c.buildRequestBody(req.CustomerOrderNo, req)
	if err != nil {
		return nil, fmt.Errorf("builld request body failed: %w", err)
	}
	// UAT: http://ceas-uat01.sand.com.cn/v4/elecaccount/ceas.elec.member.status.query
	URL := `https://cap.sandpay.com.cn/v4/elecaccount/ceas.elec.member.status.query`

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, URL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to new request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := c.cli.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	curResp := &sandResponse{}
	stdResp := &SandResponse{
		Response: curResp,
	}
	if err = json.Unmarshal(body, stdResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	if _, err = c.verifyResponse(stdResp); err != nil {
		return nil, fmt.Errorf("failed to verify response: %w", err)
	}

	return curResp, nil
}

// TransactionInfoQueryRequest 用来构建 交易订单查询 的请求参数
type TransactionInfoQueryRequest struct {
	// Mid 商户号, 杉德支付分配给接入商户的商户编号
	Mid string `json:"mid"`
	// CustomerOrderNo 商户订单号, 商户号下每次请求的唯一流水号
	CustomerOrderNo string `json:"customerOrderNo"`
	// OriCustomerOrderNo 原交易订单号
	OriCustomerOrderNo string `json:"oriCustomerOrderNo"`
	// OriPayeeCustomerOrderNo 原交易子订单号(非必填)
	OriPayeeCustomerOrderNo string `json:"oriPayeeCustomerOrderNo,omitempty"`
}

type TransactionInfoQueryResponse struct {
	// OriCustomerOrderNo 原付款申请订单号
	OriCustomerOrderNo string `json:"oriCustomerOrderNo"`
	// OriPayeeCustomerOrderNo 原收款子订单号
	OriPayeeCustomerOrderNo string `json:"oriPayeeCustomerOrderNo,omitempty"`
	// OrderAmt 订单金额
	OrderAmt float64 `json:"orderAmt"`
	// FeeAmt 手续费
	FeeAmt float64 `json:"feeAmt"`
	// OrderStatus 订单状态
	OrderStatus string `json:"orderStatus"`
	// AuthWay 鉴权方式
	AuthWay string `json:"authWay"`
	// Remark 备注
	Remark string `json:"remark,omitempty"`
	// GuaranteeStatus 担保状态
	GuaranteeStatus string `json:"guaranteeStatus,omitempty"`
	// RefundStatus 退货状态
	RefundStatus string `json:"refundStatus,omitempty"`
	// WithdrawStatus 提现状态
	WithdrawStatus string `json:"withdrawStatus,omitempty"`
	// FailureMsgs 交易失败原因
	FailureMsgs string `json:"failureMsgs,omitempty"`
	// DelayReceivedTime 预计到账时间
	DelayReceivedTime string `json:"delayReceivedTime,omitempty"`
}

// TransactionInfoQuery 交易订单查询
// doc: https://open.sandpay.com.cn/product/detail/44241/44373/44415
func (c *Client) TransactionInfoQuery(ctx context.Context, req TransactionInfoQueryRequest) (*TransactionInfoQueryResponse, error) {
	jsonBody, err := c.buildRequestBody(req.CustomerOrderNo, req)
	if err != nil {
		return nil, fmt.Errorf("builld request body failed: %w", err)
	}
	// UAT: https://ceas-uat01.sand.com.cn/v4/electrans/ceas.elec.trans.info.query
	URL := `https://cap.sandpay.com.cn/v4/electrans/ceas.elec.trans.info.query`

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, URL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to new request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	resp, err := c.cli.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	curResp := &sandResponse{}
	stdResp := &SandResponse{
		Response: curResp,
	}
	log.Printf("body: %s", body)
	if err = json.Unmarshal(body, stdResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	data, err := c.verifyResponse(stdResp)
	if err != nil {
		return nil, fmt.Errorf("failed to verify response: %w", err)
	}
	var realData TransactionInfoQueryResponse
	if err := json.Unmarshal(data, &realData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	return &realData, nil
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
	sign, err := base64.StdEncoding.DecodeString(resp.Sign)
	if err != nil {
		return nil, fmt.Errorf("decode response sign error: %w", err)
	}
	if err = c.pubKey.Verify(crypto.SHA1, []byte(resp.Data), sign); err != nil {
		return nil, fmt.Errorf("verify response sign error: %w", err)
	}

	encryptKey, err := base64.StdEncoding.DecodeString(resp.EncryptKey)
	if err != nil {
		return nil, fmt.Errorf("decode response data error: %w", err)
	}

	aesKey, err := c.prvKey.Decrypt(encryptKey)
	if err != nil {
		return nil, fmt.Errorf("aesKey response data error: %w", err)
	}
	cryptoData, err := base64.StdEncoding.DecodeString(string(resp.Data))
	if err != nil {
		return nil, fmt.Errorf("decode response data error: %w", err)
	}

	return util.AESDecryptECB(cryptoData, aesKey), nil
}

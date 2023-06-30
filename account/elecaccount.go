package account

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
)

// API会员相关接口

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

// AccountBalanceQueryRequest 查询账户余额 的请求参数
type AccountBalanceQueryRequest struct {
	// BizUserNo 会员编号, 杉德系统中该商户下用户唯一编号
	BizUserNo string `json:"bizUserNo"`

	// AccountType 账户类型
	// 01: 电子支付户
	// 02: 权益账户
	// 03: 奖励金户
	AccountType string `json:"accountType,omitempty"`

	CustomerOrderNo string `json:"customerOrderNo"`
}

// AccountBalanceQueryResponse 查询账户余额 响应参数
type AccountBalanceQueryResponse struct {
	// Mid 商户号, 杉德支付分配给接入商户的商户编号
	Mid string `json:"mid"`

	// CustomerOrderNo 商户订单号,商户号下每次请求的唯一流水号
	CustomerOrderNo string `json:"customerOrderNo"`

	// BizUserNo 会员编号, 杉德系统中该商户下用户唯一编号
	BizUserNo string `json:"bizUserNo"`

	// AccountList 账户信息结果
	AccountList []accountBalanceQueryResponseAccountListItem `json:"accountList"`
}

type accountBalanceQueryResponseAccountListItem struct {
	// AccountName 账户名称
	AccountName string `json:"accountName"`

	// AccountType 账户类型
	// 01: 支付电子户
	// 02: 权益账户
	// 03: 奖励金户
	AccountType string `json:"accountType"`

	// AvailableBal 可用金额
	AvailableBal *big.Float `json:"availableBal,omitempty"`

	// FrozenBal 冻结金额
	FrozenBal *big.Float `json:"frozenBal,omitempty"`

	// AccountStatus 账户状态
	// 00: 正常
	// 01: 冻结
	// 09: 销户
	AccountStatus string `json:"accountStatus,omitempty"`
}

// AccountBalanceQuery 个人账户余额查询
// doc: https://open.sandpay.com.cn/product/detail/44241/44246/44256
func (c *Client) AccountBalanceQuery(ctx context.Context, req AccountBalanceQueryRequest) (*AccountBalanceQueryResponse, error) {
	jsonBody, err := c.buildRequestBody(req.CustomerOrderNo, req)
	if err != nil {
		return nil, fmt.Errorf("builld request body failed: %w", err)
	}

	// 测试环境: https://ceas-uat01.sand.com.cn/v4/elecaccount/ceas.elec.account.balance.query
	URL := `https://cap.sandpay.com.cn/v4/elecaccount/ceas.elec.account.balance.query`

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
	data, err := c.verifyResponse(stdResp)
	if err != nil {
		return nil, fmt.Errorf("failed to verify response: %w", err)
	}

	var realData AccountBalanceQueryResponse
	if err := json.Unmarshal(data, &realData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	return &realData, nil
}

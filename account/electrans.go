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

// 交易相关接口

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

// TransactionInfoQueryResponse 交易订单查询 响应参数
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

type TransactionGuaranteeConfirmRequest struct {
	// OriCustomerOrderNo 原付款申请订单号
	OriCustomerOrderNo string `json:"oriCustomerOrderNo"`
	// Mid 商户号
	Mid string `json:"mid"`
	// CustomerOrderNo 商户订单号, 商户号下每次请求的唯一流水号
	CustomerOrderNo string `json:"customerOrderNo"`
	// OriPayeeCustomerOrderNo 原收款订单号
	OriPayeeCustomerOrderNo string `json:"oriPayeeCustomerOrderNo,omitempty"`
	// OriOrderAmt 原订单金额
	OriOrderAmt *big.Float `json:"oriOrderAmt"`
	// OperationType 操作类型
	// GUARANTEE_CONFIRM 担保确认
	// GUARANTEE_CANCEL 担保取消
	OperationType string `json:"operationType"`
	// Remark 备注
	Remark string `json:"remark,omitempty"`
}

type TransactionGuaranteeConfirmResponse struct {
	// OrderStatus 订单状态
	// 00 成功
	// 01 处理中
	// 02 失败
	OrderStatus string `json:"orderStatus"`
}

// TransactionGuaranteeConfirm 担保确认
// doc: https://open.sandpay.com.cn/product/detail/44241/44373/44414
func (c *Client) TransactionGuaranteeConfirm(ctx context.Context, req TransactionGuaranteeConfirmRequest) (*TransactionGuaranteeConfirmResponse, error) {
	jsonBody, err := c.buildRequestBody(req.CustomerOrderNo, req)
	if err != nil {
		return nil, fmt.Errorf("builld request body failed: %w", err)
	}

	// 测试环境：https://ceas-uat01.sand.com.cn/v4/electrans/ceas.elec.trans.guarantee.confirm
	URL := `https://cap.sandpay.com.cn/v4/electrans/ceas.elec.trans.guarantee.confirm`

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
	var realData TransactionGuaranteeConfirmResponse
	if err := json.Unmarshal(data, &realData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	return &realData, nil
}

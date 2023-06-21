package account

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// 辅助类接口

// 交易结果异步通知

// TransactionResultNotifyResponse 回调内可能携带的参数
type TransactionResultNotifyResponse struct {
	// Mid 商户号
	Mid string `json:"mid"`
	// Amount 订单金额
	Amount float64 `json:"amount,omitempty"`
	// FeeAmt 商户手续费
	FeeAmt int `json:"feeAmt,omitempty"`
	// OrderNo 订商户订单号
	OrderNo string `json:"orderNo"`
	// OrderStatus 订单状态, 00:成功
	OrderStatus string `json:"orderStatus"`
	// PayeeList 收款明细域
	PayeeList []PayeeList `json:"payeeList"`
	// PayerInfo 收款方
	PayerInfo PayerInfo `json:"payerInfo"`
	// RespCode 响应码
	RespCode string `json:"respCode"`
	// RespMsg 响应描述
	RespMsg string `json:"respMsg"`
	// RespTime 响应时间, yyyyMMddHHmmss
	RespTime string `json:"respTime"`

	// SandSerialNo 杉德流水号
	// DEPOSIT 充值
	// B2C_TRANSFER B2C转账
	// C2C_TRANSFER C2C转账
	// C2B_TRANSFER C2B转账
	// WITHDRAW 提现
	// RETURN_CARD 退卡
	// HB_SEND 红包发放
	// TRANSFER_RETURN 转账退回
	// CONFIRM_RECEIPT 确认收款
	// PAYMENT 会员付款
	// PROTOCOL_PAY 协议扣款
	SandSerialNo string `json:"sandSerialNo"`
	// TransType 交易类型
	TransType string `json:"transType"`
	// UserFeeAmt 用户手续费
	UserFeeAmt int `json:"userFeeAmt"`
}

type PayeeList struct {
	BizUserNo            string  `json:"bizUserNo"`
	PayeeAmt             float64 `json:"payeeAmt"`
	PayeeCustomerOrderNo string  `json:"payeeCustomerOrderNo"`
	Remark               string  `json:"remark"`
	SandSerialNo         string  `json:"sandSerialNo"`
}
type PayerInfo struct {
	PayerAccName string `json:"payerAccName"`
	PayerAccNo   string `json:"payerAccNo"`
	PayerMemID   string `json:"payerMemID"`
}

func (c *Client) TransactionResultNotify(ctx context.Context, reqData []byte) (*TransactionResultNotifyResponse, error) {
	stdResp := &SandResponse{
		Response: new(sandResponse),
	}
	if err := json.Unmarshal(reqData, stdResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request data: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(stdResp.Sign)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 sign: %w", err)
	}
	if err := c.pubKey.Verify(crypto.SHA1, []byte(stdResp.Data), sig); err != nil {
		return nil, fmt.Errorf("failed to verify data: %w", err)
	}

	var resp TransactionResultNotifyResponse
	if err := json.Unmarshal([]byte(stdResp.Data), &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data to return value: %w", err)
	}
	return &resp, nil
}

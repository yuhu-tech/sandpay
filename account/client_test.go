package account

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"testing"
	"time"

	"github.com/yuhu-tech/sandpay/util"
)

func getTestClient() (*Client, error) {
	mid := `68888XXXXXXXX`
	keyFile := "../cert/68888XXXXXXXX.pem"
	keyMode := util.RSA_PKCS8
	certFile := "../cert/sand_pro.pem"
	client, err := NewClient(&Config{
		MID:      mid,
		KeyFile:  keyFile,
		KeyMode:  keyMode,
		CertFile: certFile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %v", err.Error())
	}
	return client, nil
}

func TestMemberStatusQuery(t *testing.T) {
	client, err := getTestClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err.Error())
	}
	ctx := context.Background()
	resp, err := client.MemberStatusQuery(ctx, MemberStatusQueryRequest{
		// BizUserNo: "123",
		BizUserNo:       "cl1u3wpjg9dok0770rn8ls0u1",
		CustomerOrderNo: strconv.Itoa(int(time.Now().Unix())),
	})
	if err != nil {
		t.Fatalf("failed to query member status: %v", err.Error())
	}
	t.Logf("data: %#v", resp)
}

func TestTransactionInfoQuery(t *testing.T) {
	client, err := getTestClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err.Error())
	}
	ctx := context.Background()
	resp, err := client.TransactionInfoQuery(ctx, TransactionInfoQueryRequest{
		Mid:                "68888XXXXXXXX",
		CustomerOrderNo:    fmt.Sprintf("%v", time.Now().UnixNano()),
		OriCustomerOrderNo: "466044717667237897",
	})
	if err != nil {
		t.Fatalf("failed to query member status: %v", err.Error())
	}
	t.Logf("data: %#v", resp)
}

func TestVerifyResponse(t *testing.T) {
	client, err := getTestClient()
	if err != nil {
		t.Fatalf("failed to get client: %v", err.Error())
	}
	var resp SandResponse
	JSON := `{}`
	if err = json.Unmarshal([]byte(JSON), &resp); err != nil {
		t.Fatalf("failed to unmarshal data: %v", err.Error())
	}

	data, err := client.verifyResponse(&resp)
	if err != nil {
		t.Fatalf("failed to verify response: %v", err.Error())
	}

	log.Printf("data: %s", data)
}

func TestResponseS(t *testing.T) {
	client, err := getTestClient()
	if err != nil {
		t.Fatalf("failed to get client: %v", err.Error())
	}
	reqData := []byte(`{"charset":"UTF-8","data":{},"extend":"","sign":"","signType":"SHA1WithRSA"}`)
	ctx := context.TODO()
	res, err := client.TransactionResultNotify(ctx, reqData)
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Logf("%#v", res)
}

func TestTransactionResultNotify(t *testing.T) {
	client, err := getTestClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err.Error())
	}
	ctx := context.Background()
	data := `{}`
	resp, err := client.TransactionResultNotify(ctx, []byte(data))
	if err != nil {
		t.Fatalf("failed to query member status: %v", err.Error())
	}
	t.Logf("data: %#v", resp)
}

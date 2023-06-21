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
	t.Logf("enKey: %#v", resp.EncryptKey)
	data, err := client.verifyResponse(&resp)
	if err != nil {
		t.Fatalf("failed to verify response: %v", err.Error())
	}

	log.Printf("data: %s", data)
}

func TestResponse(t *testing.T) {
	client, err := getTestClient()
	if err != nil {
		t.Fatalf("failed to get client: %v", err.Error())
	}
	reqData := []byte(`{"charset":"UTF-8","data":"{\"amount\":0.18,\"feeAmt\":0,\"mid\":\"6888805120378\",\"orderNo\":\"466081972800778249\",\"orderStatus\":\"00\",\"payeeList\":[{\"bizUserNo\":\"6888805120378\",\"payeeAmt\":0.01,\"payeeCustomerOrderNo\":\"466081972800778249-2\",\"remark\":\"订单[466081972800778249]交易手续费\",\"sandSerialNo\":\"CEAS2023062110010000371350\"},{\"bizUserNo\":\"cl1u3wpjg9dok0770rn8ls0u1\",\"payeeAmt\":0.17,\"payeeCustomerOrderNo\":\"466081972800778249-1\",\"remark\":\"Frog_#5收入\",\"sandSerialNo\":\"CEAS2023062110010000371351\"}],\"payerInfo\":{\"payerAccName\":\"陈清\",\"payerAccNo\":\"200841000020004\",\"payerMemID\":\"ckp4vydancim10762jrxjpzf7\"},\"respCode\":\"00000\",\"respMsg\":\"成功\",\"respTime\":\"20230621162845\",\"sandSerialNo\":\"CEAS23062115140702100000135300\",\"transType\":\"PAYMENT\",\"userFeeAmt\":0}","extend":"","sign":"VX5l8PiawO15KTquviINzlMpaLNuJxNom7865XkcMm9lKWmEbm8eKGkjULK5w955aRYdP7kPSghF83NqwppWN7gpIIw8uZ2znj1cUmZfsc7icA1iMmxk3SOB49fSXLfrV5mmQspU2u6v+UlcoZDwOSjt4Z4vTP2OJFsZdfWWY08xdheU+KO7sjh5lph74W4n4FiOpbzsqPT/zIvkcYS5W6dbiwiA+iwGGbcSC6ZQ7jGgWowhVIP/TZHKu4X6Iyzh/Cyrt9un4wmh97hAn/O+hdLqB9zl/PcQSecZ9mb78TnpcwkSCt/7l/6IMimYt31L9t5zOcgzbfviNrOi8vMeaw==","signType":"SHA1WithRSA"}`)
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
	data := `{"charset":"UTF-8","data":"{\"amount\":0.18,\"feeAmt\":0,\"mid\":\"6888805120378\",\"orderNo\":\"466081972800778249\",\"orderStatus\":\"00\",\"payeeList\":[{\"bizUserNo\":\"6888805120378\",\"payeeAmt\":0.01,\"payeeCustomerOrderNo\":\"466081972800778249-2\",\"remark\":\"订单[466081972800778249]交易手续费\",\"sandSerialNo\":\"CEAS2023062110010000371350\"},{\"bizUserNo\":\"cl1u3wpjg9dok0770rn8ls0u1\",\"payeeAmt\":0.17,\"payeeCustomerOrderNo\":\"466081972800778249-1\",\"remark\":\"Frog_#5收入\",\"sandSerialNo\":\"CEAS2023062110010000371351\"}],\"payerInfo\":{\"payerAccName\":\"陈清\",\"payerAccNo\":\"200841000020004\",\"payerMemID\":\"ckp4vydancim10762jrxjpzf7\"},\"respCode\":\"00000\",\"respMsg\":\"成功\",\"respTime\":\"20230621162845\",\"sandSerialNo\":\"CEAS23062115140702100000135300\",\"transType\":\"PAYMENT\",\"userFeeAmt\":0}","extend":"","sign":"VX5l8PiawO15KTquviINzlMpaLNuJxNom7865XkcMm9lKWmEbm8eKGkjULK5w955aRYdP7kPSghF83NqwppWN7gpIIw8uZ2znj1cUmZfsc7icA1iMmxk3SOB49fSXLfrV5mmQspU2u6v+UlcoZDwOSjt4Z4vTP2OJFsZdfWWY08xdheU+KO7sjh5lph74W4n4FiOpbzsqPT/zIvkcYS5W6dbiwiA+iwGGbcSC6ZQ7jGgWowhVIP/TZHKu4X6Iyzh/Cyrt9un4wmh97hAn/O+hdLqB9zl/PcQSecZ9mb78TnpcwkSCt/7l/6IMimYt31L9t5zOcgzbfviNrOi8vMeaw==","signType":"SHA1WithRSA"}`
	resp, err := client.TransactionResultNotify(ctx, []byte(data))
	if err != nil {
		t.Fatalf("failed to query member status: %v", err.Error())
	}
	t.Logf("data: %#v", resp)
}

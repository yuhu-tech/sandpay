package acceptance

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/yuhu-tech/sandpay/util"
)

func TestMemberStatusQuery(t *testing.T) {
	mid := `68888XXXXXXXX`
	keyFile := "../cert/68888XXXXXXXX.pem"
	keyMode := util.RSA_PKCS8
	certFile := "../cert/sand.pem"
	client, err := NewClient(&Config{
		MID:      mid,
		KeyFile:  keyFile,
		KeyMode:  keyMode,
		CertFile: certFile,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err.Error())
	}
	// ctx := context.Background()
	form, err := client.Form("sandpay.trade.query", "00000001", X{
		"orderCode": strconv.Itoa(int(time.Now().Unix())),
	})
	if err != nil {
		t.Fatalf("failed to build form: %v", err.Error())
	}
	do, err := client.Do(context.Background(), `https://cashier.sandpay.com.cn/gateway/api/order/query`, form)
	if err != nil {
		t.Fatalf("failed to query member status: %v", err.Error())
	}
	t.Logf("content: %#v", do)
}

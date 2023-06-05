package acceptance

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/yuhu-tech/sandpay/util"
)

func TestMemberStatusQuery(t *testing.T) {
	mid := `6888805AB0378`
	keyFile := "../cert/6888805AB0378.pem"
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

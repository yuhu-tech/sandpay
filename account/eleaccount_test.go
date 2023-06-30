package account

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestAccountBalanceQuery(t *testing.T) {
	client, err := getTestClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err.Error())
	}
	ctx := context.Background()
	resp, err := client.AccountBalanceQuery(ctx, AccountBalanceQueryRequest{
		BizUserNo:       "ckp4vydancim10762jrxjpzf7",
		CustomerOrderNo: fmt.Sprintf("%d", time.Now().Unix()),
	})

	t.Logf("%#v", resp)
}

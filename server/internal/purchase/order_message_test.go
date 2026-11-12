package purchase

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ovh-buy/server/internal/types"
)

func TestAutoPayMessageDoesNotClaimPaymentSucceeded(t *testing.T) {
	msg := BuildOrderSuccessMessage(&types.QueueItem{AutoPay: true}, "123", "")
	if !strings.Contains(msg, "已请求") || !strings.Contains(msg, "核对扣款是否成功") || strings.Contains(msg, "尚未付款") || strings.Contains(msg, "已按惯例放弃") {
		t.Fatal(msg)
	}
}

// 这是整个系统里唯一一条"你花钱了"的消息,措辞必须能单独审。
func TestDumpOrderMessages(t *testing.T) {
	item := &types.QueueItem{
		ID:         "a1b2c3d4-1111-2222-3333",
		PlanCode:   "24ska01",
		Datacenter: "waw",
		Options:    []string{"ram-32g-ecc-2400", "softraid-2x2000sa"},
	}
	url := "https://manager.eu.ovhcloud.com/dedicated/#/billing/order?orderId=108523471"

	fmt.Println("\n════════ 抢购成功（订单待付款）════════")
	fmt.Println(BuildOrderSuccessMessage(item, "108523471", url))

	fmt.Println("\n════════ 拿不到控制面板链接时 ════════")
	fmt.Println(BuildOrderSuccessMessage(item, "108523471", ""))
}

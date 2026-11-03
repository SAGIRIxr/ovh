package purchase

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovh-buy/server/internal/app"
	"github.com/ovh-buy/server/internal/config"
	"github.com/ovh-buy/server/internal/db"
	"github.com/ovh-buy/server/internal/logger"
	"github.com/ovh-buy/server/internal/storage"
	"github.com/ovh-buy/server/internal/types"
)

// 手填 FQN 时只认这一条组合:别的组合有货不能下单,这条有货才进购物车。
func TestPurchaseHonorsExplicitFQN(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, tc := range []struct {
		name, fqn  string
		options    []string
		expectCart bool
	}{
		{"other combo in stock", "27skleb01-v1.ram-64g-ecc-2400.softraid-2x450nvme", nil, false},
		{"exact combo in stock", "27skleb01-v1.ram-32g-ecc-2400.softraid-2x450nvme", nil, true},
		{"case insensitive", "27SKLEB01-v1.RAM-32g-ecc-2400.softraid-2x450nvme", nil, true},
		{"with full option codes", "27skleb01-v1.ram-32g-ecc-2400.softraid-2x450nvme",
			[]string{"bandwidth-500-27skle", "ram-32g-ecc-2400-27skleb01-v1", "softraid-2x450nvme-27skleb01-v1"}, true},
		{"no fqn keeps old behaviour", "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database, err := db.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			lg := logger.New(filepath.Join(dir, "test.log"), slog.New(slog.NewTextHandler(io.Discard, nil)))
			st := app.NewState(storage.Paths{DataDir: dir}, config.New(database), lg, database)
			st.Accounts = []types.OVHAccount{{ID: "eu", Endpoint: "ovh-eu", Zone: "FR", AppKey: "test", AppSecret: "test", ConsumerKey: "test"}}
			carts := 0
			transport := preorderTransport(func(r *http.Request) (*http.Response, error) {
				body, status := "{}", http.StatusOK
				switch {
				case strings.HasSuffix(r.URL.Path, "/auth/time"):
					body = fmt.Sprint(time.Now().Unix())
				case strings.Contains(r.URL.Path, "/dedicated/server/datacenter/availabilities"):
					body = `[{"fqn":"27skleb01-v1.ram-32g-ecc-2400.softraid-2x450nvme","datacenters":[{"datacenter":"gra","availability":"1H-low"}]},
					         {"fqn":"27skleb01-v1.ram-64g-ecc-2400.softraid-2x450nvme","datacenters":[{"datacenter":"gra","availability":"unavailable"}]}]`
				case strings.HasSuffix(r.URL.Path, "/order/cart"):
					carts++
					status, body = http.StatusBadRequest, `{"message":"test stops at cart creation"}`
				default:
					return nil, fmt.Errorf("unexpected test request: %s", r.URL)
				}
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			http.DefaultTransport = transport
			client, err := st.OVH.ClientFor("eu")
			if err != nil {
				t.Fatal(err)
			}
			client.Client = &http.Client{Transport: transport}
			item := &types.QueueItem{ID: "f", AccountID: "eu", PlanCode: "27skleb01-v1", Datacenter: "gra",
				MaxRetries: 1, Options: tc.options, FQN: tc.fqn}
			outcome := PurchaseServer(context.Background(), st, item)
			// 锁定的组合没货时仍会为它预热购物车(carts 也会是 1),但必须停在「等库存」,
			// 不能拿有货的另一套组合去下单
			if tc.expectCart && (carts != 1 || outcome.WaitingForStock) {
				t.Fatalf("expected to order the in-stock combo: %+v carts=%d", outcome, carts)
			}
			if !tc.expectCart && (!outcome.WaitingForStock || outcome.Fatal || outcome.Attempted) {
				t.Fatalf("other combo in stock must be treated as unavailable: %+v carts=%d", outcome, carts)
			}
		})
	}
}

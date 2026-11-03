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

// 三个大区都查不到记录的型号(还没上架的新品):普通任务判死,强制入队的任务按无货继续等。
func TestForceKeepsUnlistedPlanAlive(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%v", force), func(t *testing.T) {
			dir := t.TempDir()
			database, err := db.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			lg := logger.New(filepath.Join(dir, "test.log"), slog.New(slog.NewTextHandler(io.Discard, nil)))
			st := app.NewState(storage.Paths{DataDir: dir}, config.New(database), lg, database)
			st.Accounts = []types.OVHAccount{{ID: "eu", Endpoint: "ovh-eu", Zone: "PT", AppKey: "test", AppSecret: "test", ConsumerKey: "test"}}
			transport := preorderTransport(func(r *http.Request) (*http.Response, error) {
				body := "{}"
				switch path := r.URL.Path; {
				case strings.HasSuffix(path, "/auth/time"):
					body = fmt.Sprint(time.Now().Unix())
				case strings.Contains(path, "/order/catalog/public/eco"):
					body = `{"plans":[{"planCode":"24sk202"}]}`
				case strings.Contains(path, "/dedicated/server/datacenter/availabilities"):
					body = `[]`
				default:
					return nil, fmt.Errorf("unexpected fixture request: %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			http.DefaultTransport = transport
			client, err := st.OVH.ClientFor("eu")
			if err != nil {
				t.Fatal(err)
			}
			client.Client = &http.Client{Transport: transport}
			item := &types.QueueItem{ID: "force-task", AccountID: "eu", PlanCode: "26new-rumor", Datacenter: "gra", Force: force}
			outcome := PurchaseServer(context.Background(), st, item)
			if force && (outcome.Fatal || outcome.Attempted) {
				t.Fatalf("强制入队的未上架型号不该被判死: %+v", outcome)
			}
			if !force && !outcome.Fatal {
				t.Fatalf("普通任务查不到型号应判死: %+v", outcome)
			}
		})
	}
}

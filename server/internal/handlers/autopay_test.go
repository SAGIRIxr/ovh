package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/ovh-buy/server/internal/types"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAutoPayQueuePolicyPersists(t *testing.T) {
	previous := http.DefaultTransport
	http.DefaultTransport = queuePreorderTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"plans":[{"planCode":"plan"}]}`)), Request: r}, nil
	})
	defer func() { http.DefaultTransport = previous }()
	state, _ := newWatchTestMonitor(t)
	state.Accounts = []types.OVHAccount{{ID: "eu", Endpoint: "ovh-eu", Zone: "PAY-TEST"}, {ID: "eu2", Endpoint: "ovh-eu", Zone: "PAY-TEST"}}
	router := gin.New()
	router.POST("/queue", AddQueueItem(state))
	router.PUT("/queue/:id", UpdateQueueItem(state))
	send := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		fields        string
		pay, fallback bool
	}{
		{``, false, false}, {`,"autoPay":true`, true, false}, {`,"autoPay":true,"couponFallback":true`, true, true}, {`,"couponFallback":true`, false, false},
	} {
		before := len(state.Queue)
		w := send("POST", "/queue", `{"account_id":"eu","account_ids":["eu","eu2"],"planCode":"plan","datacenters":["gra"],"quantity":1,"purchaseMode":"total","coupon":"SAVE"`+tc.fields+`}`)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		rows, err := state.DB.ListQueue()
		if err != nil || len(rows) != before+2 {
			t.Fatal(rows, err)
		}
		for _, row := range rows[before:] {
			if row.AutoPay != tc.pay || row.CouponFallback != tc.fallback || row.GroupLimit != 1 {
				t.Fatalf("payment intent lost: %+v", row)
			}
		}
	}
	state.Queue[0].Status = "paused"
	if err := state.DB.ReplaceQueue(state.Queue); err != nil {
		t.Fatal(err)
	}
	w := send("PUT", "/queue/"+state.Queue[0].ID, `{"datacenter":"gra","retryInterval":17,"autoPay":true,"couponFallback":true,"coupon":"SAVE","duration":"P12M"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	rows, err := state.DB.ListQueue()
	if err != nil || !rows[0].AutoPay || !rows[0].CouponFallback || rows[0].Status != "paused" || rows[0].Duration != "P12M" {
		t.Fatal(rows, err)
	}
}

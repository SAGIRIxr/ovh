package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/ovh-buy/server/internal/types"
)

// GET /api/settings 不能再下发 Telegram Token / Webhook / 老 OVH 凭据的明文;
// 前端把掩码原样存回来时旧值要保住,填了新值则替换。
func TestSettingsMaskSecretsAndKeepOnSave(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newTGTestState(t)
	orig := types.Config{
		AppKey: "legacy-app-key-123", AppSecret: "legacy-secret-456", ConsumerKey: "legacy-ck-789",
		TgToken: "123456:ABCDEFtokenvalue", TgChatID: "42",
		NotifyWebhookURL: "https://hook.example/path?token=supersecret",
	}
	if err := s.Config.Set(orig); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/api/settings", GetSettings(s))
	r.POST("/api/settings", SaveSettings(s))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	body := w.Body.String()
	for _, secret := range []string{orig.AppKey, orig.AppSecret, orig.ConsumerKey, orig.TgToken, "supersecret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("settings 响应泄露了 %q: %s", secret, body)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("敏感响应要 no-store")
	}

	// 原样存回(只改 Chat ID)
	var got types.Config
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	got.TgChatID = "43"
	payload, _ := json.Marshal(got)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(string(payload))))
	if w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	cur := s.Config.Get()
	if cur.TgToken != orig.TgToken || cur.AppSecret != orig.AppSecret || cur.NotifyWebhookURL != orig.NotifyWebhookURL || cur.TgChatID != "43" {
		t.Fatalf("掩码存回后旧值丢了: %+v", cur)
	}

	// 填新值 / 清空要生效
	got.TgToken = "999:newtoken"
	got.NotifyWebhookURL = ""
	payload, _ = json.Marshal(got)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(string(payload))))
	if cur = s.Config.Get(); cur.TgToken != "999:newtoken" || cur.NotifyWebhookURL != "" {
		t.Fatalf("新值没生效: %+v", cur)
	}
}

func TestPairURLHonorsHTTPSProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		proto, base, want string
	}{
		{"", "", "http://panel.example/api/app/pair#ABC"},
		{"https", "", "https://panel.example/api/app/pair#ABC"},
		{"https, http", "", "https://panel.example/api/app/pair#ABC"},
		{"http", "https://pub.example/", "https://pub.example/api/app/pair#ABC"},
	} {
		t.Setenv("PUBLIC_BASE_URL", tc.base)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "http://panel.example/api/app/pairing-code", nil)
		if tc.proto != "" {
			c.Request.Header.Set("X-Forwarded-Proto", tc.proto)
		}
		if got := pairURL(c, "ABC"); got != tc.want {
			t.Fatalf("proto=%q base=%q: got %s want %s", tc.proto, tc.base, got, tc.want)
		}
	}
}

// 空码 / 超大请求体也要算失败次数,不能无限次白打免鉴权接口
func TestRedeemPairingRejectsJunkAndCountsIt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newTGTestState(t)
	r := gin.New()
	r.POST("/api/app/pair", RedeemPairingCode(s))
	limited := false
	for i := 0; i < 20; i++ {
		big := `{"deviceName":"` + strings.Repeat("x", 1<<20) + `"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/app/pair", strings.NewReader(big))
		req.RemoteAddr = "203.0.113.7:1234"
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("垃圾请求应 400,得 %d", w.Code)
		}
	}
	if !limited {
		t.Fatal("连续空码请求应触发限流")
	}
}

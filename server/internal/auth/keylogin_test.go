package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestKeyLoginDisabledAndInternalToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ResetAuthFailures()
	disabled := true
	r := gin.New()
	r.Use(Middleware(Config{
		APIKey: "correct-key", Enabled: true, WhitelistPaths: DefaultWhitelist(),
		KeyLoginDisabled: func() bool { return disabled },
		InternalToken:    "internal-secret",
		WebSessionValid:  func(tok string) (int64, bool) { return 1, tok == "good-session" },
	}))
	r.GET("/api/stats", func(c *gin.Context) { c.Status(200) })
	r.POST("/api/internal/monitor/price", func(c *gin.Context) { c.Status(200) })
	do := func(method, path string, h map[string]string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		for k, v := range h {
			req.Header.Set(k, v)
		}
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := do("GET", "/api/stats", map[string]string{"X-API-Key": "correct-key"}); code != 401 {
		t.Fatalf("关闭后正确的访问密钥也不能登录,得 %d", code)
	}
	// 关闭状态下猜密钥不计数:不该把这个 IP 锁住
	for i := 0; i < MaxAuthFailures+2; i++ {
		do("GET", "/api/stats", map[string]string{"X-API-Key": "guess"})
	}
	if blocked, _ := authBlocked("192.0.2.1", time.Now()); blocked {
		t.Fatal("关闭后 X-API-Key 不该再参与计数")
	}
	if code := do("GET", "/api/stats", map[string]string{"Authorization": "Bearer good-session"}); code != 200 {
		t.Fatalf("通行证会话照常能用,得 %d", code)
	}
	if code := do("POST", "/api/internal/monitor/price", map[string]string{"X-Internal-Token": "internal-secret"}); code != 200 {
		t.Fatalf("内部令牌应能调内部接口,得 %d", code)
	}
	if code := do("GET", "/api/stats", map[string]string{"X-Internal-Token": "internal-secret"}); code != 401 {
		t.Fatalf("内部令牌不能用在别的接口,得 %d", code)
	}
	if code := do("POST", "/api/internal/monitor/price", map[string]string{"X-Internal-Token": "wrong"}); code != 401 {
		t.Fatalf("内部令牌不对应拒绝,得 %d", code)
	}
	disabled = false
	if code := do("GET", "/api/stats", map[string]string{"X-API-Key": "correct-key"}); code != 200 {
		t.Fatalf("恢复后访问密钥应能登录,得 %d", code)
	}
}

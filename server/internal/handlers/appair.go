package handlers

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ovh-buy/server/internal/app"
	"github.com/ovh-buy/server/internal/auth"
	"github.com/ovh-buy/server/internal/db"
)

// App 配对接口(网页端管理 + App 端兑换)。
//
// 三个角色:
//   - 网页(已鉴权):POST /api/app/pairing-codes 生成码;GET/DELETE /api/app/devices 管理设备
//   - App(免鉴权,白名单):POST /api/app/pair 凭码换设备令牌
//   - 兑换限流:按来源 IP 记失败(码是 8 位,不能让人无限试)

// pairFailureLimiter 配对码暴力尝试的限流(独立于 auth 的密钥限流,
// 那个在鉴权中间件里、而 /api/app/pair 在白名单中不走那套)
var pairFailureLimiter = &ipFailureWindow{max: 5, window: time.Minute, lockMs: 5 * time.Minute}

// pairGlobalLimiter 全局失败闸:按 IP 的限流挡单点撞库,这里挡分布式 ——
// 攻击者换一排 IP 各试 4 次(躲开单 IP 阈值)照样能在 2 分钟窗口内扫掉可观空间。
// 任何来源的兑换失败都计入:每分钟全局最多 30 次失败,超了整个接口锁 1 分钟。
// 正常用户不可能触发:一次配对就是一次兑换,失败重试也是个位数。
var pairGlobalLimiter = &globalFailureWindow{max: 30, window: time.Minute, lockMs: time.Minute}

// globalFailureWindow 全局(跨来源)失败计数 + 锁定
type globalFailureWindow struct {
	max     int
	window  time.Duration
	lockMs  time.Duration
	mu      sync.Mutex
	fails   []time.Time
	blocked time.Time
}

func (w *globalFailureWindow) allow() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Since(w.blocked) < w.lockMs {
		return false
	}
	now := time.Now()
	keep := w.fails[:0]
	for _, t := range w.fails {
		if now.Sub(t) < w.window {
			keep = append(keep, t)
		}
	}
	w.fails = keep
	return len(w.fails) < w.max
}

func (w *globalFailureWindow) fail() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fails = append(w.fails, time.Now())
	if len(w.fails) >= w.max {
		w.blocked = time.Now()
		w.fails = w.fails[:0]
	}
}

// ipFailureWindow 简单的按 IP 失败计数(与 auth.MaxAuthFailures 同思路,独立实例化)
type ipFailureWindow struct {
	max     int
	window  time.Duration
	lockMs  time.Duration
	mu      sync.Mutex
	fails   map[string][]time.Time
	blocked map[string]time.Time
}

// allow 该 IP 当前是否放行
func (w *ipFailureWindow) allow(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fails == nil {
		w.fails = map[string][]time.Time{}
		w.blocked = map[string]time.Time{}
	}
	if until, ok := w.blocked[ip]; ok {
		if time.Since(until) < w.lockMs {
			return false
		}
		delete(w.blocked, ip)
	}
	now := time.Now()
	keep := w.fails[ip][:0]
	for _, t := range w.fails[ip] {
		if now.Sub(t) < w.window {
			keep = append(keep, t)
		}
	}
	w.fails[ip] = keep
	return true
}

// fail 记一次失败;达到 max 后锁 lockMs
func (w *ipFailureWindow) fail(ip string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fails[ip] = append(w.fails[ip], time.Now())
	if len(w.fails[ip]) >= w.max {
		w.blocked[ip] = time.Now()
		delete(w.fails, ip)
	}
}

// CreatePairingCode POST /api/app/pairing-codes —— 网页端生成二维码内容
//
// 用设备令牌 / 通行证会话登录的请求要在请求体里再给一次访问密钥:配对出来的设备令牌
// 永不过期、换密钥也不失效,不拦的话偷到一个 30 天会话就能换成永久后门,
// 「添加通行证要输密钥」那道门也被绕开了。用 X-API-Key 登录的本来就证明过密钥,不再问。
func CreatePairingCode(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, viaDevice := c.Get("app_device_id")
		_, viaSession := c.Get("web_session_id")
		if viaDevice || viaSession {
			var body struct {
				APIKey string `json:"apiKey"`
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<10)
			_ = c.ShouldBindJSON(&body)
			ok, wait := auth.VerifyKeyAgain(c.ClientIP(), strings.TrimSpace(body.APIKey), state.APIKey, time.Now())
			if wait > 0 {
				c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "访问密钥错误次数过多,请稍后再试"})
				return
			}
			if !ok {
				c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "生成配对码需要再输一次访问密钥", "code": "NEED_API_KEY"})
				return
			}
		}
		code, expiresAt, err := state.DB.CreatePairingCode()
		if err != nil {
			state.Logger.Error("生成配对码失败: "+err.Error(), "app")
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "生成配对码失败", "code": "E57703499"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":   true,
			"code":      code,
			"expiresAt": expiresAt,
			// 二维码内容直接编码这两样,App 扫码后不用手填地址
			"pairUrl": pairURL(c, code),
		})
	}
}

// pairURL 生成 App 可识别的配对 URL(ovhconsole://pair?host=...&code=...)
//
// 协议判断:直连 TLS,或者反代(终止 TLS 后回源 http)带了 X-Forwarded-Proto: https。
// 这个头可以伪造,但伪造的结果只是让二维码变成 https,不会降级;而不认它的话,
// 「HTTPS 反代 → 后端 HTTP」这种最常见的部署生成的永远是 http 地址,App 会明文兑换配对码。
// 设了 PUBLIC_BASE_URL(如 https://panel.example.com)就直接用它。
func pairURL(c *gin.Context, code string) string {
	if base := strings.TrimRight(strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")), "/"); base != "" {
		return base + "/api/app/pair#" + code
	}
	scheme := "https"
	if c.Request.TLS == nil && !strings.EqualFold(strings.TrimSpace(strings.Split(c.GetHeader("X-Forwarded-Proto"), ",")[0]), "https") {
		// 本地 http 部署(127.0.0.1:19998)也要能配对;App 侧对私有地址允许明文
		scheme = "http"
	}
	host := c.Request.Host
	return scheme + "://" + host + "/api/app/pair#" + code
}

// RedeemPairingCode POST /api/app/pair —— App 凭码换令牌(白名单,免密钥)
func RedeemPairingCode(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !pairFailureLimiter.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error":   "尝试次数过多,请 5 分钟后再试(配对码 2 分钟就会过期,先去网页重新生成)", "code": "EC57B85C6",
			})
			return
		}
		// 全局闸在 IP 闸之后:单 IP 闸先给本地用户更快的恢复节奏,
		// 全局闸只在真出现分布式撞库时才兜底
		if !pairGlobalLimiter.allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error":   "配对尝试过于频繁,接口已暂时锁定 1 分钟 —— 稍后再试或联系管理员", "code": "E93CC6F2D",
			})
			return
		}
		var body struct {
			Code       string `json:"code"`
			DeviceName string `json:"deviceName"`
		}
		// 免鉴权接口:请求体封顶 4 KiB(码 + 60 字设备名绰绰有余),不让人塞几 MB 进来解析
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<10)
		_ = c.ShouldBindJSON(&body)
		code := strings.ToUpper(strings.TrimSpace(body.Code))
		if code == "" {
			// 空码 / 畸形 JSON 也算一次失败,否则可以无限次白打这个接口
			pairFailureLimiter.fail(ip)
			pairGlobalLimiter.fail()
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "缺少配对码", "code": "E6641AC88"})
			return
		}
		name := strings.TrimSpace(body.DeviceName)
		if len(name) > 60 {
			name = name[:60]
		}
		token, deviceID, err := state.DB.RedeemPairingCode(code, name)
		if err != nil {
			pairFailureLimiter.fail(ip)
			pairGlobalLimiter.fail()
			msg, code2 := "配对失败", "ED03B15C6"
			switch {
			case errors.Is(err, db.ErrPairingCodeNotFound):
				msg, code2 = "配对码不存在 —— 检查大小写,或去网页重新生成", "E79820B5A"
			case errors.Is(err, db.ErrPairingCodeUsed):
				msg, code2 = "配对码已被使用(一码一机)。去网页重新生成再试", "EA92792C8"
			case errors.Is(err, db.ErrPairingCodeExpired):
				msg, code2 = "配对码已过期(有效期 2 分钟)。去网页重新生成再试", "E21D475B2"
			}
			state.Logger.Warn("App 配对失败 ip="+ip+" code="+code+" 原因="+err.Error(), "app")
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msg, "code": code2})
			return
		}
		state.Logger.Info("App 配对成功 device=#"+strconv.FormatInt(deviceID, 10)+" name="+name, "app")
		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"token":         token,
			"deviceId":      deviceID,
			"serverVersion": Version,
		})
	}
}

// ListAppDevices GET /api/app/devices —— 网页端设备管理列表
func ListAppDevices(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		devs, err := state.DB.ListDevices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		out := make([]gin.H, 0, len(devs))
		for _, d := range devs {
			row := gin.H{"id": d.ID, "name": d.Name, "createdAt": d.CreatedAt}
			if d.LastUsed.Valid {
				row["lastUsedAt"] = d.LastUsed.Time
			}
			row["revoked"] = d.Revoked.Valid
			if d.Revoked.Valid {
				row["revokedAt"] = d.Revoked.Time
			}
			out = append(out, row)
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "devices": out, "total": len(out)})
	}
}

// RevokeAppDevice DELETE /api/app/devices/:id —— 吊销(幂等)
func RevokeAppDevice(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "设备 id 非法", "code": "E1703A9CF"})
			return
		}
		if err := state.DB.RevokeDevice(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		state.Logger.Info("App 设备已吊销 #"+strconv.FormatInt(id, 10), "app")
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "设备已吊销,该设备的令牌立即失效", "code": "EB183A580"})
	}
}

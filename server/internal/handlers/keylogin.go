package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ovh-buy/server/internal/app"
)

// 关闭访问密钥登录 + 应急恢复。
//
// 关掉之后网页只能用通行证进来,访问密钥只剩「二次确认」的用途(加通行证、看完整凭据、
// 会话登录时生成配对码)。App 设备令牌、Telegram 都不受影响。
//
// 防锁死:
//   - 只有当前就是用通行证登录的会话才能关 —— 证明这个域名下的通行证确实能用;
//   - 通行证全丢了的应急办法:在数据目录里放一个 allow-key-login 文件(内容随意),
//     访问密钥登录立刻恢复,不用重启;删掉文件又回到关闭状态。
//     能在服务器上建文件的人本来就拥有整台机器,这扇门不会降低安全性。

const emergencyKeyLoginFile = "allow-key-login"

var (
	emergencyMu      sync.Mutex
	emergencyChecked time.Time
	emergencyExists  bool
)

// EmergencyKeyLoginPath 应急文件的完整路径
func EmergencyKeyLoginPath(state *app.State) string {
	return filepath.Join(state.Paths.DataDir, emergencyKeyLoginFile)
}

// EmergencyKeyLoginFile 应急文件在不在。每个请求都会问,结果缓存 3 秒,不每次都 stat
func EmergencyKeyLoginFile(state *app.State) bool {
	emergencyMu.Lock()
	defer emergencyMu.Unlock()
	if time.Since(emergencyChecked) < 3*time.Second {
		return emergencyExists
	}
	_, err := os.Stat(EmergencyKeyLoginPath(state))
	emergencyExists = err == nil
	emergencyChecked = time.Now()
	return emergencyExists
}

// KeyLoginDisabled 访问密钥登录当前是否真的被关着(配置关了且没有应急文件)
func KeyLoginDisabled(state *app.State) bool {
	return state.Config.Get().DisableKeyLogin && !EmergencyKeyLoginFile(state)
}

// GetKeyLogin GET /api/auth/key-login
func GetKeyLogin(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, viaSession := c.Get("web_session_id")
		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"disabled":      state.Config.Get().DisableKeyLogin,
			"emergencyFile": EmergencyKeyLoginFile(state),
			"emergencyPath": EmergencyKeyLoginPath(state),
			"viaPasskey":    viaSession,
		})
	}
}

// SetKeyLogin POST /api/auth/key-login {disabled}
func SetKeyLogin(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			Disabled bool `json:"disabled"`
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<10)
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "请求格式不对"})
			return
		}
		if body.Disabled {
			if _, viaSession := c.Get("web_session_id"); !viaSession {
				c.JSON(http.StatusForbidden, gin.H{"success": false,
					"error": "请先退出,用通行证登录一次再关闭访问密钥登录 —— 这样能确认通行证在这个域名下确实能用,不会把自己锁在外面"})
				return
			}
		}
		cfg := state.Config.Get()
		cfg.DisableKeyLogin = body.Disabled
		if err := state.Config.Set(cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		if body.Disabled {
			state.Logger.Warn("已关闭访问密钥登录(来源 "+c.ClientIP()+")。应急恢复:在数据目录放一个 "+emergencyKeyLoginFile+" 文件", "auth")
		} else {
			state.Logger.Warn("已恢复访问密钥登录(来源 "+c.ClientIP()+")", "auth")
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "disabled": body.Disabled})
	}
}

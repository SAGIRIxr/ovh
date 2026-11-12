package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/ovh-buy/server/internal/app"
	"github.com/ovh-buy/server/internal/auth"
	"github.com/ovh-buy/server/internal/db"
	"github.com/ovh-buy/server/internal/secret"
)

// 通行证(WebAuthn / passkey)登录。
//
// 它给面板加了两样以前没有的东西:一个免鉴权的登录入口,和一种长期有效的登录凭据。
// 下面每一条都对应一种具体的滥用方式:
//
//   - 添加通行证要再输一次访问密钥(和「查看完整凭据」同一道门、同一个失败计数)。
//     否则偷到设备令牌 / 会话令牌的人能给自己注册一个通行证长期驻留,吊销设备也赶不走。
//   - 通行证和会话都绑定当前访问密钥的指纹:怀疑泄漏时换 API_SECRET_KEY,
//     别人偷偷加的通行证、已经发出去的会话一起失效。
//   - 每个通行证记下注册时的 RP ID(域名),登录只认当前域名下的。服务器校验签名里的
//     rpIdHash 和 clientData 里的 origin,浏览器又不允许别的站点用这个域名的通行证 ——
//     钓鱼站套壳转发拿不到能用的签名。IP 地址访问一律拒绝(WebAuthn 本来也不支持)。
//   - 要求用户验证(指纹 / PIN / Windows Hello):捡到安全钥匙本身登不进来。
//   - 签名计数器倒退(克隆迹象)直接拒绝登录。
//   - 挑战一次性:不管成功失败,完成那一步先把它从内存删掉,重放必然失败;2 分钟过期。
//     待完成的挑战全局最多 maxPasskeyFlows 个,免鉴权接口不能被刷爆内存。
//   - 免鉴权的两个登录接口按来源 IP 记失败、全局再兜一层,请求体封顶 64 KiB。
//   - 会话令牌 32 字节随机,库里只存 SHA-256,30 天过期;退出登录 / 删通行证即吊销。

const (
	passkeyFlowTTL       = 2 * time.Minute
	maxPasskeyFlows      = 200
	maxPasskeyFlowsPerIP = 10
	passkeyBodyMax       = 64 << 10
)

// 整个面板只有一个管理员身份。user handle 固定,登录时据此确认是本面板签出的通行证
var passkeyUserHandle = []byte("ovh-console-admin")

// rpID 只用于显示:用户名写成 admin@域名,Bitwarden 之类的密码管理器里一眼能认出是哪个面板
type passkeyUser struct {
	rpID  string
	creds []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return passkeyUserHandle }
func (u passkeyUser) WebAuthnName() string                       { return "admin@" + u.rpID }
func (u passkeyUser) WebAuthnDisplayName() string                { return "OVH 控制台 (" + u.rpID + ")" }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

type passkeyFlow struct {
	ip      string
	kind    string // register / login
	rpID    string
	name    string // 注册时的名字
	session webauthn.SessionData
	expires time.Time
}

var (
	passkeyFlowsMu sync.Mutex
	passkeyFlows   = map[string]passkeyFlow{}
)

// 登录失败限流:单 IP 10 次 / 分钟,全局 60 次 / 分钟
var (
	passkeyLoginLimiter  = &ipFailureWindow{max: 10, window: time.Minute, lockDuration: 5 * time.Minute}
	passkeyGlobalLimiter = &globalFailureWindow{max: 60, window: time.Minute, lockDuration: time.Minute}
)

func putPasskeyFlow(f passkeyFlow) (string, error) {
	passkeyFlowsMu.Lock()
	defer passkeyFlowsMu.Unlock()
	now := time.Now()
	for k, v := range passkeyFlows {
		if now.After(v.expires) {
			delete(passkeyFlows, k)
		}
	}
	if len(passkeyFlows) >= maxPasskeyFlows {
		return "", errors.New("登录请求太多,请稍后再试")
	}
	// 单个来源最多挂 maxPasskeyFlowsPerIP 个:一个人刷不满全局名额
	mine := 0
	for _, v := range passkeyFlows {
		if v.ip == f.ip {
			mine++
		}
	}
	if mine >= maxPasskeyFlowsPerIP {
		return "", errors.New("登录请求太多,请稍后再试")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw)
	f.expires = now.Add(passkeyFlowTTL)
	passkeyFlows[id] = f
	return id, nil
}

// takePasskeyFlow 取出并删除(一次性)。类型、域名不对或已过期都当不存在
func takePasskeyFlow(id, kind, rpID string) (passkeyFlow, bool) {
	passkeyFlowsMu.Lock()
	defer passkeyFlowsMu.Unlock()
	f, ok := passkeyFlows[id]
	delete(passkeyFlows, id)
	if !ok || f.kind != kind || f.rpID != rpID || time.Now().After(f.expires) {
		return passkeyFlow{}, false
	}
	return f, true
}

var errPasskeyNeedsDomain = errors.New("通行证只能在域名或 localhost 下使用,用 IP 地址打开面板时不可用")

// passkeyRP 按当前访问的地址确定 RP ID 和允许的来源。
// 设了 PUBLIC_BASE_URL 就只认它;否则用请求的 Host。Host 可以被直接调接口的人随便填,
// 但这不构成绕过:签名是浏览器替真实页面的域名做的,填别的 Host 只会让校验对不上。
func passkeyRP(c *gin.Context) (rpID string, origins []string, err error) {
	host := c.Request.Host
	if base := strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")); base != "" {
		u, perr := url.Parse(base)
		if perr != nil || u.Host == "" {
			return "", nil, errors.New("PUBLIC_BASE_URL 不是合法地址")
		}
		host = u.Host
	}
	hostname := host
	if h, _, serr := net.SplitHostPort(host); serr == nil {
		hostname = h
	}
	hostname = strings.ToLower(strings.Trim(hostname, "[]"))
	if hostname == "" || net.ParseIP(hostname) != nil {
		return "", nil, errPasskeyNeedsDomain
	}
	origins = []string{"https://" + host}
	// 浏览器只在 localhost 上允许非 https 的 WebAuthn,其它域名放进 http 也用不上
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		origins = append(origins, "http://"+host)
	}
	return hostname, origins, nil
}

func newWebAuthn(rpID string, origins []string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "OVH 控制台",
		RPOrigins:     origins,
	})
}

func currentKeyFP(state *app.State) string { return secret.Fingerprint(state.APIKey) }

// activePasskeyUser 当前密钥、当前域名下的通行证,以及 credential_id → 库内记录
func activePasskeyUser(state *app.State, rpID string) (passkeyUser, map[string]db.Passkey, error) {
	rows, err := state.DB.ActivePasskeys(rpID, currentKeyFP(state))
	if err != nil {
		return passkeyUser{}, nil, err
	}
	u := passkeyUser{rpID: rpID}
	byID := map[string]db.Passkey{}
	for _, p := range rows {
		var cred webauthn.Credential
		if json.Unmarshal([]byte(p.Credential), &cred) != nil {
			continue
		}
		u.creds = append(u.creds, cred)
		byID[p.CredentialID] = p
	}
	return u, byID, nil
}

func credIDString(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// readLimitedJSON 读请求体(封顶),解析出 flowId 和原样的 credential JSON
func readPasskeyFinish(c *gin.Context) (flowID string, credential []byte, err error) {
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, passkeyBodyMax))
	if err != nil {
		return "", nil, errors.New("请求体过大或读取失败")
	}
	var body struct {
		FlowID     string          `json:"flowId"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.FlowID == "" || len(body.Credential) == 0 {
		return "", nil, errors.New("请求格式不对")
	}
	return body.FlowID, body.Credential, nil
}

// PasskeyRegisterBegin POST /api/auth/passkeys/register/begin(需登录 + 再输一次访问密钥)
func PasskeyRegisterBegin(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			APIKey string `json:"apiKey"`
			Name   string `json:"name"`
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<10)
		_ = c.ShouldBindJSON(&body)
		ok, wait := auth.VerifyKeyAgain(c.ClientIP(), strings.TrimSpace(body.APIKey), state.APIKey, time.Now())
		if wait > 0 {
			c.Header("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "访问密钥错误次数过多,请稍后再试"})
			return
		}
		if !ok {
			// 403 而不是 401:401 会被前端当成会话失效直接登出
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "访问密钥不对"})
			return
		}
		rpID, origins, err := passkeyRP(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		wa, err := newWebAuthn(rpID, origins)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "通行证配置错误: " + err.Error()})
			return
		}
		user, _, err := activePasskeyUser(state, rpID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		exclude := make([]protocol.CredentialDescriptor, 0, len(user.creds))
		for i := range user.creds {
			exclude = append(exclude, user.creds[i].Descriptor())
		}
		creation, session, err := wa.BeginRegistration(user,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementRequired,
				UserVerification: protocol.VerificationRequired,
			}),
			webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
			webauthn.WithExclusions(exclude),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			name = "未命名通行证"
		}
		if r := []rune(name); len(r) > 40 {
			name = string(r[:40])
		}
		flowID, err := putPasskeyFlow(passkeyFlow{ip: c.ClientIP(), kind: "register", rpID: rpID, name: name, session: *session})
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "flowId": flowID, "options": creation.Response})
	}
}

// PasskeyRegisterFinish POST /api/auth/passkeys/register/finish(需登录)
func PasskeyRegisterFinish(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		flowID, raw, err := readPasskeyFinish(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		rpID, origins, err := passkeyRP(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		flow, ok := takePasskeyFlow(flowID, "register", rpID)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "这次添加已过期,请重新点「添加通行证」"})
			return
		}
		wa, err := newWebAuthn(rpID, origins)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(raw))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "通行证数据解析失败"})
			return
		}
		user, _, err := activePasskeyUser(state, rpID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		cred, err := wa.CreateCredential(user, flow.session, parsed)
		if err != nil {
			state.Logger.Warn("通行证注册校验失败: "+err.Error(), "auth")
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "通行证校验失败"})
			return
		}
		js, _ := json.Marshal(cred)
		id, err := state.DB.AddPasskey(db.Passkey{
			CredentialID: credIDString(cred.ID), Name: flow.name, RPID: rpID,
			Credential: string(js), KeyFP: currentKeyFP(state),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "保存失败: " + err.Error()})
			return
		}
		state.Logger.Warn(fmt.Sprintf("新增通行证「%s」(域名 %s,来源 %s)", flow.name, rpID, c.ClientIP()), "auth")
		c.JSON(http.StatusOK, gin.H{"success": true, "id": id})
	}
}

// PasskeyLoginBegin POST /api/auth/passkey/login/begin(免鉴权)
func PasskeyLoginBegin(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !passkeyLoginLimiter.allow(c.ClientIP()) || !passkeyGlobalLimiter.allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "通行证登录失败次数过多,请几分钟后再试"})
			return
		}
		rpID, origins, err := passkeyRP(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		wa, err := newWebAuthn(rpID, origins)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		flowID, err := putPasskeyFlow(passkeyFlow{ip: c.ClientIP(), kind: "login", rpID: rpID, session: *session})
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "flowId": flowID, "options": assertion.Response})
	}
}

// PasskeyLoginFinish POST /api/auth/passkey/login/finish(免鉴权)→ 会话令牌
func PasskeyLoginFinish(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !passkeyLoginLimiter.allow(ip) || !passkeyGlobalLimiter.allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "通行证登录失败次数过多,请几分钟后再试"})
			return
		}
		fail := func(status int, msg, detail string) {
			passkeyLoginLimiter.fail(ip)
			passkeyGlobalLimiter.fail()
			if detail != "" {
				state.Logger.Warn("通行证登录失败 ip="+ip+": "+detail, "auth")
			}
			c.JSON(status, gin.H{"success": false, "error": msg})
		}
		flowID, raw, err := readPasskeyFinish(c)
		if err != nil {
			fail(http.StatusBadRequest, err.Error(), "")
			return
		}
		rpID, origins, err := passkeyRP(c)
		if err != nil {
			fail(http.StatusBadRequest, err.Error(), "")
			return
		}
		flow, ok := takePasskeyFlow(flowID, "login", rpID)
		if !ok {
			fail(http.StatusBadRequest, "登录请求已过期,请重新点「通行证登录」", "")
			return
		}
		wa, err := newWebAuthn(rpID, origins)
		if err != nil {
			fail(http.StatusInternalServerError, err.Error(), "")
			return
		}
		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(raw))
		if err != nil {
			fail(http.StatusBadRequest, "通行证数据解析失败", err.Error())
			return
		}
		user, byID, err := activePasskeyUser(state, rpID)
		if err != nil {
			fail(http.StatusInternalServerError, err.Error(), "")
			return
		}
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			if !bytes.Equal(userHandle, passkeyUserHandle) {
				return nil, errors.New("不是本面板的通行证")
			}
			if _, ok := byID[credIDString(rawID)]; !ok {
				return nil, errors.New("通行证未注册或已失效")
			}
			return user, nil
		}
		_, cred, err := wa.ValidatePasskeyLogin(handler, flow.session, parsed)
		if err != nil {
			fail(http.StatusUnauthorized, "通行证校验失败(没注册过、已删除,或更换访问密钥后已失效)", err.Error())
			return
		}
		if cred.Authenticator.CloneWarning {
			fail(http.StatusUnauthorized, "通行证签名计数异常,已拒绝登录", "签名计数器倒退,疑似克隆")
			return
		}
		rec := byID[credIDString(cred.ID)]
		js, _ := json.Marshal(cred)
		_ = state.DB.UpdatePasskeyAfterLogin(rec.ID, string(js))
		token, expires, err := state.DB.CreateWebSession(rec.ID, currentKeyFP(state), ip, c.Request.UserAgent())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "创建会话失败"})
			return
		}
		state.Logger.Info(fmt.Sprintf("通行证「%s」登录成功(来源 %s)", rec.Name, ip), "auth")
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"success": true, "token": token, "expiresAt": expires.Format(time.RFC3339)})
	}
}

// ListPasskeys GET /api/auth/passkeys
func ListPasskeys(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := state.DB.ListPasskeys()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		fp := currentKeyFP(state)
		rpID, _, rpErr := passkeyRP(c)
		out := make([]gin.H, 0, len(rows))
		for _, p := range rows {
			item := gin.H{
				"id": p.ID, "name": p.Name, "rpId": p.RPID,
				"createdAt": p.CreatedAt.Format(time.RFC3339),
				// 换过访问密钥的不能再登录,留在列表里让用户自己删
				"active":        p.KeyFP == fp,
				"currentDomain": rpErr == nil && p.RPID == rpID,
				"sessions":      state.DB.CountWebSessions(p.ID),
			}
			if p.LastUsed.Valid {
				item["lastUsed"] = p.LastUsed.Time.Format(time.RFC3339)
			}
			out = append(out, item)
		}
		resp := gin.H{"success": true, "passkeys": out, "domainOk": rpErr == nil}
		if rpErr != nil {
			resp["domainError"] = rpErr.Error()
		}
		c.JSON(http.StatusOK, resp)
	}
}

// DeletePasskey DELETE /api/auth/passkeys/:id(连带吊销它的会话)
func DeletePasskey(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "id 不对"})
			return
		}
		if err := state.DB.DeletePasskey(id); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, db.ErrPasskeyNotFound) {
				status = http.StatusNotFound
			}
			c.JSON(status, gin.H{"success": false, "error": err.Error()})
			return
		}
		state.Logger.Warn(fmt.Sprintf("删除了通行证 #%d(来源 %s)", id, c.ClientIP()), "auth")
		c.JSON(http.StatusOK, gin.H{"success": true})
	}
}

// Logout POST /api/auth/logout:通行证会话退出时在服务端作废令牌(用访问密钥登录的没有服务端会话)
func Logout(state *app.State) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := c.Get("web_session_id"); ok {
			token := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
			_ = state.DB.RevokeWebSession(token)
		}
		c.JSON(http.StatusOK, gin.H{"success": true})
	}
}

// WebSessionValidator 给鉴权中间件用
func WebSessionValidator(state *app.State) func(string) (int64, bool) {
	return func(token string) (int64, bool) {
		return state.DB.WebSessionValid(token, currentKeyFP(state))
	}
}

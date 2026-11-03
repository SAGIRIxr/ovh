package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/ovh-buy/server/internal/app"
)

// softAuthenticator 一个最小的软件验证器:ES256、none 证明。用来端到端地测通行证的每道校验
type softAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
	noUV   bool // 模拟不做用户验证的安全钥匙
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuthenticator{key: k, credID: id}
}

var b64 = base64.RawURLEncoding

func (a *softAuthenticator) flags(attested bool) byte {
	f := byte(0x01) // UP
	if !a.noUV {
		f |= 0x04
	}
	if attested {
		f |= 0x40
	}
	return f
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func (a *softAuthenticator) register(t *testing.T, rpID, challenge, origin string) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, a.flags(true))
	auth = binary.BigEndian.AppendUint32(auth, a.count)
	auth = append(auth, make([]byte, 16)...) // AAGUID
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.credID)))
	auth = append(auth, a.credID...)
	auth = append(auth, cose...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData("webauthn.create", challenge, origin)),
			"attestationObject": b64.EncodeToString(att),
		},
	})
	return cred
}

func (a *softAuthenticator) assert(t *testing.T, rpID, challenge, origin string) []byte {
	a.count++
	rpHash := sha256.Sum256([]byte(rpID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, a.flags(false))
	auth = binary.BigEndian.AppendUint32(auth, a.count)
	cd := clientData("webauthn.get", challenge, origin)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(auth),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(passkeyUserHandle),
		},
	})
	return cred
}

type passkeyHarness struct {
	t     *testing.T
	state *app.State
	r     *gin.Engine
}

func newPasskeyHarness(t *testing.T) *passkeyHarness {
	gin.SetMode(gin.TestMode)
	s := newTGTestState(t)
	s.APIKey = "the-real-access-key"
	r := gin.New()
	r.POST("/begin-reg", PasskeyRegisterBegin(s))
	r.POST("/finish-reg", PasskeyRegisterFinish(s))
	r.POST("/begin-login", PasskeyLoginBegin(s))
	r.POST("/finish-login", PasskeyLoginFinish(s))
	r.DELETE("/passkeys/:id", DeletePasskey(s))
	// 每个用例独立的限流状态
	passkeyLoginLimiter = &ipFailureWindow{max: 10, window: 60e9, lockMs: 300e9}
	passkeyGlobalLimiter = &globalFailureWindow{max: 60, window: 60e9, lockMs: 60e9}
	return &passkeyHarness{t: t, state: s, r: r}
}

func (h *passkeyHarness) post(path, host, body, ip string) (int, map[string]any) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Host = host
	if ip != "" {
		req.RemoteAddr = ip + ":1111"
	}
	h.r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func challengeOf(t *testing.T, out map[string]any) (flow, challenge string) {
	opts, _ := out["options"].(map[string]any)
	flow, _ = out["flowId"].(string)
	challenge, _ = opts["challenge"].(string)
	if flow == "" || challenge == "" {
		t.Fatalf("begin 没给出 flowId/challenge: %v", out)
	}
	return
}

func finishBody(flow string, cred []byte) string {
	return `{"flowId":"` + flow + `","credential":` + string(cred) + `}`
}

const host = "ovh.example"
const origin = "https://ovh.example"

// 注册一个通行证并返回验证器
func (h *passkeyHarness) registerOK(a *softAuthenticator) {
	code, out := h.post("/begin-reg", host, `{"apiKey":"the-real-access-key","name":"手机"}`, "")
	if code != 200 {
		h.t.Fatalf("register begin: %d %v", code, out)
	}
	flow, ch := challengeOf(h.t, out)
	if code, out = h.post("/finish-reg", host, finishBody(flow, a.register(h.t, host, ch, origin)), ""); code != 200 {
		h.t.Fatalf("register finish: %d %v", code, out)
	}
}

func (h *passkeyHarness) login(a *softAuthenticator, reqHost, rpID, org string) (int, map[string]any) {
	code, out := h.post("/begin-login", reqHost, `{}`, "")
	if code != 200 {
		return code, out
	}
	flow, ch := challengeOf(h.t, out)
	return h.post("/finish-login", reqHost, finishBody(flow, a.assert(h.t, rpID, ch, org)), "")
}

func TestPasskeyHappyPathAndSession(t *testing.T) {
	h := newPasskeyHarness(t)
	a := newSoftAuthenticator(t)
	h.registerOK(a)
	code, out := h.login(a, host, host, origin)
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	token, _ := out["token"].(string)
	if len(token) != 64 {
		t.Fatalf("会话令牌不对: %v", out)
	}
	if _, ok := WebSessionValidator(h.state)(token); !ok {
		t.Fatal("新发的会话应该有效")
	}
	if _, ok := WebSessionValidator(h.state)(token + "x"); ok {
		t.Fatal("篡改过的令牌不能通过")
	}
}

func TestPasskeyRegisterNeedsAccessKey(t *testing.T) {
	h := newPasskeyHarness(t)
	if code, _ := h.post("/begin-reg", host, `{"apiKey":"guess","name":"x"}`, ""); code != http.StatusForbidden {
		t.Fatalf("访问密钥不对应拒绝注册,得 %d", code)
	}
	if code, _ := h.post("/begin-reg", host, `{}`, ""); code != http.StatusForbidden {
		t.Fatalf("不带访问密钥应拒绝注册,得 %d", code)
	}
}

func TestPasskeyRejectsAttacks(t *testing.T) {
	h := newPasskeyHarness(t)
	a := newSoftAuthenticator(t)
	h.registerOK(a)

	// 1. 重放:同一个 flow 第二次提交必须失败
	_, out := h.post("/begin-login", host, `{}`, "")
	flow, ch := challengeOf(t, out)
	body := finishBody(flow, a.assert(t, host, ch, origin))
	if code, out := h.post("/finish-login", host, body, ""); code != 200 {
		t.Fatalf("首次登录应成功: %d %v", code, out)
	}
	if code, _ := h.post("/finish-login", host, body, ""); code == 200 {
		t.Fatal("重放同一次登录必须失败")
	}

	// 2. 签名里的来源是钓鱼站
	if code, _ := h.login(a, host, host, "https://evil.example"); code == 200 {
		t.Fatal("clientData 来源不对必须失败")
	}
	// 3. 验证器替别的域名签的名(rpIdHash 不对)
	if code, _ := h.login(a, host, "evil.example", origin); code == 200 {
		t.Fatal("rpIdHash 不对必须失败")
	}
	// 4. 换个 Host 来访问:那个域名下没有注册过的通行证
	if code, _ := h.login(a, "evil.example", "evil.example", "https://evil.example"); code == 200 {
		t.Fatal("别的域名不能用这个通行证登录")
	}
	// 5. 没做用户验证
	a.noUV = true
	if code, _ := h.login(a, host, host, origin); code == 200 {
		t.Fatal("没有用户验证(UV)必须失败")
	}
	a.noUV = false
	// 6. 签名计数器倒退(克隆)
	a.count = 0
	if code, _ := h.login(a, host, host, origin); code == 200 {
		t.Fatal("签名计数倒退必须拒绝")
	}
	// 7. 没注册过的验证器
	if code, _ := h.login(newSoftAuthenticator(t), host, host, origin); code == 200 {
		t.Fatal("没注册过的通行证不能登录")
	}
	// 8. 用 IP 访问直接拒绝
	if code, _ := h.post("/begin-login", "203.0.113.9:20000", `{}`, ""); code != http.StatusBadRequest {
		t.Fatalf("IP 访问应 400,得 %d", code)
	}
	// 上面每一条都必须是被对应的校验挡下,而不是功能整体坏了:同一个验证器正常登录仍要成功
	a.count = 100
	if code, out := h.login(a, host, host, origin); code != 200 {
		t.Fatalf("攻击用例之后正常登录应成功: %d %v", code, out)
	}
}

func TestPasskeyKeyRotationAndDeleteRevoke(t *testing.T) {
	h := newPasskeyHarness(t)
	a := newSoftAuthenticator(t)
	h.registerOK(a)
	_, out := h.login(a, host, host, origin)
	token, _ := out["token"].(string)

	// 删除通行证 → 会话立即失效
	list, _ := h.state.DB.ListPasskeys()
	w := httptest.NewRecorder()
	h.r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/passkeys/"+jsonNum(list[0].ID), nil))
	if w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	if _, ok := WebSessionValidator(h.state)(token); ok {
		t.Fatal("删掉通行证后它的会话必须失效")
	}

	// 重新注册,登录,然后换访问密钥 → 通行证和会话都失效
	b := newSoftAuthenticator(t)
	h.registerOK(b)
	_, out = h.login(b, host, host, origin)
	token, _ = out["token"].(string)
	h.state.APIKey = "rotated-key"
	if _, ok := WebSessionValidator(h.state)(token); ok {
		t.Fatal("换了访问密钥,旧会话必须失效")
	}
	if code, _ := h.login(b, host, host, origin); code == 200 {
		t.Fatal("换了访问密钥,旧通行证必须不能再登录")
	}
}

func TestPasskeyLoginRateLimited(t *testing.T) {
	h := newPasskeyHarness(t)
	limited := false
	for i := 0; i < 20; i++ {
		code, _ := h.post("/finish-login", host, `{"flowId":"nope","credential":{}}`, "198.51.100.4")
		if code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("连续失败应触发限流")
	}
	big := `{"flowId":"x","credential":"` + strings.Repeat("a", 200<<10) + `"}`
	if code, _ := h.post("/finish-login", host, big, "198.51.100.5"); code != http.StatusBadRequest {
		t.Fatalf("超大请求体应 400,得 %d", code)
	}
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestPasskeyRegisterRequiresUserVerification(t *testing.T) {
	h := newPasskeyHarness(t)
	a := newSoftAuthenticator(t)
	a.noUV = true
	_, out := h.post("/begin-reg", host, `{"apiKey":"the-real-access-key","name":"key"}`, "")
	flow, ch := challengeOf(t, out)
	if code, _ := h.post("/finish-reg", host, finishBody(flow, a.register(t, host, ch, origin)), ""); code == 200 {
		t.Fatal("没做用户验证的验证器不能注册")
	}
}

// 用通行证会话 / 设备令牌登录的,生成配对码要再给访问密钥:否则 30 天会话能换出永久设备令牌
func TestPairingCodeNeedsKeyWhenViaToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newTGTestState(t)
	s.APIKey = "the-real-access-key"
	r := gin.New()
	r.POST("/pc", func(c *gin.Context) { c.Set("web_session_id", int64(1)) }, CreatePairingCode(s))
	r.POST("/pc-key", CreatePairingCode(s)) // 模拟 X-API-Key 登录:中间件不设任何令牌标记
	do := func(path, body string) int {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return w.Code
	}
	if code := do("/pc", `{}`); code != http.StatusForbidden {
		t.Fatalf("会话登录不带密钥应 403,得 %d", code)
	}
	if code := do("/pc", `{"apiKey":"the-real-access-key"}`); code != 200 {
		t.Fatalf("会话登录带对密钥应 200,得 %d", code)
	}
	if code := do("/pc-key", ``); code != 200 {
		t.Fatalf("访问密钥登录不用再输,得 %d", code)
	}
}

func TestPasskeyFlowsCappedPerIP(t *testing.T) {
	h := newPasskeyHarness(t)
	passkeyFlowsMu.Lock()
	passkeyFlows = map[string]passkeyFlow{}
	passkeyFlowsMu.Unlock()
	capped := false
	for i := 0; i < maxPasskeyFlowsPerIP+2; i++ {
		if code, _ := h.post("/begin-login", host, `{}`, "198.51.100.77"); code == http.StatusServiceUnavailable {
			capped = true
			break
		}
	}
	if !capped {
		t.Fatal("同一来源的待完成挑战应有上限")
	}
	if code, _ := h.post("/begin-login", host, `{}`, "198.51.100.78"); code != 200 {
		t.Fatalf("别的来源不该受影响,得 %d", code)
	}
}

func TestKeyLoginToggleGuardsAndEmergencyFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newTGTestState(t)
	r := gin.New()
	r.POST("/kl", SetKeyLogin(s))
	r.POST("/kl-session", func(c *gin.Context) { c.Set("web_session_id", int64(1)) }, SetKeyLogin(s))
	r.POST("/settings", SaveSettings(s))
	do := func(path, body string) int {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return w.Code
	}
	if code := do("/kl", `{"disabled":true}`); code != http.StatusForbidden {
		t.Fatalf("不是通行证会话不能关闭密钥登录,得 %d", code)
	}
	if code := do("/kl-session", `{"disabled":true}`); code != 200 || !KeyLoginDisabled(s) {
		t.Fatalf("通行证会话应能关闭,得 %d", code)
	}
	// 普通保存设置(前端提交的整份表单里 disableKeyLogin=false)不能把它顺手打开
	if code := do("/settings", `{"tgChatId":"1","disableKeyLogin":false}`); code != 200 || !s.Config.Get().DisableKeyLogin {
		t.Fatalf("保存设置不该改动密钥登录开关: %d %+v", code, s.Config.Get())
	}
	// 应急文件:放进去立刻恢复,删掉又关上(绕开 3 秒缓存)
	if err := os.WriteFile(EmergencyKeyLoginPath(s), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	emergencyChecked = time.Time{}
	if KeyLoginDisabled(s) {
		t.Fatal("有应急文件时密钥登录应恢复")
	}
	os.Remove(EmergencyKeyLoginPath(s))
	emergencyChecked = time.Time{}
	if !KeyLoginDisabled(s) {
		t.Fatal("删掉应急文件后应回到关闭状态")
	}
	if code := do("/kl", `{"disabled":false}`); code != 200 || KeyLoginDisabled(s) {
		t.Fatalf("任何已登录会话都能重新打开密钥登录,得 %d", code)
	}
}

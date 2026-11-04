package main

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// securityHeaders 所有响应都带的浏览器安全头。
//
//   - X-Frame-Options / CSP frame-ancestors:不许别的网站把面板嵌进 iframe。
//     登录态在 localStorage 里,嵌进去的面板也是已登录的,透明框盖在诱导页面上
//     就能骗人点「删除 / 关闭密钥登录 / 下单」(点击劫持)。
//   - nosniff:浏览器不许按内容猜类型,JSON 不会被当成脚本执行。
//   - Referrer-Policy:订单链接带 orderPassword,点出去时不把面板地址漏给对方。
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

var inlineScriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// buildCSP 首页的内容安全策略。
//
// 脚本只认本站文件,index.html 里的内联脚本(首帧前的主题切换)按内容哈希逐段放行 ——
// 哈希从实际打包进来的 index.html 现算,改了那段脚本也不会对不上。
// 这样就算哪里出了 XSS,注入的脚本也跑不起来,存在 localStorage 里的会话令牌偷不走。
//
// connect-src 放行 OVH 三个站点的公开库存接口:库存是前端直连的(见 web/src/lib/ovh-regions.ts)。
// style-src 留 'unsafe-inline':toast 等组件运行时注入 <style>,样式注入危害远小于脚本。
// Google Fonts:globals.css 里 @import 了 Inter 字体(样式表在 fonts.googleapis.com,字体文件在 fonts.gstatic.com)。
func buildCSP(indexHTML []byte) string {
	scripts := []string{"'self'"}
	for _, m := range inlineScriptRe.FindAllSubmatch(indexHTML, -1) {
		sum := sha256.Sum256(m[1])
		scripts = append(scripts, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src " + strings.Join(scripts, " "),
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"img-src 'self' data: blob:",
		"font-src 'self' data: https://fonts.gstatic.com",
		"connect-src 'self' https://eu.api.ovh.com https://ca.api.ovh.com https://api.us.ovhcloud.com",
		"frame-src 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	}, "; ")
}

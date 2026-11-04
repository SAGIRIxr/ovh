package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildCSPHashesInlineScripts(t *testing.T) {
	body := "\n      (function(){ document.documentElement.classList.add('x') })();\n    "
	html := []byte(`<head><script>` + body + `</script><script type="module" src="/assets/a.js"></script></head>`)
	csp := buildCSP(html)
	sum := sha256.Sum256([]byte(body))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(csp, "script-src 'self' "+want) {
		t.Fatalf("内联脚本哈希不对:\n%s\n期望含 %s", csp, want)
	}
	for _, must := range []string{"frame-ancestors 'none'", "object-src 'none'", "https://eu.api.ovh.com", "https://api.us.ovhcloud.com"} {
		if !strings.Contains(csp, must) {
			t.Fatalf("CSP 缺少 %q: %s", must, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline' 'sha") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatal("脚本不能放开 unsafe-inline")
	}
}

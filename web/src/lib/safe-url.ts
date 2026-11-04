/**
 * 只放行 http / https 链接。
 *
 * 订单、发票、IPMI、更新说明这些链接地址来自 OVH / GitHub 的接口数据。React 18 不拦
 * `javascript:` 地址,接口数据一旦被篡改,点一下链接就是在面板里执行任意脚本
 * (登录令牌就在 localStorage 里)。凡是拿接口数据当 href / window.open 地址的地方都过一遍这里。
 */
export function safeHref(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url, window.location.origin);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : undefined;
  } catch {
    return undefined;
  }
}

/** window.open 的安全版:地址不合格就什么都不做 */
export function openSafe(url: string | null | undefined): void {
  const href = safeHref(url);
  if (href) window.open(href, "_blank", "noopener,noreferrer");
}

import { useState } from "react";
import { ChevronDown, ClipboardPaste } from "lucide-react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { isOrderable } from "@/lib/availability";
import { apiDatacenterCode } from "@/lib/datacenters";
import type { AvailabilityItem } from "@/hooks/use-availability";

export interface ManualConfig {
  planCode?: string;
  fqn?: string;
  options?: string;
}

/** 解析 PLANCODE= / FQN= / OPTIONS= 形式的文本(ovh-auto-buy 的环境变量写法)。
 *  兼容 docker-compose 的「- KEY=value」、.env 的「export KEY=value」、带引号的值和「KEY: value」。 */
export function parseManualConfig(text: string): ManualConfig {
  const out: ManualConfig = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim().replace(/^-\s*/, "").replace(/^export\s+/i, "");
    const m = line.match(/^([A-Za-z_]+)\s*[=:]\s*(.*)$/);
    if (!m) continue;
    const val = m[2].trim().replace(/^["']|["']$/g, "").trim();
    switch (m[1].toUpperCase()) {
      case "PLANCODE":
      case "PLAN_CODE":
        out.planCode = val;
        break;
      case "FQN":
        out.fqn = val;
        break;
      case "OPTIONS":
        out.options = val;
        break;
    }
  }
  return out;
}

/** 和 FQN 不是同一套配置的选项。两者冲突的任务永远等不到货(选项过滤和 FQN 过滤是「且」)。
 *  - 有这个型号的库存数据(variants)时,口径和后端下单一致:选项能匹配上库存里某条 FQN 的段
 *    (参与库存判定),却匹配不上锁定的这条 → 确定冲突(certain),后端也会判死。
 *  - 没有库存数据时只能猜:锁定的 FQN 里有同类段(第一个 "-" 前的前缀相同,如 ram / softraid)
 *    却一段都没对上。老式 addon 命名也可能落到这里,所以只提示、不拦提交。 */
export function fqnOptionConflicts(
  fqn: string,
  options: string[],
  variants?: AvailabilityItem[]
): { conflicts: string[]; certain: boolean } {
  const segsOf = (f: string) => f.toLowerCase().split(".").slice(1);
  const pinned = segsOf(fqn);
  if (pinned.length === 0) return { conflicts: [], certain: false };
  const matches = (seg: string, opt: string) => seg === opt || opt.startsWith(seg + "-") || seg.startsWith(opt + "-");
  const opts = options.map((o) => o.trim().toLowerCase()).filter(Boolean);
  if (variants && variants.length > 0) {
    const all = variants.flatMap((v) => segsOf(v.fqn));
    return {
      conflicts: opts.filter((o) => all.some((s) => matches(s, o)) && !pinned.some((s) => matches(s, o))),
      certain: true,
    };
  }
  const family = (s: string) => s.split("-")[0];
  return {
    conflicts: opts.filter((o) => {
      const same = pinned.filter((s) => family(s) === family(o));
      return same.length > 0 && !same.some((s) => matches(s, o));
    }),
    certain: false,
  };
}

/** FQN 去掉第一段 planCode 后的硬件段,按钮和队列行上显示用 */
export function fqnHardware(fqn: string): string {
  return fqn.split(".").slice(1).join(" · ");
}

/** 手动填写配置:整段粘贴 + FQN 锁定 + 库存里出现过的组合按钮。
 *  目录里没有的型号没有分组 chip 可点,只能靠这里,此时常开(forced);
 *  目录里有的机型折叠起来,展开后填的 FQN 才生效。
 *  OPTIONS 不在这里单独放输入框 —— 对话框里本来就有手填 addon 的输入框,粘贴时直接填进去。 */
export function ManualConfigSection({
  open,
  onOpenChange,
  forced = false,
  planCode,
  fqn,
  onFqnChange,
  onPaste,
  variants,
  datacenters,
  showFqn = true,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  forced?: boolean;
  planCode: string;
  fqn: string;
  onFqnChange: (fqn: string) => void;
  /** 粘贴识别出至少一项时回调,由调用方决定怎么分发到型号 / 选项 */
  onPaste: (parsed: ManualConfig) => void;
  /** 这个型号在库存接口里的全部 FQN,给出可点的组合按钮 */
  variants?: AvailabilityItem[];
  /** 已选机房,组合按钮的绿/红点只看这些机房 */
  datacenters?: string[];
  /** 监控订阅没有 FQN 字段,只用粘贴 */
  showFqn?: boolean;
}) {
  const { t } = useTranslation();
  const [paste, setPaste] = useState("");
  const expanded = forced || open;

  // 只在粘贴和失焦时解析:打字时每敲一个键就解析,「PLANCODE=2」刚打出第一个字符就会被拿去换型号
  const applyPaste = (text: string) => {
    setPaste(text);
    const parsed = parseManualConfig(text);
    const hits = [
      parsed.planCode && "PLANCODE",
      parsed.fqn !== undefined && "FQN",
      parsed.options !== undefined && "OPTIONS",
    ].filter(Boolean);
    if (hits.length === 0) return;
    onPaste(parsed);
    setPaste("");
    toast.success(t("queue.manual.recognized", { keys: hits.join(" / ") }));
  };

  const code = planCode.trim().toLowerCase();
  const fqnMismatch = fqn.trim() !== "" && code !== "" && !fqn.trim().toLowerCase().startsWith(code + ".");
  const dcFilter = datacenters && datacenters.length > 0 ? new Set(datacenters.map(apiDatacenterCode)) : null;
  const inStock = (v: AvailabilityItem) =>
    (v.datacenters || []).some((dc) => (!dcFilter || dcFilter.has(apiDatacenterCode(dc.datacenter || ""))) && isOrderable(dc.availability));
  const combos = showFqn ? (variants || []).filter((v) => v.fqn.includes(".")) : [];

  return (
    <div className="rounded-xl border border-border">
      {!forced && (
        <button
          type="button"
          onClick={() => onOpenChange(!open)}
          aria-expanded={open}
          className="flex w-full items-center justify-between gap-2 px-3.5 py-2.5 text-left text-[13px] hover:bg-muted/40 rounded-xl transition-colors"
        >
          <span className="flex items-center gap-2">
            <ClipboardPaste className="w-3.5 h-3.5 text-muted-foreground" />
            {t("queue.manual.title")}
            <span className="text-[11px] text-muted-foreground">
              {showFqn ? t("queue.manual.subtitle") : t("queue.manual.subtitleNoFqn")}
            </span>
          </span>
          <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform", open && "rotate-180")} />
        </button>
      )}
      {expanded && (
        <div className={cn("space-y-3 px-3.5 pb-3.5", forced ? "pt-3.5" : "pt-1")}>
          <div>
            <label htmlFor="manual-config-paste" className="block text-[12px] font-medium mb-1">
              {t("queue.manual.pasteLabel")}
            </label>
            <Textarea
              id="manual-config-paste"
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
              onPaste={(e) => {
                const text = e.clipboardData.getData("text");
                if (!text) return;
                e.preventDefault();
                applyPaste(text);
              }}
              onBlur={() => paste.trim() && applyPaste(paste)}
              rows={3}
              className="font-mono text-[12px]"
              placeholder={t("queue.manual.pastePlaceholder")}
            />
          </div>

          {combos.length > 0 && (
            <div>
              <div className="text-[12px] font-medium mb-1.5">{t("queue.manual.combosLabel")}</div>
              <div className="flex flex-wrap gap-2">
                {combos.map((v) => {
                  const active = fqn.trim().toLowerCase() === v.fqn.toLowerCase();
                  const ok = inStock(v);
                  return (
                    <button
                      key={v.fqn}
                      type="button"
                      title={v.fqn}
                      onClick={() => onFqnChange(active ? "" : v.fqn)}
                      className={
                        "inline-flex items-center gap-2 px-3 h-8 rounded-full border text-[12px] font-mono transition-colors " +
                        (active
                          ? "border-foreground bg-foreground text-background"
                          : "border-border bg-secondary/40 hover:bg-secondary text-foreground")
                      }
                    >
                      <span
                        className={"inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 " + (ok ? "bg-success" : "bg-destructive")}
                        aria-label={ok ? t("commons.optionGroup.inStock") : t("commons.optionGroup.outOfStock")}
                      />
                      {fqnHardware(v.fqn)}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">{t("queue.manual.combosHint")}</p>
            </div>
          )}

          {showFqn && (
            <div>
              <label htmlFor="manual-config-fqn" className="block text-[12px] font-medium mb-1">
                {t("queue.manual.fqnLabel")}
              </label>
              <Input
                id="manual-config-fqn"
                value={fqn}
                onChange={(e) => onFqnChange(e.target.value)}
                className="font-mono text-[12px]"
                autoCapitalize="none"
                spellCheck={false}
                placeholder={`${code || "<planCode>"}.ram-32g-ecc-2400.softraid-2x450nvme`}
              />
              <p className={cn("text-[11px] mt-1", fqnMismatch ? "text-warning" : "text-muted-foreground")}>
                {fqnMismatch ? t("queue.manual.fqnMismatch", { code }) : t("queue.manual.fqnHint")}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

import type { QueueItem } from "@/hooks/use-queue";
import { OVH_DATACENTERS, apiDatacenterCode } from "@/lib/datacenters";

/** 同一套配置(型号 + FQN + 选项)的身份。复制任务时用它判重,分享时用它把多机房合成一组 */
export function configKey(it: Pick<QueueItem, "planCode" | "fqn" | "options">): string {
  return [
    it.planCode.trim().toLowerCase(),
    (it.fqn || "").trim().toLowerCase(),
    [...(it.options || [])].map((o) => o.trim().toLowerCase()).sort().join(","),
  ].join("|");
}

/** 同一账户、同一机房、同一套配置的任务算重复 */
export function taskKey(it: Pick<QueueItem, "accountId" | "planCode" | "datacenter" | "fqn" | "options">): string {
  return `${it.accountId}|${apiDatacenterCode(it.datacenter)}|${configKey(it)}`;
}

/**
 * 把任务写成 ovh-auto-buy 的环境变量格式(PLANCODE / FQN / OPTIONS / DATACENTER),
 * 朋友可以直接贴进新建任务的「整段粘贴」,也能原样塞进 ovh-auto-buy 的 compose。
 * 同一套配置的多个机房合成一组。只带配置,不带账户、优惠码、自动付款 ——
 * 这些是各人自己的事,分享出去的文本不该替别人决定扣不扣钱。
 */
export function buildShareText(items: QueueItem[]): string {
  const groups = new Map<string, { item: QueueItem; dcs: string[] }>();
  for (const it of items) {
    const key = configKey(it);
    const g = groups.get(key) || { item: it, dcs: [] };
    const dc = apiDatacenterCode(it.datacenter);
    if (!g.dcs.includes(dc)) g.dcs.push(dc);
    groups.set(key, g);
  }
  return [...groups.values()]
    .map(({ item, dcs }) => {
      const lines = [`PLANCODE=${item.planCode}`];
      if (item.fqn) lines.push(`FQN=${item.fqn}`);
      if (item.options && item.options.length > 0) lines.push(`OPTIONS=${item.options.join(",")}`);
      lines.push(`DATACENTER=${dcs.join(",")}`);
      return lines.join("\n");
    })
    .join("\n\n");
}

/** DATACENTER=gra,rbx,ca-east-tor-a → 机房选择器用的代码;认不出的放进 unknown */
export function parseDatacenterList(raw: string): { codes: string[]; unknown: string[] } {
  const codes: string[] = [];
  const unknown: string[] = [];
  for (const part of raw.split(/[,，\s]+/).map((s) => s.trim().toLowerCase()).filter(Boolean)) {
    const dc = OVH_DATACENTERS.find((d) => d.code === part || apiDatacenterCode(d.code) === part);
    if (!dc) unknown.push(part);
    else if (!codes.includes(dc.code)) codes.push(dc.code);
  }
  return { codes, unknown };
}

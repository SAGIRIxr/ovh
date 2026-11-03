import { useMemo } from "react";
import { Search, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { QueueItem } from "@/hooks/use-queue";
import { findAccountByID, type OVHAccount } from "@/hooks/use-accounts";
import { OVH_DATACENTERS, apiDatacenterCode } from "@/lib/datacenters";

export type QueueGroupBy = "none" | "account" | "plan";

export interface QueueFilterState {
  account: string; // "" = 全部
  plan: string;
  dc: string; // API 机房码
  search: string;
  groupBy: QueueGroupBy;
}

export const EMPTY_QUEUE_FILTERS: QueueFilterState = { account: "", plan: "", dc: "", search: "", groupBy: "none" };

const ALL = "__all__";

/** 账户名优先,读不到账户列表时退回 id 前 8 位 */
export function accountLabel(accounts: OVHAccount[] | undefined, id: string): string {
  const acc = findAccountByID(accounts, id);
  return acc ? `${acc.name} · ${acc.zone}` : id ? id.slice(0, 8) : "—";
}

/** 机型、机房、FQN、选项、优惠码、账户名都能搜;空格分开的多个词要同时命中 */
function matchesSearch(it: QueueItem, words: string[], accounts: OVHAccount[] | undefined): boolean {
  if (words.length === 0) return true;
  const hay = [
    it.planCode,
    it.datacenter,
    apiDatacenterCode(it.datacenter),
    it.fqn || "",
    (it.options || []).join(" "),
    it.coupon || "",
    accountLabel(accounts, it.accountId),
  ]
    .join(" ")
    .toLowerCase();
  return words.every((w) => hay.includes(w));
}

/** 按账户 / 机型 / 机房 / 搜索词过滤(状态筛选在外面另算,好让状态 tab 上的数字跟着这里变) */
export function applyQueueFilters(
  items: QueueItem[],
  f: QueueFilterState,
  accounts: OVHAccount[] | undefined
): QueueItem[] {
  const words = f.search.toLowerCase().split(/\s+/).filter(Boolean);
  return items.filter(
    (it) =>
      (!f.account || it.accountId === f.account) &&
      (!f.plan || it.planCode === f.plan) &&
      (!f.dc || apiDatacenterCode(it.datacenter) === f.dc) &&
      matchesSearch(it, words, accounts)
  );
}

/** 筛选栏:账户 / 机型 / 机房三个下拉 + 搜索 + 分组方式。下拉里只列队列里真有的值,带任务数 */
export function QueueFilters({
  items,
  accounts,
  value,
  onChange,
  shown,
}: {
  items: QueueItem[];
  accounts: OVHAccount[] | undefined;
  value: QueueFilterState;
  onChange: (next: QueueFilterState) => void;
  /** 过滤后剩几条,用于「已筛选 x / y」 */
  shown: number;
}) {
  const { t } = useTranslation();
  const facets = useMemo(() => {
    const count = (key: (it: QueueItem) => string) => {
      const m = new Map<string, number>();
      for (const it of items) m.set(key(it), (m.get(key(it)) || 0) + 1);
      return m;
    };
    const acc = count((it) => it.accountId);
    const plan = count((it) => it.planCode);
    const dc = count((it) => apiDatacenterCode(it.datacenter));
    return {
      accounts: [...acc.entries()].sort((a, b) => accountLabel(accounts, a[0]).localeCompare(accountLabel(accounts, b[0]))),
      plans: [...plan.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      dcs: [...dc.entries()].sort((a, b) => a[0].localeCompare(b[0])),
    };
  }, [items, accounts]);

  const dcName = (code: string) => {
    const dc = OVH_DATACENTERS.find((d) => apiDatacenterCode(d.code) === code);
    return dc ? `${dc.code.toUpperCase()} ${dc.name}` : code.toUpperCase();
  };
  const set = (patch: Partial<QueueFilterState>) => onChange({ ...value, ...patch });
  const active = !!(value.account || value.plan || value.dc || value.search.trim());

  const facet = (
    key: "account" | "plan" | "dc",
    label: string,
    entries: [string, number][],
    render: (v: string) => string
  ) => (
    <Select value={value[key] || ALL} onValueChange={(v) => set({ [key]: v === ALL ? "" : v })}>
      <SelectTrigger className="h-9 w-auto min-w-[8.5rem] max-w-[14rem] text-[13px]" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>
          {label} · {t("queue.filters.all")}
        </SelectItem>
        {entries.map(([v, n]) => (
          <SelectItem key={v} value={v}>
            {render(v)} ({n})
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );

  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative flex-1 min-w-[12rem] max-w-sm">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
        <Input
          value={value.search}
          onChange={(e) => set({ search: e.target.value })}
          placeholder={t("queue.filters.searchPlaceholder")}
          aria-label={t("queue.filters.searchPlaceholder")}
          className="h-9 pl-8 text-[13px]"
        />
      </div>
      {facets.accounts.length > 1 && facet("account", t("queue.filters.account"), facets.accounts, (v) => accountLabel(accounts, v))}
      {facets.plans.length > 1 && facet("plan", t("queue.filters.plan"), facets.plans, (v) => v)}
      {facets.dcs.length > 1 && facet("dc", t("queue.filters.dc"), facets.dcs, dcName)}
      <Select value={value.groupBy} onValueChange={(v) => set({ groupBy: v as QueueGroupBy })}>
        <SelectTrigger className="h-9 w-auto min-w-[8.5rem] text-[13px]" aria-label={t("queue.filters.groupBy")}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="none">{t("queue.filters.groupNone")}</SelectItem>
          <SelectItem value="account">{t("queue.filters.groupAccount")}</SelectItem>
          <SelectItem value="plan">{t("queue.filters.groupPlan")}</SelectItem>
        </SelectContent>
      </Select>
      {active && (
        <button
          type="button"
          onClick={() => onChange({ ...EMPTY_QUEUE_FILTERS, groupBy: value.groupBy })}
          className="inline-flex items-center gap-1 text-[12px] text-muted-foreground hover:text-foreground"
        >
          <X className="w-3.5 h-3.5" />
          {t("queue.filters.clear", { shown, total: items.length })}
        </button>
      )}
    </div>
  );
}

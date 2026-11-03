import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { qk } from "@/lib/query";
import { toast } from "sonner";
import i18n from "@/i18n";
import { apiMessage } from "@/lib/api-error";
import { clampOrderPlan, MAX_ORDER_QUANTITY, MAX_ORDER_FANOUT } from "@/lib/order-limits";
import { errorMessage } from "@/components/common/LoadFailed";
import { taskKey } from "@/lib/queue-share";

export type QueueStatus = "pending" | "running" | "paused" | "completed" | "failed";

export interface QueueItem {
  id: string;
  accountId: string;
  planCode: string;
  orderId?: string;
  datacenter: string;
  /** 下单成功后用 OVH 默认支付方式自动付款(显式开关,默认关) */
  autoPay?: boolean;
  coupon?: string;
  /** 优惠码被拒时仍按原价自动付款(只在 autoPay 时有意义) */
  couponFallback?: boolean;
  preorder?: boolean;
  /** 强制入队:型号还没上架也一直刷 */
  force?: boolean;
  /** 上次结账超时且没对上账,恢复后会先对账 */
  uncertainCheckout?: boolean;
  /** 锁定的整套硬件组合,只在这条 FQN 有货时下单 */
  fqn?: string;
  options: string[];
  status: QueueStatus;
  createdAt: string;
  updatedAt: string;
  retryInterval: number;
  retryCount: number;
  /** 真正提交给 OVH 并失败的次数（无货的轮次不计）。后端按它封顶重试。 */
  failureCount?: number;
  /** 后端 types.QueueItem 还会传回这几个字段（多为 omitempty），前端目前不渲染但保留类型对齐 */
  maxRetries?: number;
  lastCheckTime?: number;
  quickOrder?: boolean;
  priority?: number;
  fromTelegram?: boolean;
  configSniperTaskId?: string;
}

/** 抢购队列列表 */
export function useQueueList() {
  return useQuery({
    queryKey: qk.queue.list(),
    // Array.isArray:调用方直接 .filter/.map,truthy 非数组会整页白屏
    queryFn: async () => {
      const d = (await api.get<QueueItem[]>("/queue")).data;
      return Array.isArray(d) ? d : [];
    },
    refetchInterval: 5000,
  });
}

export interface PurchaseTiming {
 dispatch?: { wroteRequest: boolean; detectionToWriteUs: number; connectionReused: boolean; prewarmed: boolean };
  at: string;
  totalMs: number;
  phases: { name: string; ms: number }[];
  /** ordered = 真的下单了；unavailable = 那一轮没货；failed = 中途出错 */
  outcome: "ordered" | "unavailable" | "failed";
}

/**
 * 每个任务（兼容旧版机型@机房键）最近一轮的阶段耗时。
 *
 * 抢购还在跑的时候，用户最想知道的是"我到底卡在哪一步" ——
 * 是 OVH 一直没货（那就换机型），还是每轮建购物车要 3 秒（那就换台机器）。
 * 轮询频率和队列一致，多一个请求换一个能直接采取行动的答案。
 */
export function usePurchaseTimings() {
  return useQuery({
    queryKey: ["queue", "timings"],
    queryFn: async () =>
      // ?? {} 不能省:queryFn 返回 undefined 会被 react-query 当成错误抛出,
      // 整个 timings 查询翻进 isError,页面顶部弹一条"耗时读取失败"的横幅 ——
      // 而真实情况只是这一轮还没有任何计时数据。
      (await api.get<{ timings: Record<string, PurchaseTiming> }>("/queue/timings")).data?.timings ?? {},
    refetchInterval: 5000,
  });
}

/**
 * 批量创建抢购任务：对每个 datacenter × quantity 调用 POST /queue。
 * 返回成功 / 失败计数。
 *
 * 多账户:account_id 必填,后端据此决定下单走哪个账户,以及购物车的 ovhSubsidiary。
 */
export function useCreateQueueItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (payload: {
      account_id: string;
      planCode: string;
      datacenters: string[];
      options?: string[];
      retryInterval?: number;
      quantity?: number;
      autoPay?: boolean;
      coupon?: string;
      couponFallback?: boolean;
      preorder?: boolean;
      force?: boolean;
      /** 整套硬件组合(<planCode>.<段>...),只在这条 FQN 有货时下单 */
      fqn?: string;
    }) => {
      const dcs = payload.datacenters;
      // 上界以前完全没有:填 9999 × 5 个机房 = 近 5 万次串行 POST。
      // 后端 EnqueueItems 也会拒,但那是在发出几百个请求之后 —— 这里先收住。
      const plan = clampOrderPlan(dcs.length, payload.quantity ?? 1);
      const qty = plan.quantity;
      if (plan.clamped) {
        toast.warning(
          i18n.t("hooksMsg.queue.clampedWarning", {
            maxQty: MAX_ORDER_QUANTITY,
            maxTasks: MAX_ORDER_FANOUT,
            qty,
            total: plan.total,
          })
        );
      }
      let success = 0;
      let failed = 0;
      // 第一条失败原因要留下来。以前是 catch 里 failed++ 就完了,
      // 用户看到「N 个任务创建失败」却不知道为什么(比如撞上了队列总量闸门)。
      let firstError = "";
      // 后端判定「三个大区都查不到这个型号」时会带 can_force:可以改成强制入队重试
      let canForce = false;
      for (const dc of dcs) {
        for (let i = 0; i < qty; i++) {
          try {
            await api.post("/queue", {
              account_id: payload.account_id,
              planCode: payload.planCode,
              datacenter: dc,
              retryInterval: payload.retryInterval,
              options: payload.options || [],
              autoPay: payload.autoPay ?? false,
              preorder: payload.preorder ?? false,
              force: payload.force ?? false,
              coupon: payload.coupon?.trim() || undefined,
              couponFallback: payload.couponFallback ?? false,
              fqn: payload.fqn?.trim() || undefined,
            });
            success++;
          } catch (e: any) {
            failed++;
            if (!firstError) firstError = errorMessage(e);
            if (e?.response?.data?.can_force) canForce = true;
          }
        }
      }
      // 可强制入队的失败交给调用方弹选项,这里不再重复报错
      if (failed > 0 && firstError && !canForce) toast.error(i18n.t("hooksMsg.queue.someFailed", { reason: firstError }));
      return { success, failed, total: dcs.length * qty, firstError, canForce };
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue.list() });
      qc.invalidateQueries({ queryKey: qk.stats() });
    },
    onError: (e: any) => toast.error(apiMessage(e) || i18n.t("hooksMsg.queue.addFailed")),
  });
}

export function useUpdateQueueItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...patch }: { id: string; datacenter: string; options: string[]; retryInterval: number; autoPay: boolean; coupon: string; couponFallback: boolean }) =>
      (await api.put(`/queue/${encodeURIComponent(id)}`, patch)).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue.list() });
      qc.invalidateQueries({ queryKey: qk.stats() });
      toast.success(i18n.t("queue.editSaved"));
    },
    onError: (e: any) => toast.error(apiMessage(e) || i18n.t("queue.editFailed")),
  });
}

/** 切换任务状态（暂停 / 恢复） */
export function useToggleQueueItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, action }: { id: string; action: "pause" | "resume" }) =>
      (await api.put(`/queue/${id}/status`, { status: action === "pause" ? "paused" : "running" })).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue.list() });
      // 暂停/恢复改变仪表盘 activeQueues
      qc.invalidateQueries({ queryKey: qk.stats() });
    },
    onError: (e: any) => toast.error(apiMessage(e) || i18n.t("hooksMsg.queue.actionFailed")),
  });
}

/** 删除单个任务 */
/** 改单条任务的重试间隔。处理器每轮都读任务上的值，所以下一轮就生效 */
export function useUpdateQueueInterval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, retryInterval }: { id: string; retryInterval: number }) =>
      (await api.put(`/queue/${id}/interval`, { retryInterval })).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue.list() });
      toast.success(i18n.t("hooksMsg.queue.intervalUpdated"));
    },
    onError: (e: any) => toast.error(apiMessage(e) || i18n.t("hooksMsg.queue.intervalSetFailed")),
  });
}

export function useRemoveQueueItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => (await api.delete(`/queue/${id}`)).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue.list() });
      qc.invalidateQueries({ queryKey: qk.stats() });
    },
    onError: (e: any) => toast.error(apiMessage(e) || i18n.t("hooksMsg.queue.removeFailed")),
  });
}

/** 清空所有任务 */
export function useClearQueue() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => (await api.delete("/queue/clear")).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue.list() });
      qc.invalidateQueries({ queryKey: qk.stats() });
      toast.success(i18n.t("hooksMsg.queue.cleared"));
    },
    onError: (e: any) => toast.error(apiMessage(e) || i18n.t("hooksMsg.queue.clearFailed")),
  });
}

/**
 * 把已有任务原样复制到别的账户:型号、机房、配置、FQN、重试间隔、优惠码、强制入队都照搬。
 * keepAutoPay=false 时复制出来的一律不自动付款 —— 换了账户就换了钱包,得用户自己点头。
 * 目标账户已有同机房同配置的任务(没结束的)就跳过,免得一台机器排两条队、抢到两单。
 */
export function useCopyQueueItems() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (payload: {
      items: QueueItem[];
      accountIds: string[];
      keepAutoPay: boolean;
      /** 判重用的现有队列 */
      existing: QueueItem[];
    }) => {
      const live = new Set(
        payload.existing.filter((q) => q.status !== "completed" && q.status !== "failed").map(taskKey)
      );
      let created = 0;
      let skipped = 0;
      let failed = 0;
      let firstError = "";
      for (const accountId of payload.accountIds) {
        for (const it of payload.items) {
          if (it.accountId === accountId) continue;
          const key = taskKey({ ...it, accountId });
          if (live.has(key)) {
            skipped++;
            continue;
          }
          try {
            await api.post("/queue", {
              account_id: accountId,
              planCode: it.planCode,
              datacenter: it.datacenter,
              retryInterval: it.retryInterval,
              options: it.options || [],
              autoPay: payload.keepAutoPay && !!it.autoPay,
              preorder: !!it.preorder,
              force: !!it.force,
              coupon: it.coupon || undefined,
              couponFallback: payload.keepAutoPay && !!it.autoPay && !!it.couponFallback,
              fqn: it.fqn || undefined,
            });
            live.add(key);
            created++;
          } catch (e: any) {
            failed++;
            if (!firstError) firstError = apiMessage(e) || errorMessage(e);
          }
        }
      }
      return { created, skipped, failed, firstError };
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: qk.queue.list() });
      qc.invalidateQueries({ queryKey: qk.stats() });
    },
  });
}

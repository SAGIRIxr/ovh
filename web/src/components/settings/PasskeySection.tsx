/**
 * 通行证管理(设置 → 访问密码 一节的下半部分):
 * 列表 / 添加(要再输一次访问密钥)/ 删除(连带它登录出来的会话)/ 退出登录。
 */
import { useState } from "react";
import { Fingerprint, Loader2, LogOut, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, clearApiSecretKey, getSessionToken } from "@/lib/api";
import { apiMessage } from "@/lib/api-error";
import { createPasskey, isPasskeyCancel, passkeySupported } from "@/lib/passkey";
import { fmtDateTime } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Chip } from "@/components/common/Chip";
import { Switch } from "@/components/ui/switch";

interface PasskeyRow {
  id: number;
  name: string;
  rpId: string;
  createdAt: string;
  lastUsed?: string;
  active: boolean;
  currentDomain: boolean;
  sessions: number;
}

const QK = ["auth", "passkeys"];
// 详细说明、找回方法(应急文件)、密码管理器提示都在这份文档里,界面上只放一句话
export const PASSKEY_DOC = "https://github.com/SAGIRIxr/ovh/blob/main/docs/passkey.md";

export function PasskeySection() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: QK,
    queryFn: async () =>
      (await api.get<{ passkeys: PasskeyRow[]; domainOk: boolean; domainError?: string }>("/auth/passkeys")).data,
  });
  const keyLogin = useQuery({
    queryKey: ["auth", "key-login"],
    queryFn: async () =>
      (await api.get<{ disabled: boolean; emergencyFile: boolean; emergencyPath: string; viaPasskey: boolean }>("/auth/key-login")).data,
  });
  const setKeyLogin = useMutation({
    mutationFn: async (disabled: boolean) => api.post("/auth/key-login", { disabled }),
    onSuccess: (_r, disabled) => {
      toast.success(t(disabled ? "settings.passkey.keyLoginOff" : "settings.passkey.keyLoginOn"));
      qc.invalidateQueries({ queryKey: ["auth", "key-login"] });
    },
    onError: (e) => toast.error(apiMessage(e) || t("settings.passkey.keyLoginFailed")),
  });
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [apiKey, setApiKey] = useState("");

  const register = useMutation({
    mutationFn: async () => {
      const begin = await api.post("/auth/passkeys/register/begin", { apiKey: apiKey.trim(), name: name.trim() });
      const credential = await createPasskey(begin.data.options);
      await api.post("/auth/passkeys/register/finish", { flowId: begin.data.flowId, credential });
    },
    onSuccess: () => {
      toast.success(t("settings.passkey.added"));
      setAdding(false);
      setName("");
      setApiKey("");
      qc.invalidateQueries({ queryKey: QK });
    },
    onError: (e) => {
      if (!isPasskeyCancel(e)) toast.error(apiMessage(e) || (e as Error)?.message || t("settings.passkey.addFailed"));
    },
  });
  const remove = useMutation({
    mutationFn: async (id: number) => api.delete(`/auth/passkeys/${id}`),
    onSuccess: () => {
      toast.success(t("settings.passkey.deleted"));
      qc.invalidateQueries({ queryKey: QK });
    },
    onError: (e) => toast.error(apiMessage(e) || t("settings.passkey.deleteFailed")),
  });

  const logout = async () => {
    try {
      // 通行证会话在服务端作废;访问密钥登录的没有服务端会话,清本地即可
      await api.post("/auth/logout");
    } catch {
      // 退出不能因为网络问题卡住
    }
    clearApiSecretKey();
    window.location.reload();
  };

  const supported = passkeySupported();
  const domainOk = list.data?.domainOk ?? true;
  const viaSession = !!getSessionToken();

  return (
    <div className="space-y-3 pt-2">
      <div className="flex items-center gap-2">
        <Fingerprint className="w-4 h-4 text-muted-foreground" />
        <h3 className="text-[14px] font-semibold">{t("settings.passkey.title")}</h3>
        <a href={PASSKEY_DOC} target="_blank" rel="noreferrer" className="ml-auto text-[11px] text-muted-foreground underline underline-offset-2 hover:text-foreground">
          {t("settings.passkey.docLink")}
        </a>
      </div>

      {!supported ? (
        <p className="text-[12px] text-warning">{t("settings.passkey.unsupported")}</p>
      ) : !domainOk ? (
        <p className="text-[12px] text-warning">{list.data?.domainError}</p>
      ) : adding ? (
        <div className="rounded-xl border border-border p-3 space-y-2">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("settings.passkey.namePlaceholder")} maxLength={40} />
          <Input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={t("settings.passkey.keyPlaceholder")}
            autoComplete="off"
          />
          <div className="flex gap-2">
            <Button size="sm" onClick={() => register.mutate()} disabled={register.isPending || !apiKey.trim()}>
              {register.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Fingerprint className="w-3.5 h-3.5" />}
              {t("settings.passkey.create")}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setAdding(false)} disabled={register.isPending}>
              {t("settings.passkey.cancel")}
            </Button>
          </div>
        </div>
      ) : (
        <Button size="sm" variant="outline" onClick={() => setAdding(true)}>
          <Plus className="w-3.5 h-3.5" />
          {t("settings.passkey.add")}
        </Button>
      )}

      <div className="space-y-2">
        {(list.data?.passkeys || []).map((p) => (
          <div key={p.id} className="flex items-center gap-3 rounded-xl border border-border px-3 py-2">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[13px] font-medium">{p.name}</span>
                <Chip className="font-mono">{p.rpId}</Chip>
                {!p.active && <Chip tone="warning" title={t("settings.passkey.inactiveTitle")}>{t("settings.passkey.inactive")}</Chip>}
                {p.active && !p.currentDomain && <Chip>{t("settings.passkey.otherDomain")}</Chip>}
              </div>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {t("settings.passkey.meta", {
                  created: fmtDateTime(p.createdAt),
                  used: p.lastUsed ? fmtDateTime(p.lastUsed) : t("settings.passkey.neverUsed"),
                  sessions: p.sessions,
                })}
              </p>
            </div>
            <Button
              size="icon"
              variant="ghost"
              aria-label={t("settings.passkey.delete")}
              title={t("settings.passkey.delete")}
              disabled={remove.isPending}
              onClick={() => {
                if (window.confirm(t("settings.passkey.deleteConfirm", { name: p.name }))) remove.mutate(p.id);
              }}
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        ))}
        {list.data && list.data.passkeys.length === 0 && (
          <p className="text-[12px] text-muted-foreground">{t("settings.passkey.empty")}</p>
        )}
      </div>

      {keyLogin.data && (
        <div className="rounded-xl border border-border p-3 space-y-1.5">
          <label className="flex items-center justify-between gap-3 cursor-pointer">
            <span className="text-[13px] font-medium">{t("settings.passkey.disableKeyLogin")}</span>
            <Switch
              checked={keyLogin.data.disabled}
              disabled={setKeyLogin.isPending || (!keyLogin.data.disabled && !keyLogin.data.viaPasskey)}
              onCheckedChange={(v) => {
                if (v && !window.confirm(t("settings.passkey.disableConfirm"))) return;
                setKeyLogin.mutate(v);
              }}
            />
          </label>
          <p className="text-[11px] text-muted-foreground">
            {!keyLogin.data.disabled && !keyLogin.data.viaPasskey
              ? t("settings.passkey.disableNeedsPasskey")
              : t("settings.passkey.disableHint")}
          </p>
          {keyLogin.data.disabled && keyLogin.data.emergencyFile && (
            <p className="text-[11px] text-warning">{t("settings.passkey.emergencyActive")}</p>
          )}
        </div>
      )}

      <div className="pt-2 border-t border-border flex items-center justify-between gap-2">
        <p className="text-[11px] text-muted-foreground">
          {viaSession ? t("settings.passkey.loggedInViaPasskey") : t("settings.passkey.loggedInViaKey")}
        </p>
        <Button size="sm" variant="outline" onClick={() => void logout()}>
          <LogOut className="w-3.5 h-3.5" />
          {t("settings.passkey.logout")}
        </Button>
      </div>
    </div>
  );
}

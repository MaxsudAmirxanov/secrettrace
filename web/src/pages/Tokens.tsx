import { useState } from "react";

import { useCreateToken, useRevokeToken, useTokens } from "../api/hooks";
import type { CreatedToken, SourceType, TokenInfo, TokenKind } from "../api/types";
import { IconPlus, IconToken } from "../components/icons";
import { ConfirmDialog, Modal } from "../components/Modal";
import { DataTable } from "../components/Table";
import { Time } from "../components/Time";
import { useToast } from "../components/Toast";
import { Badge, Button, Checkbox, CopyButton, ErrorBanner, Field, Input, Mono, Notice, PageHeader, Select } from "../components/ui";
import { formatDate } from "../lib/format";
import { API_SCOPES, SOURCE_TYPE_LABELS, TOKEN_KIND_LABELS } from "../lib/labels";

const NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Optional binding fields: empty strings are not sent. */
export function bindingFields(f: { certCn: string; sourceType: string; uriPattern: string; environment: string }) {
  const out: { cert_cn?: string; source_type?: SourceType; source_uri_pattern?: string; environment?: string } = {};
  if (f.certCn.trim()) out.cert_cn = f.certCn.trim();
  if (f.sourceType) out.source_type = f.sourceType as SourceType;
  if (f.uriPattern.trim()) out.source_uri_pattern = f.uriPattern.trim();
  if (f.environment.trim()) out.environment = f.environment.trim();
  return out;
}

/** Validation message for the binding fields, or null. */
export function bindingError(f: { certCn: string; environment: string }): string | null {
  if (f.certCn.trim() && !NAME_RE.test(f.certCn.trim())) return "CN: 1–64 символа из A–Z, a–z, 0–9, «.», «_», «-»";
  if (f.environment.trim() && !NAME_RE.test(f.environment.trim()))
    return "Окружение: 1–64 символа из A–Z, a–z, 0–9, «.», «_», «-»";
  return null;
}

function tokenState(t: TokenInfo): { label: string; tone: "green" | "gray" | "amber" } {
  if (t.revoked_at) return { label: "Отозван", tone: "gray" };
  if (t.expires_at && new Date(t.expires_at).getTime() <= Date.now()) return { label: "Истёк", tone: "amber" };
  return { label: "Активен", tone: "green" };
}

function CreateModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (t: CreatedToken) => void }) {
  const create = useCreateToken();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<TokenKind>("ci");
  const [scopes, setScopes] = useState<string[]>(API_SCOPES.map((s) => s.id));
  const [days, setDays] = useState("90");
  const [certCn, setCertCn] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [uriPattern, setUriPattern] = useState("");
  const [environment, setEnvironment] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [bindErr, setBindErr] = useState<string | null>(null);

  const submit = () => {
    if (!name.trim()) return setErr("Укажите имя");
    if (scopes.length === 0) return setErr("Выберите хотя бы одно право");
    setErr(null);
    const b = bindingError({ certCn, environment });
    setBindErr(b);
    if (b) return;
    create.mutate(
      {
        name: name.trim(),
        kind,
        scopes,
        expires_in_days: Number(days),
        ...bindingFields({ certCn, sourceType, uriPattern, environment }),
      },
      { onSuccess: (t) => onCreated(t) },
    );
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Новый API-токен"
      footer={
        <>
          <Button onClick={onClose}>Отмена</Button>
          <Button variant="primary" loading={create.isPending} onClick={submit}>
            Выпустить
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Имя" required error={err}>
          {(id, d) => <Input id={id} aria-describedby={d} value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="gitlab-ci-infra" />}
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Тип">
            {(id) => (
              <Select id={id} value={kind} onChange={(e) => setKind(e.target.value as TokenKind)}>
                {Object.entries(TOKEN_KIND_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Срок действия">
            {(id) => (
              <Select id={id} value={days} onChange={(e) => setDays(e.target.value)}>
                {["7", "30", "90", "180", "365"].map((d) => (
                  <option key={d} value={d}>
                    {d} дн.
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <fieldset className="space-y-2">
          <legend className="label">Права</legend>
          {API_SCOPES.map((s) => (
            <Checkbox
              key={s.id}
              checked={scopes.includes(s.id)}
              onChange={(c) => setScopes((cur) => (c ? [...cur, s.id] : cur.filter((x) => x !== s.id)))}
              label={s.label}
              hint={s.id}
            />
          ))}
        </fieldset>
        <fieldset className="space-y-3">
          <legend className="label">Привязка</legend>
          <p className="text-xs text-slate-500">
            Токен с CN принимается только через mTLS-порт с клиентским сертификатом этого CN (выпуск:{" "}
            <code>make client-cert CN=…</code>). Остальные поля ограничивают, о каких источниках и под каким окружением
            токен может сообщать. Пустое поле — без ограничения.
          </p>
          <Field label="CN клиентского сертификата" error={bindErr}>
            {(id, d) => (
              <Input id={id} aria-describedby={d} value={certCn} onChange={(e) => setCertCn(e.target.value)} maxLength={64} placeholder="ci-infra" />
            )}
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Тип источника">
              {(id) => (
                <Select id={id} value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
                  <option value="">Любой</option>
                  {Object.entries(SOURCE_TYPE_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Окружение">
              {(id) => <Input id={id} value={environment} onChange={(e) => setEnvironment(e.target.value)} maxLength={64} placeholder="ci" />}
            </Field>
          </div>
          <Field label="Шаблон URI источника">
            {(id) => (
              <Input id={id} value={uriPattern} onChange={(e) => setUriPattern(e.target.value)} maxLength={2048} placeholder="https://git.example.com/acme/**" />
            )}
          </Field>
        </fieldset>
        {create.error && <ErrorBanner error={create.error} />}
      </div>
    </Modal>
  );
}

function TokenBinding({ t }: { t: TokenInfo }) {
  const parts = [
    t.cert_cn && `CN ${t.cert_cn}`,
    t.source_type && SOURCE_TYPE_LABELS[t.source_type],
    t.source_uri_pattern,
    t.environment && `env ${t.environment}`,
  ].filter(Boolean) as string[];
  if (parts.length === 0) return <span className="text-xs text-slate-500">нет</span>;
  return (
    <div className="flex max-w-xs flex-col gap-0.5 text-xs">
      {parts.map((p) => (
        <Mono key={p}>{p}</Mono>
      ))}
    </div>
  );
}

export function TokensPage() {
  const toast = useToast();
  const { data, error, isLoading, refetch } = useTokens();
  const revoke = useRevokeToken();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [toRevoke, setToRevoke] = useState<TokenInfo | null>(null);
  const items = data ?? [];

  return (
    <>
      <PageHeader
        title="API-токены"
        description="Учётные данные для CI и агентов. Сервер хранит только хеш; значение показывается один раз при выпуске. Токены всегда имеют срок действия."
        actions={
          <Button variant="primary" icon={<IconPlus size={16} />} onClick={() => setCreating(true)}>
            Выпустить токен
          </Button>
        }
      />
      <DataTable
        loading={isLoading}
        error={error}
        onRetry={() => void refetch()}
        empty={items.length === 0}
        emptyIcon={<IconToken />}
        emptyTitle="Токенов нет"
        emptyText="Выпустите токен для CI, чтобы сканировать репозитории в пайплайне."
        head={
          <tr>
            <th>Токен</th>
            <th>Права</th>
            <th>Привязка</th>
            <th>Состояние</th>
            <th>Использован</th>
            <th>Истекает</th>
            <th />
          </tr>
        }
      >
        {items.map((t) => {
          const st = tokenState(t);
          return (
            <tr key={t.id}>
              <td>
                <p className="font-medium text-slate-900 dark:text-white">{t.name}</p>
                <p className="text-xs text-slate-500">
                  {TOKEN_KIND_LABELS[t.kind]} · <Mono>{t.token_prefix}…</Mono>
                </p>
              </td>
              <td>
                <div className="flex max-w-xs flex-wrap gap-1">
                  {t.scopes.map((s) => (
                    <Badge key={s}>{s}</Badge>
                  ))}
                </div>
              </td>
              <td>
                <TokenBinding t={t} />
              </td>
              <td>
                <Badge tone={st.tone} dot>
                  {st.label}
                </Badge>
              </td>
              <td>
                <Time iso={t.last_used_at} fallback="никогда" />
              </td>
              <td className="whitespace-nowrap">{formatDate(t.expires_at)}</td>
              <td className="text-right">
                {st.label === "Активен" && (
                  <Button size="sm" variant="ghost" className="text-rose-600" onClick={() => setToRevoke(t)}>
                    Отозвать
                  </Button>
                )}
              </td>
            </tr>
          );
        })}
      </DataTable>

      {creating && (
        <CreateModal
          open
          onClose={() => setCreating(false)}
          onCreated={(t) => {
            setCreating(false);
            setCreated(t);
          }}
        />
      )}
      <Modal
        open={created !== null}
        dismissible={false}
        onClose={() => setCreated(null)}
        title="Токен выпущен"
        footer={
          <Button variant="primary" onClick={() => setCreated(null)}>
            Я сохранил токен
          </Button>
        }
      >
        {created && (
          <div className="space-y-4">
            <Notice tone="amber" title="Скопируйте токен сейчас">
              Он показывается один раз и нигде не хранится в открытом виде. Сохраните его в секретах CI (например, как
              переменную <code>SECRETTRACE_TOKEN</code> с флагами masked/protected).
            </Notice>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs dark:bg-slate-800">{created.token}</code>
              <CopyButton value={created.token} />
            </div>
          </div>
        )}
      </Modal>
      <ConfirmDialog
        open={toRevoke !== null}
        title="Отозвать токен?"
        confirmLabel="Отозвать"
        danger
        loading={revoke.isPending}
        onClose={() => setToRevoke(null)}
        onConfirm={() =>
          toRevoke &&
          revoke.mutate(toRevoke.id, {
            onSuccess: () => {
              toast.success("Токен отозван");
              setToRevoke(null);
            },
            onError: (e) => toast.error(e),
          })
        }
      >
        Токен «{toRevoke?.name}» перестанет работать немедленно. CI, который его использует, начнёт получать 401.
      </ConfirmDialog>
    </>
  );
}

import { useState } from "react";
import { Link } from "react-router-dom";

import { errorMessage } from "../api/client";
import { flatten, useAudit, verifyAudit } from "../api/hooks";
import type { AuditEntry, AuditVerify } from "../api/types";
import { IconAudit, IconShield } from "../components/icons";
import { DataTable, LoadMore } from "../components/Table";
import { Time } from "../components/Time";
import { Badge, Button, Card, CopyButton, Input, Mono, PageHeader, Select, type Tone } from "../components/ui";
import { formatDateTime } from "../lib/format";
import { useSyncedSearch, useUrlFilters } from "../lib/hooks";

const ACTION_GROUPS = [
  { value: "", label: "Все действия" },
  { value: "auth.", label: "Вход и сессии" },
  { value: "user.", label: "Пользователи" },
  { value: "secret.", label: "Секреты" },
  { value: "source.", label: "Источники" },
  { value: "scan.", label: "Сканы" },
  { value: "ingest.", label: "Данные от CI" },
  { value: "api_token.", label: "API-токены" },
] as const;

function actionTone(action: string): Tone {
  if (action.includes("failed") || action.includes("tampered")) return "red";
  if (action.startsWith("auth.")) return "blue";
  if (action.endsWith(".delete") || action.includes("revoke") || action.includes("reset")) return "amber";
  if (action.endsWith(".create")) return "green";
  return "gray";
}

function targetLink(e: AuditEntry): string | null {
  if (!e.target_id) return null;
  switch (e.target_type) {
    case "secret":
      return `/secrets/${e.target_id}`;
    case "source":
      return `/sources/${e.target_id}`;
    case "scan":
    case "scan_job":
      return `/scans/${e.target_id}`;
    default:
      return null;
  }
}

function Details({ value }: { value: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  const keys = Object.keys(value);
  if (keys.length === 0) return <span className="text-slate-400">—</span>;
  const preview = keys
    .slice(0, 3)
    .map((k) => {
      const v = value[k];
      return `${k}: ${v === null ? "—" : typeof v === "object" ? "{…}" : String(v)}`;
    })
    .join(", ");
  return (
    <div className="max-w-xs">
      <button type="button" className="text-left text-xs text-slate-600 hover:text-slate-900 dark:text-slate-300" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        {open ? "Скрыть" : preview.length > 60 ? `${preview.slice(0, 60)}…` : preview}
      </button>
      {open && (
        <pre className="mt-1 max-h-60 overflow-auto rounded bg-slate-100 p-2 font-mono text-[11px] dark:bg-slate-800">{JSON.stringify(value, null, 2)}</pre>
      )}
    </div>
  );
}

function VerifyCard() {
  const [result, setResult] = useState<AuditVerify | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await verifyAudit());
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <div className="flex flex-wrap items-start gap-4">
        <span className="rounded-lg bg-brand-50 p-2.5 text-brand-600 dark:bg-brand-500/10 dark:text-brand-300">
          <IconShield />
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-slate-900 dark:text-white">Целостность журнала</p>
          <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
            Каждая запись содержит SHA-256 предыдущей. Проверка пересчитывает всю цепочку и находит изменённые записи.
            Сохраняйте хеш последней записи отдельно — так обнаруживается и удаление хвоста.
          </p>
          {error && <p className="mt-2 text-sm text-rose-600">{error}</p>}
          {result &&
            (result.ok ? (
              <div className="mt-3 space-y-2 text-sm">
                <Badge tone="green" dot>
                  Цепочка цела: {result.rows} записей
                </Badge>
                {result.head && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-slate-500">Хеш последней записи:</span>
                    <Mono className="break-all">{result.head}</Mono>
                    <CopyButton value={result.head} />
                  </div>
                )}
              </div>
            ) : (
              <div className="mt-3">
                <Badge tone="red" dot>
                  Цепочка нарушена на записи #{result.broken_at}: {result.reason}
                </Badge>
              </div>
            ))}
        </div>
        <Button onClick={() => void run()} loading={busy}>
          Проверить
        </Button>
      </div>
    </Card>
  );
}

export function AuditPage() {
  const [f, set] = useUrlFilters(["action", "actor_id", "target_id"] as const);
  const [action, setAction] = useSyncedSearch(f.action, (v) => set("action", v));
  const [actor, setActor] = useSyncedSearch(f.actor_id, (v) => set("actor_id", v));
  const [target, setTarget] = useSyncedSearch(f.target_id, (v) => set("target_id", v));
  const query = useAudit({ action: f.action || undefined, actor_id: f.actor_id || undefined, target_id: f.target_id || undefined });
  const items = flatten(query.data?.pages);
  const group = ACTION_GROUPS.some((g) => g.value === f.action) ? f.action : "custom";

  return (
    <>
      <PageHeader title="Журнал аудита" description="Все действия пользователей, токенов и системы. Журнал только дополняется; значения секретов в него не попадают." />
      <div className="mb-6">
        <VerifyCard />
      </div>
      <div className="mb-4 grid gap-3 sm:grid-cols-4">
        <Select value={group} onChange={(e) => e.target.value !== "custom" && setAction(e.target.value)} aria-label="Группа действий">
          {ACTION_GROUPS.map((g) => (
            <option key={g.value} value={g.value}>
              {g.label}
            </option>
          ))}
          {group === "custom" && <option value="custom">Своё: {f.action}</option>}
        </Select>
        <Input value={action} onChange={(e) => setAction(e.target.value)} placeholder="Действие, напр. secret.create" aria-label="Действие" maxLength={100} />
        <Input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="ID исполнителя" aria-label="Исполнитель" maxLength={200} />
        <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="ID объекта" aria-label="Объект" maxLength={200} />
      </div>
      <DataTable
        loading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
        empty={items.length === 0}
        emptyIcon={<IconAudit />}
        emptyTitle="Записей нет"
        head={
          <tr>
            <th>#</th>
            <th>Время</th>
            <th>Кто</th>
            <th>Действие</th>
            <th>Объект</th>
            <th>IP</th>
            <th>Подробности</th>
          </tr>
        }
        footer={<LoadMore count={items.length} hasNext={!!query.hasNextPage} loading={query.isFetchingNextPage} onLoad={() => void query.fetchNextPage()} />}
      >
        {items.map((e) => {
          const link = targetLink(e);
          return (
            <tr key={e.id}>
              <td className="tabular-nums text-slate-400">{e.id}</td>
              <td title={formatDateTime(e.ts)}>
                <Time iso={e.ts} />
              </td>
              <td>
                <button type="button" className="text-left hover:underline" onClick={() => setActor(e.actor_id)} title="Показать только этого исполнителя">
                  <span className="font-medium text-slate-900 dark:text-white">{e.actor_name ?? (e.actor_type === "system" ? "система" : e.actor_id.slice(0, 8))}</span>
                  <span className="block text-xs text-slate-500">{e.actor_type === "user" ? "пользователь" : e.actor_type === "token" ? "токен" : "система"}</span>
                </button>
              </td>
              <td>
                <Badge tone={actionTone(e.action)}>{e.action}</Badge>
              </td>
              <td className="text-xs">
                {e.target_type ? (
                  <>
                    <span className="text-slate-500">{e.target_type} </span>
                    {link ? (
                      <Link to={link} className="link font-mono">
                        {e.target_id?.slice(0, 8)}
                      </Link>
                    ) : (
                      <span className="font-mono">{e.target_id?.slice(0, 8)}</span>
                    )}
                  </>
                ) : (
                  <span className="text-slate-400">—</span>
                )}
              </td>
              <td className="font-mono text-xs">{e.ip ?? "—"}</td>
              <td>
                <Details value={e.details} />
              </td>
            </tr>
          );
        })}
      </DataTable>
    </>
  );
}

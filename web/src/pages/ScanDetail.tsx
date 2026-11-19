import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { useCancelScan, useScan } from "../api/hooks";
import { Can } from "../auth/guards";
import { JobStatusBadge } from "../components/badges";
import { IconStop } from "../components/icons";
import { ConfirmDialog } from "../components/Modal";
import { useToast } from "../components/Toast";
import { Badge, Button, Card, DescriptionList, ErrorBanner, PageHeader, PageLoader, cx } from "../components/ui";
import { formatDateTime, formatDuration, shortId } from "../lib/format";
import { TRIGGER_LABELS } from "../lib/labels";
import { statRows } from "../lib/stats";

export function ScanDetailPage() {
  const { id = "" } = useParams();
  const toast = useToast();
  const { data: s, error, isLoading, refetch } = useScan(id);
  const cancel = useCancelScan();
  const [confirm, setConfirm] = useState(false);

  if (isLoading) return <PageLoader />;
  if (error || !s) return <ErrorBanner error={error} onRetry={() => void refetch()} />;

  const active = s.status === "queued" || s.status === "running";
  const worker = s.trigger === "manual" || s.trigger === "schedule";
  const rows = statRows(s.stats);

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/scans" className="link">
            ← Сканы
          </Link>
        }
        title={`Скан ${shortId(s.id)}`}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <JobStatusBadge status={s.status} />
            <span>{TRIGGER_LABELS[s.trigger]}</span>
            {s.full_scan && <Badge tone="violet">вся история</Badge>}
          </span>
        }
        actions={
          active &&
          worker && (
            <Can role="operator">
              <Button variant="danger" icon={<IconStop size={14} />} onClick={() => setConfirm(true)}>
                Отменить
              </Button>
            </Can>
          )
        }
      />
      {s.error && (
        <div className="mb-6">
          <ErrorBanner error={new Error(s.error)} />
        </div>
      )}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Запуск" className="lg:col-span-1">
          <DescriptionList
            items={[
              [
                "Источник",
                s.source_id ? (
                  <Link to={`/sources/${s.source_id}`} className="link">
                    {s.source_name ?? shortId(s.source_id)}
                  </Link>
                ) : (
                  "удалён"
                ),
              ],
              ["Попыток", s.attempts],
              ["Создан", formatDateTime(s.created_at)],
              ["Начат", formatDateTime(s.started_at)],
              ["Завершён", formatDateTime(s.finished_at)],
              ["Длительность", s.started_at ? formatDuration(s.started_at, s.finished_at) : "—"],
              ...(s.status === "queued" ? ([["Не раньше", formatDateTime(s.run_after)]] as [string, string][]) : []),
            ]}
          />
        </Card>
        <Card title="Результаты" className="lg:col-span-2">
          {rows.length === 0 ? (
            <p className="text-sm text-slate-500">{active ? "Скан ещё выполняется…" : "Счётчиков нет"}</p>
          ) : (
            <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              {rows.map((r) => (
                <div key={r.key} className="rounded-lg bg-slate-50 px-4 py-3 dark:bg-slate-800/50">
                  <dt className="text-xs text-slate-500 dark:text-slate-400">{r.label}</dt>
                  <dd
                    className={cx(
                      "mt-1 text-lg font-semibold tabular-nums",
                      r.emphasis === "danger" && "text-rose-600 dark:text-rose-400",
                      r.emphasis === "muted" && "text-slate-500",
                    )}
                  >
                    {r.value}
                  </dd>
                </div>
              ))}
            </dl>
          )}
          {s.source_id && !active && (
            <p className="mt-4 text-sm">
              <Link to={`/findings?source_id=${s.source_id}`} className="link">
                Находки этого источника →
              </Link>
            </p>
          )}
        </Card>
      </div>
      <ConfirmDialog
        open={confirm}
        title="Отменить скан?"
        confirmLabel="Отменить скан"
        danger
        loading={cancel.isPending}
        onClose={() => setConfirm(false)}
        onConfirm={() =>
          cancel.mutate(s.id, {
            onSuccess: () => {
              toast.success("Скан отменён");
              setConfirm(false);
            },
            onError: (e) => toast.error(e),
          })
        }
      >
        Воркер остановит git и сканирование. Найденное до отмены не записывается.
      </ConfirmDialog>
    </>
  );
}

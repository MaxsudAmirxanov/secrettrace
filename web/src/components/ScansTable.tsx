import { Link, useNavigate } from "react-router-dom";

import { flatten, useScans } from "../api/hooks";
import type { JobStatus, ScanTrigger } from "../api/types";
import { formatDuration, formatNumber } from "../lib/format";
import { TRIGGER_LABELS } from "../lib/labels";
import { JobStatusBadge } from "./badges";
import { IconScan } from "./icons";
import { DataTable, LoadMore } from "./Table";
import { Time } from "./Time";
import { Badge } from "./ui";

export function ScansTable({
  sourceId,
  status,
  trigger,
  showSource = true,
}: {
  sourceId?: string;
  status?: JobStatus;
  trigger?: ScanTrigger;
  showSource?: boolean;
}) {
  const navigate = useNavigate();
  const query = useScans({ source_id: sourceId, status, trigger });
  const items = flatten(query.data?.pages);
  return (
    <DataTable
      loading={query.isLoading}
      error={query.error}
      onRetry={() => void query.refetch()}
      empty={items.length === 0}
      emptyIcon={<IconScan />}
      emptyTitle="Сканов нет"
      head={
        <tr>
          {showSource && <th>Источник</th>}
          <th>Запуск</th>
          <th>Статус</th>
          <th>Создан</th>
          <th>Длительность</th>
          <th className="text-right">Совпадений</th>
          <th className="text-right">Нарушений</th>
        </tr>
      }
      footer={<LoadMore count={items.length} hasNext={!!query.hasNextPage} loading={query.isFetchingNextPage} onLoad={() => void query.fetchNextPage()} />}
    >
      {items.map((s) => {
        const matched = typeof s.stats.matched === "number" ? s.stats.matched : undefined;
        const violations = typeof s.stats.violations === "number" ? s.stats.violations : undefined;
        return (
          <tr key={s.id} className="clickable" tabIndex={0} onClick={() => navigate(`/scans/${s.id}`)} onKeyDown={(e) => e.key === "Enter" && navigate(`/scans/${s.id}`)}>
            {showSource && (
              <td>
                {s.source_id ? (
                  <Link to={`/sources/${s.source_id}`} className="link" onClick={(e) => e.stopPropagation()}>
                    {s.source_name ?? s.source_id.slice(0, 8)}
                  </Link>
                ) : (
                  <span className="text-slate-400">удалён</span>
                )}
              </td>
            )}
            <td>
              <span className="whitespace-nowrap">{TRIGGER_LABELS[s.trigger]}</span>
              {s.full_scan && (
                <span className="ml-1.5">
                  <Badge tone="violet">вся история</Badge>
                </span>
              )}
            </td>
            <td>
              <JobStatusBadge status={s.status} />
              {s.error && (
                <p className="mt-1 max-w-xs truncate text-xs text-rose-600 dark:text-rose-400" title={s.error}>
                  {s.error}
                </p>
              )}
            </td>
            <td>
              <Time iso={s.created_at} />
            </td>
            <td className="whitespace-nowrap tabular-nums">{s.started_at ? formatDuration(s.started_at, s.finished_at) : "—"}</td>
            <td className="text-right tabular-nums">{matched === undefined ? "—" : formatNumber(matched)}</td>
            <td className="text-right tabular-nums">
              {violations === undefined ? "—" : violations > 0 ? <Badge tone="red">{violations}</Badge> : "0"}
            </td>
          </tr>
        );
      })}
    </DataTable>
  );
}

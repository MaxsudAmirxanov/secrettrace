import { Link, useNavigate } from "react-router-dom";

import { flatten, useSources } from "../api/hooks";
import { Can } from "../auth/guards";
import { JobStatusBadge } from "../components/badges";
import { IconPlus, IconRepo } from "../components/icons";
import { DataTable, LoadMore } from "../components/Table";
import { Time } from "../components/Time";
import { Badge, Mono, PageHeader, Select } from "../components/ui";
import { useUrlFilters } from "../lib/hooks";
import { SOURCE_TYPE_LABELS } from "../lib/labels";

export function SourcesPage() {
  const navigate = useNavigate();
  const [f, set] = useUrlFilters(["enabled"] as const);
  const query = useSources({ enabled: f.enabled === "" ? undefined : f.enabled === "true" });
  const items = flatten(query.data?.pages);

  return (
    <>
      <PageHeader
        title="Источники"
        description="Git-репозитории, которые сервер сканирует сам, и источники, о которых сообщили CI и агенты."
        actions={
          <Can role="operator">
            <Link to="/sources/new" className="btn btn-primary">
              <IconPlus size={16} /> Добавить репозиторий
            </Link>
          </Can>
        }
      />
      <div className="mb-4 flex">
        <Select value={f.enabled} onChange={(e) => set("enabled", e.target.value)} aria-label="Состояние" className="sm:w-48">
          <option value="">Все</option>
          <option value="true">Включённые</option>
          <option value="false">Выключенные</option>
        </Select>
      </div>
      <DataTable
        loading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
        empty={items.length === 0}
        emptyIcon={<IconRepo />}
        emptyTitle="Источников нет"
        emptyText="Добавьте git-репозиторий для серверного сканирования или подключите CI через API-токен."
        head={
          <tr>
            <th>Источник</th>
            <th>Расписание</th>
            <th>Доступ</th>
            <th>Последний скан</th>
            <th>Следующий</th>
            <th>Состояние</th>
          </tr>
        }
        footer={<LoadMore count={items.length} hasNext={!!query.hasNextPage} loading={query.isFetchingNextPage} onLoad={() => void query.fetchNextPage()} />}
      >
        {items.map((s) => (
          <tr key={s.id} className="clickable" tabIndex={0} onClick={() => navigate(`/sources/${s.id}`)} onKeyDown={(e) => e.key === "Enter" && navigate(`/sources/${s.id}`)}>
            <td className="max-w-sm">
              <p className="font-medium text-slate-900 dark:text-white">{s.name}</p>
              <p className="truncate font-mono text-xs text-slate-500" title={s.uri}>
                {s.uri}
              </p>
              <p className="mt-0.5 text-xs text-slate-400">
                {SOURCE_TYPE_LABELS[s.type]}
                {s.environment && ` · ${s.environment}`}
              </p>
            </td>
            <td>{s.schedule ? <Mono>{s.schedule}</Mono> : <span className="text-slate-400">вручную</span>}</td>
            <td>{s.credential_ref ? <Mono>{s.credential_ref}</Mono> : <span className="text-slate-400">публичный</span>}</td>
            <td>
              <Time iso={s.last_scan_at} fallback="не было" />
            </td>
            <td>
              <Time iso={s.next_scan_at} />
            </td>
            <td>
              <div className="flex flex-wrap gap-1">
                {s.active_scan ? <JobStatusBadge status={s.active_scan.status} /> : null}
                {!s.enabled && <Badge>Выключен</Badge>}
                {s.enabled && !s.active_scan && <Badge tone="green">Готов</Badge>}
              </div>
            </td>
          </tr>
        ))}
      </DataTable>
    </>
  );
}

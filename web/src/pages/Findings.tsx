import { Link } from "react-router-dom";

import { flatten, useFindings } from "../api/hooks";
import { FindingBadges } from "../components/badges";
import { FindingWhere } from "../components/FindingRow";
import { IconAlert, IconSearch } from "../components/icons";
import { DataTable, LoadMore } from "../components/Table";
import { Time } from "../components/Time";
import { Badge, Input, Mono, PageHeader, Select, cx } from "../components/ui";
import { boolParam, useSyncedSearch, useUrlFilters } from "../lib/hooks";
import { SECRET_TYPE_LABELS } from "../lib/labels";

const KEYS = ["is_allowed", "in_current_state", "q", "environment", "secret_id", "source_id"] as const;

const PRESETS = [
  { label: "Все", is_allowed: "", in_current_state: "" },
  { label: "Открытые нарушения", is_allowed: "false", in_current_state: "true" },
  { label: "Только в истории", is_allowed: "false", in_current_state: "false" },
  { label: "Разрешённые", is_allowed: "true", in_current_state: "" },
] as const;

export function FindingsPage() {
  const [f, set, setMany] = useUrlFilters(KEYS);
  const [q, setQ] = useSyncedSearch(f.q, (v) => set("q", v));
  const [env, setEnv] = useSyncedSearch(f.environment, (v) => set("environment", v));
  const query = useFindings({
    is_allowed: boolParam(f.is_allowed),
    in_current_state: boolParam(f.in_current_state),
    q: f.q || undefined,
    environment: f.environment || undefined,
    secret_id: f.secret_id || undefined,
    source_id: f.source_id || undefined,
  });
  const items = flatten(query.data?.pages);

  return (
    <>
      <PageHeader
        title="Находки"
        description="Все места, где обнаружены зарегистрированные секреты. Содержимое файлов не хранится — только путь, строка и коммит."
      />
      <div className="mb-4 flex flex-wrap gap-2">
        {PRESETS.map((p) => {
          const active = f.is_allowed === p.is_allowed && f.in_current_state === p.in_current_state;
          return (
            <button
              key={p.label}
              type="button"
              onClick={() => setMany({ is_allowed: p.is_allowed, in_current_state: p.in_current_state })}
              className={cx(
                "rounded-full border px-3 py-1.5 text-xs font-medium transition-colors",
                active
                  ? "border-slate-900 bg-slate-900 text-white dark:border-white dark:bg-white dark:text-slate-900"
                  : "border-slate-300 bg-white text-slate-600 hover:border-slate-400 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300",
              )}
              aria-pressed={active}
            >
              {p.label}
            </button>
          );
        })}
      </div>
      <div className="mb-4 flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <IconSearch className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Путь, репозиторий или имя секрета"
            className="pl-9"
            aria-label="Поиск"
            maxLength={200}
          />
        </div>
        <Input value={env} onChange={(e) => setEnv(e.target.value)} placeholder="Окружение" aria-label="Окружение" className="sm:w-40" maxLength={64} />
        <Select
          value={f.in_current_state}
          onChange={(e) => set("in_current_state", e.target.value)}
          aria-label="Состояние"
          className="sm:w-48"
        >
          <option value="">Код и история</option>
          <option value="true">Только в текущем коде</option>
          <option value="false">Только в истории</option>
        </Select>
      </div>
      {(f.secret_id || f.source_id) && (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-sm">
          <span className="text-slate-500">Фильтр:</span>
          {f.secret_id && <Badge tone="blue">секрет {f.secret_id.slice(0, 8)}</Badge>}
          {f.source_id && <Badge tone="blue">источник {f.source_id.slice(0, 8)}</Badge>}
          <button
            type="button"
            className="link text-xs"
            onClick={() => setMany({ secret_id: "", source_id: "" })}
          >
            сбросить
          </button>
        </div>
      )}
      <DataTable
        loading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
        empty={items.length === 0}
        emptyIcon={<IconAlert />}
        emptyTitle="Находок нет"
        emptyText="По этим условиям ничего не найдено."
        head={
          <tr>
            <th>Секрет</th>
            <th>Где</th>
            <th>Статус</th>
            <th>Окружение</th>
            <th>Впервые / последний раз</th>
          </tr>
        }
        footer={<LoadMore count={items.length} hasNext={!!query.hasNextPage} loading={query.isFetchingNextPage} onLoad={() => void query.fetchNextPage()} />}
      >
        {items.map((x) => (
          <tr key={x.id}>
            <td className="min-w-[12rem]">
              <Link to={`/secrets/${x.secret.id}`} className="link">
                {x.secret.name}
              </Link>
              <p className="mt-0.5 text-xs text-slate-500">
                {SECRET_TYPE_LABELS[x.secret.type]} · <Mono>{x.secret.masked}</Mono>
              </p>
            </td>
            <td>
              <FindingWhere uri={x.uri} locator={x.locator} sourceId={x.source_id} sourceName={x.source_name} sourceType={x.source_type} />
            </td>
            <td>
              <FindingBadges allowed={x.is_allowed} current={x.in_current_state} />
            </td>
            <td>{x.environment ? <Badge>{x.environment}</Badge> : <span className="text-slate-400">—</span>}</td>
            <td>
              <Time iso={x.first_seen} />
              <p className="mt-0.5 text-xs text-slate-500">
                <Time iso={x.last_seen} />
              </p>
            </td>
          </tr>
        ))}
      </DataTable>
    </>
  );
}

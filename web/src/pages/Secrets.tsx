import { Link, useNavigate } from "react-router-dom";

import { flatten, useSecrets } from "../api/hooks";
import type { SecretStatus, SecretType } from "../api/types";
import { Can } from "../auth/guards";
import { SecretStatusBadge } from "../components/badges";
import { IconKey, IconPlus, IconSearch } from "../components/icons";
import { DataTable, LoadMore } from "../components/Table";
import { Badge, Input, Mono, PageHeader, Select } from "../components/ui";
import { SECRET_TYPES } from "../crypto/secretTypes";
import { formatDate } from "../lib/format";
import { useSyncedSearch, useUrlFilters } from "../lib/hooks";
import { SECRET_STATUS_LABELS, SECRET_TYPE_LABELS } from "../lib/labels";

const KEYS = ["q", "status", "type"] as const;

export function SecretsPage() {
  const navigate = useNavigate();
  const [f, set] = useUrlFilters(KEYS);
  const [q, setQ] = useSyncedSearch(f.q, (v) => set("q", v));

  const query = useSecrets({
    q: f.q || undefined,
    status: (f.status || undefined) as SecretStatus | undefined,
    type: (f.type || undefined) as SecretType | undefined,
  });
  const items = flatten(query.data?.pages);
  const filtered = !!(f.q || f.status || f.type);

  return (
    <>
      <PageHeader
        title="Реестр секретов"
        description="Секреты, которые ищет SecretTrace. Значения не хранятся: только HMAC-отпечатки и безопасные подсказки (публичный префикс)."
        actions={
          <Can role="operator">
            <Link to="/secrets/new" className="btn btn-primary">
              <IconPlus size={16} /> Зарегистрировать
            </Link>
          </Can>
        }
      />
      <div className="mb-4 flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <IconSearch className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Поиск по имени, владельцу, назначению"
            className="pl-9"
            aria-label="Поиск"
            maxLength={200}
          />
        </div>
        <Select value={f.status} onChange={(e) => set("status", e.target.value)} aria-label="Статус" className="sm:w-44">
          <option value="">Все статусы</option>
          {Object.entries(SECRET_STATUS_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </Select>
        <Select value={f.type} onChange={(e) => set("type", e.target.value)} aria-label="Тип" className="sm:w-56">
          <option value="">Все типы</option>
          {SECRET_TYPES.map((t) => (
            <option key={t} value={t}>
              {SECRET_TYPE_LABELS[t]}
            </option>
          ))}
        </Select>
      </div>
      <DataTable
        loading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
        empty={items.length === 0}
        emptyIcon={<IconKey />}
        emptyTitle={filtered ? "Ничего не найдено" : "Реестр пуст"}
        emptyText={filtered ? "Измените фильтры." : "Зарегистрируйте первый секрет, чтобы начать поиск утечек."}
        head={
          <tr>
            <th>Секрет</th>
            <th>Тип</th>
            <th>Маска</th>
            <th>Статус</th>
            <th className="text-right">Нарушения</th>
            <th className="text-right">Мест</th>
            <th>Истекает</th>
          </tr>
        }
        footer={
          <LoadMore
            count={items.length}
            hasNext={!!query.hasNextPage}
            loading={query.isFetchingNextPage}
            onLoad={() => void query.fetchNextPage()}
          />
        }
      >
        {items.map((s) => (
          <tr
            key={s.id}
            className="clickable"
            onClick={() => navigate(`/secrets/${s.id}`)}
            onKeyDown={(e) => e.key === "Enter" && navigate(`/secrets/${s.id}`)}
            tabIndex={0}
          >
            <td>
              <p className="font-medium text-slate-900 dark:text-white">{s.name}</p>
              <p className="text-xs text-slate-500">{s.owner}</p>
            </td>
            <td className="whitespace-nowrap">{SECRET_TYPE_LABELS[s.type]}</td>
            <td>
              <Mono>{s.masked}</Mono>
            </td>
            <td>
              <SecretStatusBadge status={s.status} expired={s.is_expired} />
            </td>
            <td className="text-right">
              {s.violation_count > 0 ? <Badge tone="red">{s.violation_count}</Badge> : <span className="text-slate-400">0</span>}
            </td>
            <td className="text-right tabular-nums">{s.location_count}</td>
            <td className="whitespace-nowrap">{formatDate(s.expires_at)}</td>
          </tr>
        ))}
      </DataTable>
    </>
  );
}

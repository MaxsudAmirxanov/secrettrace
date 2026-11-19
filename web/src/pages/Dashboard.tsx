import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { useOverview } from "../api/hooks";
import type { Overview } from "../api/types";
import { Can } from "../auth/guards";
import { BarChart } from "../components/BarChart";
import { JobStatusBadge } from "../components/badges";
import { IconAlert, IconClock, IconKey, IconPlus, IconRepo, IconScan } from "../components/icons";
import { Time } from "../components/Time";
import { Badge, Card, EmptyState, ErrorBanner, Mono, PageHeader, PageLoader, cx } from "../components/ui";
import { daysUntil, formatNumber } from "../lib/format";
import { SECRET_TYPE_LABELS, TRIGGER_LABELS } from "../lib/labels";
import { locatorPath } from "../lib/locator";

function Kpi({
  label,
  value,
  sub,
  tone = "default",
  icon,
  to,
}: {
  label: string;
  value: number;
  sub?: ReactNode;
  tone?: "default" | "danger" | "warn" | "ok";
  icon: ReactNode;
  to?: string;
}) {
  const color = {
    default: "text-slate-900 dark:text-white",
    danger: value > 0 ? "text-rose-600 dark:text-rose-400" : "text-slate-900 dark:text-white",
    warn: value > 0 ? "text-amber-600 dark:text-amber-400" : "text-slate-900 dark:text-white",
    ok: "text-emerald-600 dark:text-emerald-400",
  }[tone];
  const iconBg = {
    default: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
    danger: "bg-rose-50 text-rose-500 dark:bg-rose-500/10",
    warn: "bg-amber-50 text-amber-500 dark:bg-amber-500/10",
    ok: "bg-emerald-50 text-emerald-500 dark:bg-emerald-500/10",
  }[tone];
  const body = (
    <div className="card flex h-full items-start gap-4 p-5 transition-shadow hover:shadow-md">
      <span className={cx("rounded-lg p-2.5", iconBg)}>{icon}</span>
      <div className="min-w-0">
        <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
        <p className={cx("mt-1 text-2xl font-semibold tabular-nums", color)}>{formatNumber(value)}</p>
        {sub && <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{sub}</p>}
      </div>
    </div>
  );
  return to ? (
    <Link to={to} className="block rounded-xl">
      {body}
    </Link>
  ) : (
    body
  );
}

function Onboarding() {
  return (
    <Card>
      <EmptyState icon={<IconKey />} title="Реестр пока пуст">
        <p>
          SecretTrace ищет в репозиториях только те секреты, которые зарегистрированы в реестре. Значение секрета не
          покидает браузер: на сервер уходит только его отпечаток.
        </p>
        <Can role="operator">
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <Link to="/secrets/new" className="btn btn-primary">
              <IconPlus size={16} /> Зарегистрировать секрет
            </Link>
            <Link to="/sources/new" className="btn btn-secondary">
              <IconRepo size={16} /> Добавить источник
            </Link>
          </div>
        </Can>
      </EmptyState>
    </Card>
  );
}

function Lists({ o }: { o: Overview }) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Больше всего нарушений" bodyClassName="p-0">
        {o.top_exposed.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-slate-500">Нарушений нет</p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {o.top_exposed.map(({ secret, violations }) => (
              <li key={secret.id}>
                <Link to={`/secrets/${secret.id}`} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium text-slate-900 dark:text-white">{secret.name}</p>
                    <p className="text-xs text-slate-500">
                      {SECRET_TYPE_LABELS[secret.type]} · <Mono>{secret.masked}</Mono>
                    </p>
                  </div>
                  <Badge tone="red">{violations}</Badge>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Истекают в ближайшие 30 дней" bodyClassName="p-0">
        {o.expiring.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-slate-500">Ничего не истекает</p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {o.expiring.map(({ secret, expires_at }) => {
              const d = daysUntil(expires_at);
              return (
                <li key={secret.id}>
                  <Link to={`/secrets/${secret.id}`} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-medium text-slate-900 dark:text-white">{secret.name}</p>
                      <p className="text-xs text-slate-500">{SECRET_TYPE_LABELS[secret.type]}</p>
                    </div>
                    <Badge tone={d <= 7 ? "red" : "amber"}>{d <= 0 ? "сегодня" : `через ${d} дн.`}</Badge>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}

export function DashboardPage() {
  const { data: o, error, isLoading, refetch } = useOverview();
  if (isLoading) return <PageLoader />;
  if (error || !o) return <ErrorBanner error={error} onRetry={() => void refetch()} />;

  const failed = o.scans_24h.failed;
  return (
    <>
      <PageHeader
        title="Обзор"
        description="Где обнаружены зарегистрированные секреты и в каком состоянии реестр. Данные обновляются каждые 30 секунд."
      />
      {o.secrets.total === 0 ? (
        <Onboarding />
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Kpi
              label="Открытые нарушения"
              value={o.locations.open_violations}
              sub="в текущем состоянии источников"
              tone="danger"
              icon={<IconAlert />}
              to="/findings?is_allowed=false&in_current_state=true"
            />
            <Kpi
              label="Только в истории"
              value={o.locations.historical_violations}
              sub="удалены из кода, но остались в git"
              tone="warn"
              icon={<IconClock />}
              to="/findings?is_allowed=false&in_current_state=false"
            />
            <Kpi
              label="Скомпрометированные секреты"
              value={o.locations.exposed_secrets}
              sub={`из ${formatNumber(o.secrets.total)} в реестре`}
              tone="danger"
              icon={<IconKey />}
              to="/secrets"
            />
            <Kpi
              label="Сканы за 24 часа"
              value={o.scans_24h.succeeded + o.scans_24h.failed + o.scans_24h.cancelled + o.scans_24h.running + o.scans_24h.queued}
              sub={
                failed > 0 ? (
                  <span className="text-rose-600 dark:text-rose-400">с ошибкой: {failed}</span>
                ) : (
                  `успешно: ${o.scans_24h.succeeded}`
                )
              }
              icon={<IconScan />}
              to="/scans"
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Card title="Новые нарушения за 30 дней" className="lg:col-span-2">
              <BarChart data={o.violations_by_day} label="Новые нарушения по дням за последние 30 дней" />
            </Card>
            <Card title="Реестр">
              <dl className="space-y-3 text-sm">
                {(
                  [
                    ["Активные", o.secrets.active, "text-emerald-600 dark:text-emerald-400"],
                    ["Истекают ≤ 30 дней", o.secrets.expiring_soon, "text-amber-600 dark:text-amber-400"],
                    ["Истёкшие", o.secrets.expired, ""],
                    ["Отозванные", o.secrets.revoked, ""],
                    ["Заменённые", o.secrets.rotated, ""],
                  ] as const
                ).map(([k, v, c]) => (
                  <div key={k} className="flex items-center justify-between">
                    <dt className="text-slate-500 dark:text-slate-400">{k}</dt>
                    <dd className={cx("font-semibold tabular-nums", c)}>{formatNumber(v)}</dd>
                  </div>
                ))}
                <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-800">
                  <dt className="text-slate-500 dark:text-slate-400">Источники (вкл. / всего)</dt>
                  <dd className="font-semibold tabular-nums">
                    {o.sources.enabled} / {o.sources.total}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-500 dark:text-slate-400">По расписанию</dt>
                  <dd className="font-semibold tabular-nums">{o.sources.scheduled}</dd>
                </div>
              </dl>
            </Card>
          </div>

          <Lists o={o} />

          <div className="grid gap-6 xl:grid-cols-2">
            <Card
              title="Последние нарушения"
              actions={
                <Link to="/findings?is_allowed=false" className="link text-xs">
                  Все находки
                </Link>
              }
              bodyClassName="p-0"
            >
              {o.recent_violations.length === 0 ? (
                <p className="px-5 py-8 text-center text-sm text-slate-500">Нарушений не найдено</p>
              ) : (
                <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                  {o.recent_violations.map((f) => (
                    <li key={f.id} className="px-5 py-3">
                      <div className="flex items-center justify-between gap-3">
                        <Link to={`/secrets/${f.secret.id}`} className="link truncate">
                          {f.secret.name}
                        </Link>
                        <span className="shrink-0 text-xs text-slate-500">
                          <Time iso={f.first_seen} />
                        </span>
                      </div>
                      <p className="mt-0.5 truncate text-xs text-slate-500" title={`${f.uri} ${locatorPath(f.locator)}`}>
                        {f.source_name ?? f.uri} · <span className="font-mono">{locatorPath(f.locator)}</span>
                        {!f.in_current_state && " · только в истории"}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card
              title="Последние сканы"
              actions={
                <Link to="/scans" className="link text-xs">
                  Все сканы
                </Link>
              }
              bodyClassName="p-0"
            >
              {o.recent_scans.length === 0 ? (
                <p className="px-5 py-8 text-center text-sm text-slate-500">Сканов ещё не было</p>
              ) : (
                <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                  {o.recent_scans.map((s) => (
                    <li key={s.id}>
                      <Link to={`/scans/${s.id}`} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-medium text-slate-900 dark:text-white">{s.source_name ?? "Удалённый источник"}</p>
                          <p className="text-xs text-slate-500">
                            {TRIGGER_LABELS[s.trigger]} · <Time iso={s.created_at} />
                          </p>
                        </div>
                        <JobStatusBadge status={s.status} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </div>
      )}
    </>
  );
}

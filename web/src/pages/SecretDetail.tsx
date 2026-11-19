import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { flatten, useSecret, useSecretLocations, useUpdateSecret } from "../api/hooks";
import type { AllowRule, Secret, SecretStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { AllowRulesEditor, cleanRules, rulesError } from "../components/AllowRulesEditor";
import { FindingBadges, SecretStatusBadge } from "../components/badges";
import { FindingWhere } from "../components/FindingRow";
import { IconEdit } from "../components/icons";
import { ConfirmDialog, Modal } from "../components/Modal";
import { DataTable, LoadMore } from "../components/Table";
import { Time } from "../components/Time";
import { useToast } from "../components/Toast";
import {
  Badge,
  Button,
  Card,
  DescriptionList,
  ErrorBanner,
  Field,
  Input,
  Mono,
  PageHeader,
  PageLoader,
  Textarea,
  cx,
} from "../components/ui";
import { formatDate, formatDateTime } from "../lib/format";
import { SECRET_TYPE_LABELS, SOURCE_TYPE_LABELS } from "../lib/labels";
import { expiryToIso } from "./SecretNew";

function EditModal({ secret, open, onClose }: { secret: Secret; open: boolean; onClose: () => void }) {
  const update = useUpdateSecret(secret.id);
  const toast = useToast();
  const [owner, setOwner] = useState(secret.owner);
  const [purpose, setPurpose] = useState(secret.purpose ?? "");
  const [expires, setExpires] = useState(secret.expires_at?.slice(0, 10) ?? "");
  const [error, setError] = useState<unknown>(null);

  const save = async () => {
    setError(null);
    try {
      await update.mutateAsync({
        owner: owner.trim(),
        purpose: purpose.trim() || null,
        expires_at: expires ? (expiryToIso(expires) ?? null) : null,
      });
      toast.success("Изменения сохранены");
      onClose();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Изменить секрет"
      footer={
        <>
          <Button onClick={onClose}>Отмена</Button>
          <Button variant="primary" loading={update.isPending} onClick={() => void save()} disabled={!owner.trim()}>
            Сохранить
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Владелец" required>
          {(id) => <Input id={id} value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={200} />}
        </Field>
        <Field label="Назначение">
          {(id) => <Textarea id={id} rows={3} value={purpose} onChange={(e) => setPurpose(e.target.value)} maxLength={2000} />}
        </Field>
        <Field label="Действует до" hint="Пусто — бессрочно">
          {(id, d) => <Input id={id} aria-describedby={d} type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />}
        </Field>
        {error !== null && <ErrorBanner error={error} />}
      </div>
    </Modal>
  );
}

function RulesModal({ secret, open, onClose }: { secret: Secret; open: boolean; onClose: () => void }) {
  const update = useUpdateSecret(secret.id);
  const toast = useToast();
  const [rules, setRules] = useState<AllowRule[]>(secret.allow_rules.map((r) => ({ ...r })));
  const [error, setError] = useState<unknown>(null);

  const save = async () => {
    const re = rulesError(rules);
    if (re) {
      setError(new Error(re));
      return;
    }
    setError(null);
    try {
      await update.mutateAsync({ allow_rules: cleanRules(rules) });
      toast.success("Правила обновлены, статус находок пересчитан");
      onClose();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title="Разрешённые места"
      footer={
        <>
          <Button onClick={onClose}>Отмена</Button>
          <Button variant="primary" loading={update.isPending} onClick={() => void save()}>
            Сохранить
          </Button>
        </>
      }
    >
      <AllowRulesEditor rules={rules} onChange={setRules} />
      {error !== null && (
        <div className="mt-4">
          <ErrorBanner error={error} />
        </div>
      )}
    </Modal>
  );
}

const TRANSITIONS: { to: SecretStatus; label: string; text: string }[] = [
  {
    to: "revoked",
    label: "Отозвать",
    text: "Секрет будет помечен отозванным. Вернуть его в активные нельзя: отозванному значению больше нельзя доверять.",
  },
  {
    to: "rotated",
    label: "Отметить заменённым",
    text: "Значение заменено новым. Поиск старого значения продолжится, но вернуть статус «активен» нельзя. Зарегистрируйте новое значение отдельно.",
  },
];

const LOC_TABS = [
  { id: "", label: "Все" },
  { id: "false", label: "Нарушения" },
  { id: "true", label: "Разрешённые" },
] as const;

export function SecretDetailPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const toast = useToast();
  const { data: s, error, isLoading, refetch } = useSecret(id);
  const [tab, setTab] = useState<"" | "true" | "false">("");
  const locs = useSecretLocations(id, { is_allowed: tab === "" ? undefined : tab === "true" });
  const update = useUpdateSecret(id);
  const [editing, setEditing] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [transition, setTransition] = useState<(typeof TRANSITIONS)[number] | null>(null);

  if (isLoading) return <PageLoader />;
  if (error || !s) return <ErrorBanner error={error} onRetry={() => void refetch()} />;

  const terminal = s.status === "revoked" || s.status === "rotated";
  const items = flatten(locs.data?.pages);
  const operator = can("operator");

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/secrets" className="link">
            ← Реестр секретов
          </Link>
        }
        title={s.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <SecretStatusBadge status={s.status} expired={s.is_expired} />
            <span>{SECRET_TYPE_LABELS[s.type]}</span>
            <Mono>{s.masked}</Mono>
          </span>
        }
        actions={
          operator && (
            <>
              <Button icon={<IconEdit size={16} />} onClick={() => setEditing(true)}>
                Изменить
              </Button>
              {!terminal &&
                TRANSITIONS.map((t) => (
                  <Button key={t.to} variant={t.to === "revoked" ? "danger" : "secondary"} onClick={() => setTransition(t)}>
                    {t.label}
                  </Button>
                ))}
            </>
          )
        }
      />

      {s.violation_count > 0 && !terminal && (
        <div className="mb-6 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200">
          <p className="font-semibold">Секрет найден в {s.violation_count} неразрешённых местах</p>
          <p className="mt-0.5">
            Удаление из кода не отменяет утечку: значение остаётся в истории git и у всех, кто её склонировал. Замените секрет
            у поставщика, затем отметьте его заменённым.
          </p>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Сведения" className="lg:col-span-2">
          <DescriptionList
            items={[
              ["Владелец", s.owner],
              ["Назначение", s.purpose || <span className="text-slate-400">—</span>],
              ["Действует до", s.expires_at ? <span className={cx(s.is_expired && "text-amber-600")}>{formatDate(s.expires_at)}</span> : "Бессрочно"],
              ["Мест / нарушений", <span key="c">{s.location_count} / <span className={cx(s.violation_count > 0 && "font-semibold text-rose-600")}>{s.violation_count}</span></span>],
              ["Зарегистрирован", formatDateTime(s.created_at)],
              ["Изменён", formatDateTime(s.updated_at)],
            ]}
          />
        </Card>
        <Card
          title="Разрешённые места"
          actions={
            operator && (
              <Button size="sm" variant="ghost" icon={<IconEdit size={14} />} onClick={() => setRulesOpen(true)}>
                Изменить
              </Button>
            )
          }
        >
          {s.allow_rules.length === 0 ? (
            <p className="text-sm text-slate-500">Нет правил — любая находка считается нарушением.</p>
          ) : (
            <ul className="space-y-3">
              {s.allow_rules.map((r) => (
                <li key={r.id ?? r.uri_pattern} className="text-sm">
                  <p className="break-all font-mono text-[13px]">{r.uri_pattern}</p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {[
                      r.path_pattern && `путь: ${r.path_pattern}`,
                      r.source_type && SOURCE_TYPE_LABELS[r.source_type],
                      r.environment && `окружение: ${r.environment}`,
                    ]
                      .filter(Boolean)
                      .join(" · ") || "любой путь и окружение"}
                  </p>
                  {r.comment && <p className="mt-0.5 text-xs italic text-slate-500">{r.comment}</p>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="mb-3 mt-8 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-slate-900 dark:text-white">Где найден</h2>
        <div className="inline-flex rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-900" role="tablist">
          {LOC_TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={cx(
                "rounded-md px-3 py-1.5 text-xs font-medium",
                tab === t.id ? "bg-slate-900 text-white dark:bg-white dark:text-slate-900" : "text-slate-600 hover:text-slate-900 dark:text-slate-300",
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>
      <DataTable
        loading={locs.isLoading}
        error={locs.error}
        onRetry={() => void locs.refetch()}
        empty={items.length === 0}
        emptyTitle="Нигде не найден"
        emptyText="Секрет пока не обнаружен ни в одном источнике."
        head={
          <tr>
            <th>Место</th>
            <th>Статус</th>
            <th>Окружение</th>
            <th>Впервые</th>
            <th>Последний раз</th>
          </tr>
        }
        footer={<LoadMore count={items.length} hasNext={!!locs.hasNextPage} loading={locs.isFetchingNextPage} onLoad={() => void locs.fetchNextPage()} />}
      >
        {items.map((l) => (
          <tr key={l.id}>
            <td>
              <FindingWhere uri={l.uri} locator={l.locator} sourceId={l.source_id} sourceType={l.source_type} />
            </td>
            <td>
              <FindingBadges allowed={l.is_allowed} current={l.in_current_state} />
            </td>
            <td>{l.environment ? <Badge>{l.environment}</Badge> : <span className="text-slate-400">—</span>}</td>
            <td>
              <Time iso={l.first_seen} />
            </td>
            <td>
              <Time iso={l.last_seen} />
            </td>
          </tr>
        ))}
      </DataTable>

      {editing && <EditModal secret={s} open onClose={() => setEditing(false)} />}
      {rulesOpen && <RulesModal secret={s} open onClose={() => setRulesOpen(false)} />}
      <ConfirmDialog
        open={transition !== null}
        title={transition?.label ?? ""}
        danger={transition?.to === "revoked"}
        confirmLabel={transition?.label}
        loading={update.isPending}
        onClose={() => setTransition(null)}
        onConfirm={() => {
          if (!transition) return;
          update.mutate(
            { status: transition.to },
            {
              onSuccess: () => {
                toast.success("Статус изменён");
                setTransition(null);
              },
              onError: (e) => toast.error(e),
            },
          );
        }}
      >
        {transition?.text}
      </ConfirmDialog>
    </>
  );
}

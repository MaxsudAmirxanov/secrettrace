import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { useCanary, useUpdateCanary } from "../api/hooks";
import type { CanaryDetail } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { IconAlert, IconEdit } from "../components/icons";
import { Modal } from "../components/Modal";
import { DataTable } from "../components/Table";
import { Time } from "../components/Time";
import { useToast } from "../components/Toast";
import { Badge, Button, Card, DescriptionList, ErrorBanner, Field, Input, Mono, PageHeader, PageLoader, Textarea } from "../components/ui";
import { canaryState } from "../lib/canary";
import { formatDateTime, formatNumber } from "../lib/format";
import { CANARY_KIND_LABELS, CANARY_VIA_LABELS } from "../lib/labels";

function EditModal({ canary, onClose }: { canary: CanaryDetail; onClose: () => void }) {
  const update = useUpdateCanary(canary.id);
  const toast = useToast();
  const [plantedAt, setPlantedAt] = useState(canary.planted_at ?? "");
  const [memo, setMemo] = useState(canary.memo ?? "");
  const save = () =>
    update.mutate(
      { planted_at: plantedAt.trim() || null, memo: memo.trim() || null },
      {
        onSuccess: () => {
          toast.success("Сохранено");
          onClose();
        },
      },
    );
  return (
    <Modal
      open
      onClose={onClose}
      title="Изменить ловушку"
      footer={
        <>
          <Button onClick={onClose}>Отмена</Button>
          <Button variant="primary" loading={update.isPending} onClick={save}>
            Сохранить
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Где лежит">
          {(id) => <Input id={id} value={plantedAt} onChange={(e) => setPlantedAt(e.target.value)} maxLength={500} />}
        </Field>
        <Field label="Заметка">
          {(id) => <Textarea id={id} rows={3} value={memo} onChange={(e) => setMemo(e.target.value)} maxLength={2000} />}
        </Field>
        {update.error && <ErrorBanner error={update.error} />}
      </div>
    </Modal>
  );
}

export function CanaryDetailPage() {
  const { id = "" } = useParams();
  const toast = useToast();
  const { can } = useAuth();
  const { data: c, error, isLoading, refetch } = useCanary(id);
  const update = useUpdateCanary(id);
  const [editing, setEditing] = useState(false);

  if (isLoading) return <PageLoader />;
  if (error || !c) return <ErrorBanner error={error} onRetry={() => void refetch()} />;

  const st = canaryState(c);
  const toggle = () =>
    update.mutate(
      { enabled: !c.enabled },
      {
        onSuccess: () => toast.success(c.enabled ? "Ловушка выключена" : "Ловушка включена"),
        onError: (e) => toast.error(e),
      },
    );

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/canaries" className="link">
            ← Ловушки
          </Link>
        }
        title={c.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone={st.tone} dot>
              {st.label}
            </Badge>
            <span>{CANARY_KIND_LABELS[c.kind]}</span>
          </span>
        }
        actions={
          can("operator") && (
            <>
              <Button loading={update.isPending} onClick={toggle}>
                {c.enabled ? "Выключить" : "Включить"}
              </Button>
              <Button icon={<IconEdit size={14} />} onClick={() => setEditing(true)}>
                Изменить
              </Button>
            </>
          )
        }
      />
      {c.hit_count > 0 && (
        <div
          role="alert"
          className="mb-6 flex items-start gap-3 rounded-lg border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-900 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-200"
        >
          <IconAlert className="mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold">
              Ловушка сработала {formatNumber(c.hit_count)} раз, последний раз {formatDateTime(c.last_hit_at)}.
            </p>
            <p className="mt-0.5">
              Значит, её кто-то нашёл и попробовал. Выясните, откуда она могла утечь ({c.planted_at ?? "место не указано"}), и проверьте
              настоящие секреты, лежавшие рядом: их стоит считать скомпрометированными.
            </p>
          </div>
        </div>
      )}
      {!c.enabled && (
        <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300">
          Ловушка выключена: обращения к ней не записываются и не создают алертов.
        </div>
      )}
      <Card title="Сведения">
        <DescriptionList
          items={[
            ["Где лежит", c.planted_at ?? "—"],
            ["Заметка", c.memo ? <span className="whitespace-pre-wrap">{c.memo}</span> : "—"],
            ["Срабатываний", formatNumber(c.hit_count)],
            ["Последнее", formatDateTime(c.last_hit_at)],
            [
              "Секрет в реестре",
              c.secret_id ? (
                <Link to={`/secrets/${c.secret_id}`} className="link">
                  открыть: найденные места — это утечки
                </Link>
              ) : (
                "нет (ссылка)"
              ),
            ],
            ["Создана", formatDateTime(c.created_at)],
          ]}
        />
      </Card>
      <h2 className="mb-3 mt-8 text-base font-semibold text-slate-900 dark:text-white">Срабатывания</h2>
      <DataTable
        empty={c.hits.length === 0}
        emptyIcon={<IconAlert />}
        emptyTitle="Срабатываний не было"
        emptyText="Сохраняются последние 100 обращений; при потоке запросов — не больше 10 в минуту, счётчик учитывает все."
        head={
          <tr>
            <th>Время</th>
            <th>IP</th>
            <th>Запрос</th>
            <th>Хост</th>
            <th>User-Agent</th>
            <th>Токен в</th>
          </tr>
        }
      >
        {c.hits.map((h) => (
          <tr key={h.id}>
            <td>
              <Time iso={h.at} />
            </td>
            <td>{h.ip ? <Mono>{h.ip}</Mono> : "—"}</td>
            <td className="max-w-sm">
              <span className="break-all font-mono text-xs">
                <span className="font-semibold">{h.method}</span> {h.path}
              </span>
            </td>
            <td className="text-sm">{h.host ?? "—"}</td>
            <td className="max-w-xs truncate text-xs text-slate-500" title={h.user_agent ?? undefined}>
              {h.user_agent ?? "—"}
            </td>
            <td>
              <Badge>{CANARY_VIA_LABELS[h.via]}</Badge>
            </td>
          </tr>
        ))}
      </DataTable>
      {editing && <EditModal canary={c} onClose={() => setEditing(false)} />}
    </>
  );
}

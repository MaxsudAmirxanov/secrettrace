import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { useCanaries, useCreateCanary } from "../api/hooks";
import type { CanaryKind, CreatedCanary } from "../api/types";
import { Can } from "../auth/guards";
import { IconBell, IconPlus } from "../components/icons";
import { Modal } from "../components/Modal";
import { DataTable } from "../components/Table";
import { Time } from "../components/Time";
import { Badge, Button, CopyButton, ErrorBanner, Field, Input, Notice, PageHeader, Select, Textarea } from "../components/ui";
import { canaryBody, canaryError, canaryState } from "../lib/canary";
import { formatNumber } from "../lib/format";
import { CANARY_KIND_HINTS, CANARY_KIND_LABELS } from "../lib/labels";

function CreateModal({ onClose, onCreated }: { onClose: () => void; onCreated: (c: CreatedCanary) => void }) {
  const create = useCreateCanary();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<CanaryKind>("api_key");
  const [plantedAt, setPlantedAt] = useState("");
  const [memo, setMemo] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const submit = () => {
    const e = canaryError({ name, plantedAt, memo });
    setErr(e);
    if (e) return;
    create.mutate(canaryBody({ name, kind, plantedAt, memo }), { onSuccess: (c) => onCreated(c) });
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Новая ловушка"
      footer={
        <>
          <Button onClick={onClose}>Отмена</Button>
          <Button variant="primary" loading={create.isPending} onClick={submit}>
            Создать
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Имя" required error={err}>
          {(id, d) => <Input id={id} aria-describedby={d} value={name} onChange={(e) => setName(e.target.value)} maxLength={190} placeholder="laptop-alice-env" />}
        </Field>
        <Field label="Тип" hint={CANARY_KIND_HINTS[kind]}>
          {(id, d) => (
            <Select id={id} aria-describedby={d} value={kind} onChange={(e) => setKind(e.target.value as CanaryKind)}>
              {Object.entries(CANARY_KIND_LABELS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Где лежит" hint="Куда вы её положите: это увидит тот, кто будет разбирать срабатывание.">
          {(id, d) => (
            <Input
              id={id}
              aria-describedby={d}
              value={plantedAt}
              onChange={(e) => setPlantedAt(e.target.value)}
              maxLength={500}
              placeholder="ноутбук Алисы, ~/.config/deploy/.env"
            />
          )}
        </Field>
        <Field label="Заметка">
          {(id) => <Textarea id={id} rows={2} value={memo} onChange={(e) => setMemo(e.target.value)} maxLength={2000} />}
        </Field>
        {create.error && <ErrorBanner error={create.error} />}
      </div>
    </Modal>
  );
}

function CreatedModal({ created, onClose }: { created: CreatedCanary; onClose: () => void }) {
  const isKey = created.canary.kind === "api_key";
  return (
    <Modal
      open
      dismissible={false}
      onClose={onClose}
      title="Ловушка создана"
      size="lg"
      footer={
        <Button variant="primary" onClick={onClose}>
          Я сохранил значение
        </Button>
      }
    >
      <div className="space-y-4">
        <Notice tone="amber" title="Скопируйте значение сейчас">
          Сервер хранит только HMAC токена, поэтому показать его ещё раз нельзя. Разместите {isKey ? "ключ" : "ссылку"} там, откуда
          может случиться утечка, и никогда не используйте сами: любое обращение — сигнал тревоги.
        </Notice>
        {isKey ? (
          <>
            <div>
              <p className="label">Адрес сервиса</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs dark:bg-slate-800">{created.endpoint}</code>
                {created.endpoint && <CopyButton value={created.endpoint} />}
              </div>
            </div>
            <div>
              <p className="label">Ключ</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs dark:bg-slate-800">{created.value}</code>
                <CopyButton value={created.value} />
              </div>
            </div>
            <div>
              <p className="label">Для .env</p>
              <div className="flex items-start gap-2">
                <pre className="flex-1 overflow-x-auto rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs dark:bg-slate-800">{created.snippet}</pre>
                <CopyButton value={created.snippet} />
              </div>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Ключ также зарегистрирован как секрет
              {created.canary.secret_id && (
                <>
                  {" "}
                  (
                  <Link to={`/secrets/${created.canary.secret_id}`} className="link">
                    карточка в реестре
                  </Link>
                  )
                </>
              )}
              : если скан найдёт его в репозитории, на диске или в логах CI, это будет нарушение.
            </p>
          </>
        ) : (
          <div>
            <p className="label">Ссылка</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs dark:bg-slate-800">{created.value}</code>
              <CopyButton value={created.value} />
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

export function CanariesPage() {
  const navigate = useNavigate();
  const { data, error, isLoading, refetch } = useCanaries();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedCanary | null>(null);
  const items = data ?? [];

  return (
    <>
      <PageHeader
        title="Ловушки"
        description="Canary-токены: фальшивые ключи и ссылки, которыми никто не пользуется законно. Обращение к ловушке или её появление в найденных местах означает утечку, по какому бы каналу она ни случилась."
        actions={
          <Can role="operator">
            <Button variant="primary" icon={<IconPlus size={16} />} onClick={() => setCreating(true)}>
              Создать ловушку
            </Button>
          </Can>
        }
      />
      <DataTable
        loading={isLoading}
        error={error}
        onRetry={() => void refetch()}
        empty={items.length === 0}
        emptyIcon={<IconBell />}
        emptyTitle="Ловушек нет"
        emptyText="Создайте фальшивый API-ключ для .env или ссылку и положите туда, откуда может утечь настоящее: ноутбуки, вики, бэкапы конфигов."
        head={
          <tr>
            <th>Ловушка</th>
            <th>Где лежит</th>
            <th>Срабатывания</th>
            <th>Последнее</th>
            <th>Состояние</th>
          </tr>
        }
      >
        {items.map((c) => {
          const st = canaryState(c);
          return (
            <tr
              key={c.id}
              className="clickable"
              tabIndex={0}
              onClick={() => navigate(`/canaries/${c.id}`)}
              onKeyDown={(e) => e.key === "Enter" && navigate(`/canaries/${c.id}`)}
            >
              <td>
                <p className="font-medium text-slate-900 dark:text-white">{c.name}</p>
                <p className="text-xs text-slate-500">{CANARY_KIND_LABELS[c.kind]}</p>
              </td>
              <td className="max-w-xs truncate text-sm" title={c.planted_at ?? undefined}>
                {c.planted_at ?? <span className="text-slate-400">—</span>}
              </td>
              <td className={c.hit_count > 0 ? "font-semibold text-rose-600 dark:text-rose-400" : undefined}>{formatNumber(c.hit_count)}</td>
              <td>
                <Time iso={c.last_hit_at} fallback="не было" />
              </td>
              <td>
                <Badge tone={st.tone} dot>
                  {st.label}
                </Badge>
              </td>
            </tr>
          );
        })}
      </DataTable>

      {creating && (
        <CreateModal
          onClose={() => setCreating(false)}
          onCreated={(c) => {
            setCreating(false);
            setCreated(c);
          }}
        />
      )}
      {created && <CreatedModal created={created} onClose={() => setCreated(null)} />}
    </>
  );
}

import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { useCancelScan, useDeleteSource, useEnqueueScan, useSource, useUpdateSource } from "../api/hooks";
import type { SourceUpdate } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { JobStatusBadge } from "../components/badges";
import { IconEdit, IconPlay, IconRefresh, IconStop, IconTrash } from "../components/icons";
import { ConfirmDialog, Modal } from "../components/Modal";
import { ScansTable } from "../components/ScansTable";
import { SourceForm, sourceToValues, valuesToConfig } from "../components/SourceForm";
import { useToast } from "../components/Toast";
import { Badge, Button, Card, DescriptionList, ErrorBanner, Mono, PageHeader, PageLoader } from "../components/ui";
import { formatBytes, formatDateTime } from "../lib/format";
import { SOURCE_TYPE_LABELS } from "../lib/labels";
import { safeHttpUrl } from "../lib/locator";

export function SourceDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const { data: s, error, isLoading, refetch } = useSource(id);
  const update = useUpdateSource(id);
  const enqueue = useEnqueueScan();
  const cancel = useCancelScan();
  const remove = useDeleteSource();
  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmFull, setConfirmFull] = useState(false);

  if (isLoading) return <PageLoader />;
  if (error || !s) return <ErrorBanner error={error} onRetry={() => void refetch()} />;

  const operator = can("operator");
  const git = s.type === "git_repo";
  const link = safeHttpUrl(s.uri);
  const scan = (full: boolean) =>
    enqueue.mutate(
      { id: s.id, full },
      {
        onSuccess: () => {
          toast.success(full ? "Полный скан поставлен в очередь" : "Скан поставлен в очередь");
          setConfirmFull(false);
        },
        onError: (e) => toast.error(e),
      },
    );

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/sources" className="link">
            ← Источники
          </Link>
        }
        title={s.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            {s.enabled ? <Badge tone="green" dot>Включён</Badge> : <Badge dot>Выключен</Badge>}
            {s.active_scan && <JobStatusBadge status={s.active_scan.status} />}
            <span>{SOURCE_TYPE_LABELS[s.type]}</span>
          </span>
        }
        actions={
          operator && (
            <>
              {git && !s.active_scan && (
                <>
                  <Button variant="primary" icon={<IconPlay size={14} />} loading={enqueue.isPending} disabled={!s.enabled} onClick={() => scan(false)}>
                    Сканировать
                  </Button>
                  <Button icon={<IconRefresh size={14} />} disabled={!s.enabled} onClick={() => setConfirmFull(true)}>
                    Вся история
                  </Button>
                </>
              )}
              {s.active_scan && (
                <Button
                  variant="danger"
                  icon={<IconStop size={14} />}
                  loading={cancel.isPending}
                  onClick={() =>
                    s.active_scan &&
                    cancel.mutate(s.active_scan.id, { onSuccess: () => toast.success("Скан отменён"), onError: (e) => toast.error(e) })
                  }
                >
                  Отменить скан
                </Button>
              )}
              <Button icon={<IconEdit size={14} />} onClick={() => setEditing(true)}>
                Изменить
              </Button>
              <Button variant="ghost" icon={<IconTrash size={14} />} onClick={() => setConfirmDelete(true)} aria-label="Удалить источник" />
            </>
          )
        }
      />
      {!git && (
        <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300">
          Этот источник создан автоматически по данным от CI или агента. Сервер сам его не сканирует.
        </div>
      )}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Настройки" className="lg:col-span-2">
          <DescriptionList
            items={[
              [
                "Адрес",
                link ? (
                  <a href={link} target="_blank" rel="noopener noreferrer" className="link break-all font-mono text-[13px] font-normal">
                    {s.uri}
                  </a>
                ) : (
                  <span className="break-all font-mono text-[13px]">{s.uri}</span>
                ),
              ],
              ["Окружение", s.environment ?? "—"],
              ["Файл доступа", s.credential_ref ? <Mono>{s.credential_ref}</Mono> : "нет (публичный)"],
              ["Пользователь", s.config.username ?? (s.credential_ref ? "x-access-token (по умолчанию)" : "—")],
              ["Расписание (UTC)", s.schedule ? <Mono>{s.schedule}</Mono> : "только вручную"],
              ["Макс. размер файла", s.config.max_blob_bytes ? formatBytes(s.config.max_blob_bytes) : "по умолчанию (16 МиБ)"],
            ]}
          />
        </Card>
        <Card title="Сканирование">
          <DescriptionList
            items={[
              ["Последний скан", formatDateTime(s.last_scan_at)],
              ["Следующий по расписанию", formatDateTime(s.next_scan_at)],
              ["Создан", formatDateTime(s.created_at)],
            ]}
          />
          <p className="mt-4 text-sm">
            <Link to={`/findings?source_id=${s.id}`} className="link">
              Находки в этом источнике →
            </Link>
          </p>
        </Card>
      </div>
      <h2 className="mb-3 mt-8 text-base font-semibold text-slate-900 dark:text-white">История сканов</h2>
      <ScansTable sourceId={s.id} showSource={false} />

      <Modal open={editing} onClose={() => setEditing(false)} title="Изменить источник" size="lg">
        {editing && (
          <SourceForm
            initial={sourceToValues(s)}
            isNew={false}
            submitLabel="Сохранить"
            busy={update.isPending}
            error={update.error}
            onCancel={() => setEditing(false)}
            onSubmit={(v) => {
              const body: SourceUpdate = {
                name: v.name.trim(),
                environment: v.environment.trim() || null,
                credential_ref: v.credential_ref.trim() || null,
                schedule: v.schedule.trim() || null,
                enabled: v.enabled,
                config: valuesToConfig(v),
              };
              update.mutate(body, {
                onSuccess: () => {
                  toast.success("Источник обновлён");
                  setEditing(false);
                },
              });
            }}
          />
        )}
      </Modal>
      <ConfirmDialog
        open={confirmFull}
        title="Сканировать всю историю?"
        confirmLabel="Запустить"
        loading={enqueue.isPending}
        onClose={() => setConfirmFull(false)}
        onConfirm={() => scan(true)}
      >
        Обычный скан читает только новые коммиты. Полный перечитывает всю историю — это дольше, но находит секреты, которые
        добавили в реестр уже после прошлых сканов (это и так делается автоматически при изменении реестра).
      </ConfirmDialog>
      <ConfirmDialog
        open={confirmDelete}
        title="Удалить источник?"
        confirmLabel="Удалить"
        danger
        loading={remove.isPending}
        onClose={() => setConfirmDelete(false)}
        onConfirm={() =>
          remove.mutate(s.id, {
            onSuccess: () => {
              toast.success("Источник удалён");
              navigate("/sources");
            },
            onError: (e) => toast.error(e),
          })
        }
      >
        Активный скан будет отменён. Найденные места останутся в реестре, история сканов — тоже.
      </ConfirmDialog>
    </>
  );
}

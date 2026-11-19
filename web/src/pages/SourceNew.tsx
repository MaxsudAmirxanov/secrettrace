import { Link, useNavigate } from "react-router-dom";

import { useCreateSource } from "../api/hooks";
import { SourceForm, sourceToValues, valuesToCreate } from "../components/SourceForm";
import { useToast } from "../components/Toast";
import { Card, Notice, PageHeader } from "../components/ui";

export function SourceNewPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const create = useCreateSource();
  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/sources" className="link">
            ← Источники
          </Link>
        }
        title="Новый git-репозиторий"
        description="Воркер клонирует репозиторий к себе (зеркало без рабочей копии) и проверяет историю и текущее состояние."
      />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <SourceForm
            initial={sourceToValues()}
            isNew
            submitLabel="Создать"
            busy={create.isPending}
            error={create.error}
            onCancel={() => navigate("/sources")}
            onSubmit={(v) =>
              create.mutate(valuesToCreate(v), {
                onSuccess: (s) => {
                  toast.success(`Источник «${s.name}» создан`);
                  navigate(`/sources/${s.id}`);
                },
              })
            }
          />
        </Card>
        <div className="space-y-4">
          <Notice title="Учётные данные не проходят через UI">
            Токен или ssh-ключ кладёт администратор сервера в <code>deploy/worker/git-credentials/</code>. Здесь указывается
            только имя файла. Рядом обязателен файл <code>&lt;имя&gt;.hosts</code> со списком хостов, которым этот токен
            можно отдавать.
          </Notice>
          <Notice tone="amber" title="Для ssh">
            Отпечаток ключа хоста должен быть в <code>deploy/worker/ssh_known_hosts</code> — иначе подключение отклоняется.
          </Notice>
        </div>
      </div>
    </>
  );
}

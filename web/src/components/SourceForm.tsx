import { type FormEvent, useState } from "react";

import type { Source, SourceConfig, SourceCreate } from "../api/types";
import { Button, Checkbox, ErrorBanner, Field, Input, Select } from "./ui";

export const SCHEDULE_PRESETS = [
  { value: "", label: "Без расписания (только вручную)" },
  { value: "0 3 * * *", label: "Каждый день в 03:00 UTC" },
  { value: "0 */6 * * *", label: "Каждые 6 часов" },
  { value: "0 * * * *", label: "Каждый час" },
  { value: "0 6 * * 1-5", label: "По будням в 06:00 UTC" },
  { value: "0 3 * * 1", label: "По понедельникам в 03:00 UTC" },
  { value: "custom", label: "Своё cron-выражение…" },
] as const;

const URI_RE = /^(https:\/\/[^\s@/]+\/\S+|ssh:\/\/[^\s/]+\/\S+|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:\S+)$/;
const REF_RE = /^[A-Za-z0-9_-]{1,64}$/;
const USER_RE = /^[A-Za-z0-9._@][A-Za-z0-9._@-]{0,63}$/;
const CRON_RE = /^\S+( \S+){4}$/;

export interface SourceFormValues {
  name: string;
  uri: string;
  environment: string;
  credential_ref: string;
  schedule: string;
  enabled: boolean;
  username: string;
  max_blob_mib: string;
}

export function sourceToValues(s?: Source): SourceFormValues {
  return {
    name: s?.name ?? "",
    uri: s?.uri ?? "",
    environment: s?.environment ?? "",
    credential_ref: s?.credential_ref ?? "",
    schedule: s?.schedule ?? "",
    enabled: s?.enabled ?? true,
    username: s?.config.username ?? "",
    max_blob_mib: s?.config.max_blob_bytes ? String(Math.round(s.config.max_blob_bytes / 1048576)) : "",
  };
}

export function validateSource(v: SourceFormValues, isNew: boolean): Record<string, string> {
  const e: Record<string, string> = {};
  if (!v.name.trim()) e.name = "Укажите имя";
  if (isNew) {
    const uri = v.uri.trim();
    if (!uri) e.uri = "Укажите адрес репозитория";
    else if (/^https?:\/\/[^/]*@/.test(uri)) e.uri = "Не указывайте логин или токен в URL — используйте файл доступа";
    else if (uri.startsWith("http://")) e.uri = "Только https:// — http не защищает трафик";
    else if (!URI_RE.test(uri)) e.uri = "Формат: https://host/org/repo.git, ssh://host/org/repo.git или git@host:org/repo.git";
  }
  if (v.credential_ref && !REF_RE.test(v.credential_ref)) e.credential_ref = "Латиница, цифры, «_» и «-», до 64 символов";
  if (v.username && !USER_RE.test(v.username)) e.username = "Недопустимое имя пользователя";
  if (v.schedule && !CRON_RE.test(v.schedule.trim())) e.schedule = "Нужно 5 полей: минута час день месяц день_недели";
  if (v.environment.length > 64) e.environment = "До 64 символов";
  if (v.max_blob_mib) {
    const n = Number(v.max_blob_mib);
    if (!Number.isInteger(n) || n < 1 || n > 64) e.max_blob_mib = "От 1 до 64 МиБ";
  }
  return e;
}

export function valuesToConfig(v: SourceFormValues): SourceConfig {
  const c: SourceConfig = {};
  if (v.username.trim()) c.username = v.username.trim();
  if (v.max_blob_mib) c.max_blob_bytes = Number(v.max_blob_mib) * 1048576;
  return c;
}

export function valuesToCreate(v: SourceFormValues): SourceCreate {
  const body: SourceCreate = { name: v.name.trim(), type: "git_repo", uri: v.uri.trim(), enabled: v.enabled };
  if (v.environment.trim()) body.environment = v.environment.trim();
  if (v.credential_ref.trim()) body.credential_ref = v.credential_ref.trim();
  if (v.schedule.trim()) body.schedule = v.schedule.trim();
  const config = valuesToConfig(v);
  if (Object.keys(config).length > 0) body.config = config;
  return body;
}

export function SourceForm({
  initial,
  isNew,
  submitLabel,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  initial: SourceFormValues;
  isNew: boolean;
  submitLabel: string;
  busy: boolean;
  error: unknown;
  onSubmit: (v: SourceFormValues) => void;
  onCancel: () => void;
}) {
  const [v, setV] = useState(initial);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const known = SCHEDULE_PRESETS.some((p) => p.value === v.schedule && p.value !== "custom");
  const [custom, setCustom] = useState(!known);
  const set = <K extends keyof SourceFormValues>(k: K, val: SourceFormValues[K]) => setV((s) => ({ ...s, [k]: val }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const errs = validateSource(v, isNew);
    setErrors(errs);
    if (Object.keys(errs).length === 0) onSubmit(v);
  };

  return (
    <form onSubmit={submit} noValidate className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Имя" required error={errors.name}>
          {(id, d) => <Input id={id} aria-describedby={d} value={v.name} onChange={(e) => set("name", e.target.value)} maxLength={200} invalid={!!errors.name} placeholder="infra-app" />}
        </Field>
        <Field label="Окружение" error={errors.environment} hint="Попадает в находки; правила могут учитывать его">
          {(id, d) => <Input id={id} aria-describedby={d} value={v.environment} onChange={(e) => set("environment", e.target.value)} maxLength={64} placeholder="prod" />}
        </Field>
      </div>
      <Field
        label="Адрес git-репозитория"
        required={isNew}
        error={errors.uri}
        hint={isNew ? "Хост должен быть в ST_WORKER_ALLOWED_HOSTS воркера. Адрес после создания не меняется." : "Адрес источника не меняется: другой репозиторий — другой источник."}
      >
        {(id, d) => (
          <Input
            id={id}
            aria-describedby={d}
            value={v.uri}
            onChange={(e) => set("uri", e.target.value)}
            disabled={!isNew}
            maxLength={2048}
            spellCheck={false}
            placeholder="https://github.com/acme/infra.git"
            className="font-mono"
            invalid={!!errors.uri}
          />
        )}
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          label="Файл доступа (credential_ref)"
          error={errors.credential_ref}
          hint={<>Имя файла в каталоге учётных данных воркера. Рядом нужен <code>&lt;имя&gt;.hosts</code>. Пусто — публичный репозиторий.</>}
        >
          {(id, d) => (
            <Input id={id} aria-describedby={d} value={v.credential_ref} onChange={(e) => set("credential_ref", e.target.value)} maxLength={64} spellCheck={false} placeholder="github_infra" className="font-mono" invalid={!!errors.credential_ref} />
          )}
        </Field>
        <Field label="Пользователь для HTTPS / SSH" error={errors.username} hint="По умолчанию для HTTPS: x-access-token">
          {(id, d) => <Input id={id} aria-describedby={d} value={v.username} onChange={(e) => set("username", e.target.value)} maxLength={64} spellCheck={false} invalid={!!errors.username} />}
        </Field>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Расписание" error={errors.schedule} hint="Cron из 5 полей, UTC, не чаще раза в 5 минут">
          {(id, d) => (
            <div className="space-y-2">
              <Select
                id={id}
                aria-describedby={d}
                value={custom ? "custom" : v.schedule}
                onChange={(e) => {
                  if (e.target.value === "custom") {
                    setCustom(true);
                  } else {
                    setCustom(false);
                    set("schedule", e.target.value);
                  }
                }}
              >
                {SCHEDULE_PRESETS.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
              </Select>
              {custom && (
                <Input
                  aria-label="Cron-выражение"
                  value={v.schedule}
                  onChange={(e) => set("schedule", e.target.value)}
                  placeholder="30 2 * * *"
                  className="font-mono"
                  maxLength={100}
                  invalid={!!errors.schedule}
                />
              )}
            </div>
          )}
        </Field>
        <Field label="Максимальный размер файла, МиБ" error={errors.max_blob_mib} hint="Крупнее — пропускаются. По умолчанию 16">
          {(id, d) => <Input id={id} aria-describedby={d} type="number" min={1} max={64} value={v.max_blob_mib} onChange={(e) => set("max_blob_mib", e.target.value)} invalid={!!errors.max_blob_mib} />}
        </Field>
      </div>
      <Checkbox
        checked={v.enabled}
        onChange={(c) => set("enabled", c)}
        label="Включён"
        hint="Выключенный источник не сканируется; активный скан отменяется"
      />
      {error !== null && error !== undefined && <ErrorBanner error={error} />}
      <div className="flex justify-end gap-2">
        <Button onClick={onCancel}>Отмена</Button>
        <Button type="submit" variant="primary" loading={busy}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

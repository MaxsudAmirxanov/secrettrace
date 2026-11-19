import { type FormEvent, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { ApiError } from "../api/client";
import { useCreateSecret } from "../api/hooks";
import type { AllowRule } from "../api/types";
import { AllowRulesEditor, cleanRules, rulesError } from "../components/AllowRulesEditor";
import { IconEye, IconEyeOff, IconLock } from "../components/icons";
import { useToast } from "../components/Toast";
import { Button, Card, ErrorBanner, Field, Input, Mono, Notice, PageHeader, Select, Textarea } from "../components/ui";
import { prepare } from "../crypto/digest";
import { deriveHints, mask } from "../crypto/hints";
import { NORMALIZE_MESSAGES, NormalizeFailure, charCount, normalize } from "../crypto/normalize";
import { SECRET_TYPES, type SecretType, isKeyMaterial, isLowEntropy } from "../crypto/secretTypes";
import { useDebounced } from "../lib/hooks";
import { SECRET_TYPE_LABELS } from "../lib/labels";

/** `YYYY-MM-DD` from a date input → end of that day in UTC. */
export function expiryToIso(date: string): string | undefined {
  return /^\d{4}-\d{2}-\d{2}$/.test(date) ? `${date}T23:59:59Z` : undefined;
}

function usePreview(type: SecretType, value: string) {
  const v = useDebounced(value, 200);
  return useMemo(() => {
    if (!v) return null;
    try {
      const canonical = normalize(type, v);
      return { ok: true as const, masked: mask(deriveHints(type, canonical)), length: charCount(canonical) };
    } catch (e) {
      return { ok: false as const, error: e instanceof NormalizeFailure ? NORMALIZE_MESSAGES[e.code] : "Некорректное значение" };
    }
  }, [type, v]);
}

export function SecretNewPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const create = useCreateSecret();

  const [name, setName] = useState("");
  const [type, setType] = useState<SecretType>("token");
  const [owner, setOwner] = useState("");
  const [purpose, setPurpose] = useState("");
  const [expires, setExpires] = useState("");
  const [value, setValue] = useState("");
  const [reveal, setReveal] = useState(false);
  const [rules, setRules] = useState<AllowRule[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const preview = usePreview(type, value);
  const multiline = isKeyMaterial(type);
  const minDate = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);

  const validate = (): boolean => {
    const e: Record<string, string> = {};
    if (!name.trim()) e.name = "Укажите имя";
    if (!owner.trim()) e.owner = "Укажите владельца (команду или человека)";
    if (!value) e.value = "Вставьте значение секрета";
    else {
      try {
        normalize(type, value);
      } catch (err) {
        e.value = err instanceof NormalizeFailure ? NORMALIZE_MESSAGES[err.code] : "Некорректное значение";
      }
    }
    const re = rulesError(rules);
    if (re) e.rules = re;
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitError(null);
    if (!validate()) return;
    setBusy(true);
    let prepared;
    try {
      prepared = await prepare(type, value);
    } catch (err) {
      setBusy(false);
      setErrors({ value: err instanceof NormalizeFailure ? NORMALIZE_MESSAGES[err.code] : "Не удалось вычислить digest" });
      return;
    }
    // The value is no longer needed: drop it from state before anything is sent.
    setValue("");
    setReveal(false);
    try {
      const s = await create.mutateAsync({
        name: name.trim(),
        type,
        owner: owner.trim(),
        purpose: purpose.trim() || undefined,
        digest: prepared.digest,
        hints: prepared.hints,
        allow_rules: cleanRules(rules),
        expires_at: expiryToIso(expires),
      });
      toast.success(`Секрет «${s.name}» зарегистрирован`);
      navigate(`/secrets/${s.id}`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setSubmitError(new ApiError(409, "Уже зарегистрирован", "Секрет с таким именем или таким же значением уже есть в реестре. Значение очищено — вставьте его снова при повторной попытке.", undefined));
      } else {
        setSubmitError(err);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/secrets" className="link">
            ← Реестр секретов
          </Link>
        }
        title="Регистрация секрета"
        description="После регистрации SecretTrace будет искать это значение во всех источниках и в данных от CI."
      />
      <form onSubmit={submit} noValidate className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card title="Значение">
            <div className="space-y-4">
              <Field label="Тип" required>
                {(id) => (
                  <Select id={id} value={type} onChange={(e) => setType(e.target.value as SecretType)}>
                    {SECRET_TYPES.map((t) => (
                      <option key={t} value={t}>
                        {SECRET_TYPE_LABELS[t]}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field
                label="Значение секрета"
                required
                error={errors.value}
                hint={
                  multiline
                    ? "Вставьте PEM-блок целиком или публичный ключ OpenSSH. Переносы строк и \\n не важны."
                    : "Пробелы по краям обрезаются."
                }
              >
                {(id, d) => (
                  <div className="relative">
                    {multiline ? (
                      <Textarea
                        id={id}
                        aria-describedby={d}
                        rows={6}
                        value={value}
                        onChange={(e) => setValue(e.target.value)}
                        autoComplete="off"
                        spellCheck={false}
                        autoCorrect="off"
                        autoCapitalize="none"
                        data-lpignore="true"
                        className={reveal ? "font-mono text-xs" : "font-mono text-xs [-webkit-text-security:disc]"}
                        invalid={!!errors.value}
                      />
                    ) : (
                      <Input
                        id={id}
                        aria-describedby={d}
                        type={reveal ? "text" : "password"}
                        value={value}
                        onChange={(e) => setValue(e.target.value)}
                        autoComplete="new-password"
                        spellCheck={false}
                        autoCorrect="off"
                        autoCapitalize="none"
                        data-lpignore="true"
                        className="pr-10 font-mono"
                        invalid={!!errors.value}
                      />
                    )}
                    <button
                      type="button"
                      onClick={() => setReveal((r) => !r)}
                      className="absolute right-2 top-2 rounded p-1 text-slate-400 hover:text-slate-600"
                      aria-label={reveal ? "Скрыть значение" : "Показать значение"}
                    >
                      {reveal ? <IconEyeOff size={16} /> : <IconEye size={16} />}
                    </button>
                  </div>
                )}
              </Field>
              {preview?.ok && (
                <div className="rounded-lg bg-slate-50 px-4 py-3 text-sm dark:bg-slate-800/60">
                  <p className="text-slate-600 dark:text-slate-300">
                    Будет показан как <Mono>{preview.masked}</Mono> · длина {preview.length} симв.
                  </p>
                  {isLowEntropy(type) && (
                    <p className="mt-1 text-xs text-slate-500">
                      Для паролей и строк подключения подсказки не сохраняются совсем.
                    </p>
                  )}
                </div>
              )}
              <Notice tone="green">
                <span className="flex items-start gap-2">
                  <IconLock size={16} className="mt-0.5 shrink-0" />
                  <span>
                    Значение не отправляется на сервер. Браузер нормализует его и вычисляет SHA-256; сервер хранит только
                    HMAC от этого digest с ключом, которого нет в базе. После отправки поле очищается.
                  </span>
                </span>
              </Notice>
            </div>
          </Card>

          <Card title="Где секрет может находиться легально">
            <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
              Находки, подходящие под правило, не считаются нарушением (например, зашифрованные манифесты в инфраструктурном
              репозитории).
            </p>
            <AllowRulesEditor rules={rules} onChange={setRules} />
            {errors.rules && <p className="mt-2 text-xs font-medium text-rose-600">{errors.rules}</p>}
          </Card>
        </div>

        <div className="space-y-6">
          <Card title="Описание">
            <div className="space-y-4">
              <Field label="Имя" required error={errors.name} hint="Уникальное, например prod-aws-deploy-key">
                {(id, d) => (
                  <Input id={id} aria-describedby={d} value={name} onChange={(e) => setName(e.target.value)} maxLength={200} invalid={!!errors.name} />
                )}
              </Field>
              <Field label="Владелец" required error={errors.owner}>
                {(id, d) => (
                  <Input
                    id={id}
                    aria-describedby={d}
                    value={owner}
                    onChange={(e) => setOwner(e.target.value)}
                    placeholder="platform-team"
                    maxLength={200}
                    invalid={!!errors.owner}
                  />
                )}
              </Field>
              <Field label="Назначение">
                {(id) => <Textarea id={id} rows={3} value={purpose} onChange={(e) => setPurpose(e.target.value)} maxLength={2000} />}
              </Field>
              <Field label="Действует до" hint="Необязательно. Конец дня по UTC.">
                {(id, d) => <Input id={id} aria-describedby={d} type="date" min={minDate} value={expires} onChange={(e) => setExpires(e.target.value)} />}
              </Field>
            </div>
          </Card>
          {submitError !== null && <ErrorBanner error={submitError} />}
          <div className="flex gap-2">
            <Button type="submit" variant="primary" loading={busy} className="flex-1">
              Зарегистрировать
            </Button>
            <Link to="/secrets" className="btn btn-secondary">
              Отмена
            </Link>
          </div>
        </div>
      </form>
    </>
  );
}

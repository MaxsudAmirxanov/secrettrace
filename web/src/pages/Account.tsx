import { type FormEvent, useState } from "react";

import { changePassword } from "../api/hooks";
import { useAuth, useUser } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import { Button, Card, DescriptionList, ErrorBanner, Field, Input, Notice, PageHeader } from "../components/ui";
import { ROLE_HINTS, ROLE_LABELS } from "../lib/labels";
import { passwordProblem } from "../lib/password";

export function AccountPage() {
  const me = useUser();
  const { logout } = useAuth();
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [errors, setErrors] = useState<{ next?: string; repeat?: string }>({});
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const errs: typeof errors = {};
    const p = passwordProblem(me.username, next);
    if (p) errs.next = p;
    if (next !== repeat) errs.repeat = "Пароли не совпадают";
    setErrors(errs);
    if (Object.keys(errs).length || !current) return;
    setBusy(true);
    setError(null);
    try {
      await changePassword(current, next);
      toast.success("Пароль изменён. Остальные сессии завершены.");
    } catch (err) {
      setError(err);
    } finally {
      setCurrent("");
      setNext("");
      setRepeat("");
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader title="Учётная запись" />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Профиль">
          <DescriptionList
            items={[
              ["Имя пользователя", me.username],
              ["Роль", ROLE_LABELS[me.role]],
              ["Права", ROLE_HINTS[me.role]],
              ["Второй фактор", "TOTP подключён"],
            ]}
          />
          <div className="mt-6 space-y-3">
            <Notice>Потеряли телефон с аутентификатором? Попросите администратора сбросить TOTP — при следующем входе подключите заново.</Notice>
            <Button onClick={() => void logout()} className="w-full">
              Выйти
            </Button>
          </div>
        </Card>
        <Card title="Сменить пароль" className="lg:col-span-2">
          <form onSubmit={submit} noValidate className="max-w-md space-y-4">
            <Field label="Текущий пароль" required>
              {(id) => <Input id={id} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" maxLength={256} />}
            </Field>
            <Field label="Новый пароль" required error={errors.next} hint="Не короче 12 символов; лучше — фраза из нескольких слов">
              {(id, d) => <Input id={id} aria-describedby={d} type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" maxLength={256} invalid={!!errors.next} />}
            </Field>
            <Field label="Повторите новый пароль" required error={errors.repeat}>
              {(id, d) => <Input id={id} aria-describedby={d} type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} autoComplete="new-password" maxLength={256} invalid={!!errors.repeat} />}
            </Field>
            {error !== null && <ErrorBanner error={error} />}
            <p className="text-xs text-slate-500">Неверный текущий пароль считается неудачной попыткой входа: после 5 попыток учётная запись блокируется на 15 минут.</p>
            <Button type="submit" variant="primary" loading={busy} disabled={!current || !next || !repeat}>
              Сменить пароль
            </Button>
          </form>
        </Card>
      </div>
    </>
  );
}

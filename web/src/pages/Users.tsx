import { useState } from "react";

import { useCreateUser, useUserAction, useUsers } from "../api/hooks";
import type { Role, User } from "../api/types";
import { useUser } from "../auth/AuthContext";
import { IconPlus, IconUsers } from "../components/icons";
import { ConfirmDialog, Modal } from "../components/Modal";
import { DataTable } from "../components/Table";
import { Time } from "../components/Time";
import { useToast } from "../components/Toast";
import { Badge, Button, CopyButton, ErrorBanner, Field, Input, Notice, PageHeader, Select } from "../components/ui";
import { ROLE_HINTS, ROLE_LABELS, ROLE_ORDER } from "../lib/labels";
import { generatePassword, passwordProblem } from "../lib/password";

function PasswordField({
  username,
  value,
  onChange,
  error,
}: {
  username: string;
  value: string;
  onChange: (v: string) => void;
  error: string | null;
}) {
  return (
    <Field label="Пароль" required error={error} hint="Не короче 12 символов. Передайте его пользователю безопасным каналом.">
      {(id, d) => (
        <div className="flex gap-2">
          <Input id={id} aria-describedby={d} value={value} onChange={(e) => onChange(e.target.value)} autoComplete="new-password" spellCheck={false} className="font-mono" invalid={!!error} maxLength={256} />
          <Button onClick={() => onChange(generatePassword())}>Сгенерировать</Button>
          {value && !passwordProblem(username, value) && <CopyButton value={value} label="" />}
        </div>
      )}
    </Field>
  );
}

function CreateModal({ onClose }: { onClose: () => void }) {
  const create = useCreateUser();
  const toast = useToast();
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState<{ username?: string; password?: string }>({});

  const submit = () => {
    const e: typeof errors = {};
    if (!/^[A-Za-z0-9._@-]{1,64}$/.test(username.trim())) e.username = "1–64 символа: латиница, цифры, . _ @ -";
    const p = passwordProblem(username.trim(), password);
    if (p) e.password = p;
    setErrors(e);
    if (Object.keys(e).length) return;
    create.mutate(
      { username: username.trim(), role, password },
      {
        onSuccess: (u) => {
          setPassword("");
          toast.success(`Пользователь ${u.username} создан. TOTP он подключит при первом входе.`);
          onClose();
        },
      },
    );
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Новый пользователь"
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
        <Field label="Имя пользователя" required error={errors.username}>
          {(id, d) => <Input id={id} aria-describedby={d} value={username} onChange={(e) => setUsername(e.target.value)} maxLength={64} autoCapitalize="none" spellCheck={false} invalid={!!errors.username} />}
        </Field>
        <Field label="Роль" hint={ROLE_HINTS[role]}>
          {(id, d) => (
            <Select id={id} aria-describedby={d} value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {ROLE_ORDER.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <PasswordField username={username} value={password} onChange={setPassword} error={errors.password ?? null} />
        {create.error && <ErrorBanner error={create.error} />}
      </div>
    </Modal>
  );
}

type Pending =
  | { kind: "role"; user: User; role: Role }
  | { kind: "active"; user: User; active: boolean }
  | { kind: "reset-mfa"; user: User }
  | { kind: "unlock"; user: User }
  | { kind: "password"; user: User };

const CONFIRM_TEXT: Record<Pending["kind"], (p: Pending) => { title: string; text: string; danger?: boolean }> = {
  role: (p) => ({
    title: "Изменить роль?",
    text: `${p.user.username}: ${ROLE_LABELS[p.user.role]} → ${p.kind === "role" ? ROLE_LABELS[p.role] : ""}. Действует сразу, без повторного входа.`,
  }),
  active: (p) =>
    p.kind === "active" && !p.active
      ? { title: "Отключить пользователя?", text: `${p.user.username} не сможет войти, все его сессии будут завершены.`, danger: true }
      : { title: "Включить пользователя?", text: `${p.user.username} снова сможет войти.` },
  "reset-mfa": (p) => ({
    title: "Сбросить двухфакторную аутентификацию?",
    text: `Привязка TOTP у ${p.user.username} будет удалена, сессии завершены. При следующем входе он подключит приложение заново. Делайте это, только убедившись, что запрос исходит от владельца учётной записи.`,
    danger: true,
  }),
  unlock: (p) => ({ title: "Разблокировать?", text: `Счётчик неудачных входов ${p.user.username} будет сброшен.` }),
  password: () => ({ title: "", text: "" }),
};

export function UsersPage() {
  const me = useUser();
  const toast = useToast();
  const { data, error, isLoading, refetch } = useUsers();
  const action = useUserAction();
  const [creating, setCreating] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [pwError, setPwError] = useState<string | null>(null);
  const items = data ?? [];

  const run = () => {
    if (!pending) return;
    const p = pending;
    const done = { onSuccess: () => (toast.success("Готово"), setPending(null), setNewPassword("")), onError: (e: unknown) => toast.error(e) };
    switch (p.kind) {
      case "role":
        return action.mutate({ kind: "update", id: p.user.id, body: { role: p.role } }, done);
      case "active":
        return action.mutate({ kind: "update", id: p.user.id, body: { is_active: p.active } }, done);
      case "password": {
        const problem = passwordProblem(p.user.username, newPassword);
        if (problem) return setPwError(problem);
        return action.mutate({ kind: "password", id: p.user.id, password: newPassword }, done);
      }
      default:
        return action.mutate({ kind: p.kind, id: p.user.id }, done);
    }
  };

  const confirm = pending && pending.kind !== "password" ? CONFIRM_TEXT[pending.kind](pending) : null;

  return (
    <>
      <PageHeader
        title="Пользователи"
        description="Локальные учётные записи. Вход — пароль и обязательный TOTP. Свою роль и статус изменить нельзя; последнего администратора — тоже."
        actions={
          <Button variant="primary" icon={<IconPlus size={16} />} onClick={() => setCreating(true)}>
            Добавить
          </Button>
        }
      />
      <DataTable
        loading={isLoading}
        error={error}
        onRetry={() => void refetch()}
        empty={items.length === 0}
        emptyIcon={<IconUsers />}
        head={
          <tr>
            <th>Пользователь</th>
            <th>Роль</th>
            <th>Состояние</th>
            <th>Последний вход</th>
            <th className="text-right">Действия</th>
          </tr>
        }
      >
        {items.map((u) => {
          const self = u.id === me.id;
          return (
            <tr key={u.id}>
              <td>
                <p className="font-medium text-slate-900 dark:text-white">
                  {u.username}
                  {self && <span className="ml-2 text-xs font-normal text-slate-500">(вы)</span>}
                </p>
                <p className="text-xs text-slate-500">
                  создан <Time iso={u.created_at} />
                </p>
              </td>
              <td>
                <Select
                  value={u.role}
                  disabled={self}
                  aria-label={`Роль ${u.username}`}
                  className="w-44 py-1.5"
                  onChange={(e) => setPending({ kind: "role", user: u, role: e.target.value as Role })}
                >
                  {ROLE_ORDER.map((r) => (
                    <option key={r} value={r}>
                      {ROLE_LABELS[r]}
                    </option>
                  ))}
                </Select>
              </td>
              <td>
                <div className="flex flex-wrap gap-1">
                  {u.is_active ? <Badge tone="green">Активен</Badge> : <Badge>Отключён</Badge>}
                  {u.is_locked && <Badge tone="red">Заблокирован</Badge>}
                  {u.mfa_enabled ? <Badge tone="blue">TOTP</Badge> : <Badge tone="amber">TOTP не подключён</Badge>}
                  {u.failed_logins > 0 && !u.is_locked && <Badge tone="amber">неудачных входов: {u.failed_logins}</Badge>}
                </div>
              </td>
              <td>
                <Time iso={u.last_login_at} fallback="не входил" />
              </td>
              <td>
                <div className="flex flex-wrap justify-end gap-1">
                  {u.is_locked && (
                    <Button size="sm" onClick={() => setPending({ kind: "unlock", user: u })}>
                      Разблокировать
                    </Button>
                  )}
                  {!self && (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => (setPwError(null), setNewPassword(""), setPending({ kind: "password", user: u }))}>
                        Пароль
                      </Button>
                      {u.mfa_enabled && (
                        <Button size="sm" variant="ghost" onClick={() => setPending({ kind: "reset-mfa", user: u })}>
                          Сбросить TOTP
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className={u.is_active ? "text-rose-600" : ""}
                        onClick={() => setPending({ kind: "active", user: u, active: !u.is_active })}
                      >
                        {u.is_active ? "Отключить" : "Включить"}
                      </Button>
                    </>
                  )}
                </div>
              </td>
            </tr>
          );
        })}
      </DataTable>

      {creating && <CreateModal onClose={() => setCreating(false)} />}
      <ConfirmDialog
        open={confirm !== null}
        title={confirm?.title ?? ""}
        danger={confirm?.danger}
        loading={action.isPending}
        onClose={() => setPending(null)}
        onConfirm={run}
      >
        {confirm?.text}
      </ConfirmDialog>
      <Modal
        open={pending?.kind === "password"}
        onClose={() => (setPending(null), setNewPassword(""))}
        title={`Новый пароль: ${pending?.user.username ?? ""}`}
        footer={
          <>
            <Button onClick={() => (setPending(null), setNewPassword(""))}>Отмена</Button>
            <Button variant="primary" loading={action.isPending} onClick={run}>
              Установить
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Notice tone="amber">Все сессии пользователя будут завершены, блокировка снята. TOTP остаётся прежним.</Notice>
          {pending && <PasswordField username={pending.user.username} value={newPassword} onChange={setNewPassword} error={pwError} />}
        </div>
      </Modal>
    </>
  );
}

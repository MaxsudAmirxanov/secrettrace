import { type FormEvent, useEffect, useRef, useState } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";

import { ApiError, errorMessage, post, setCsrfToken } from "../api/client";
import type { EnrollResponse, LoginResponse, Me } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { safeNext } from "../auth/guards";
import { IconShield } from "../components/icons";
import { QrCode } from "../components/QrCode";
import { Button, CopyButton, ErrorBanner, Field, Input, Notice, PageLoader, Spinner } from "../components/ui";

type Step = "password" | "enroll" | "verify";

function groupSecret(s: string): string {
  return s.replace(/(.{4})/g, "$1 ").trim();
}

function CodeForm({ onDone, onRestart, title }: { onDone: (me: Me) => void; onRestart: () => void; title: string }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!/^\d{6}$/.test(code)) {
      setError("Код — 6 цифр из приложения-аутентификатора");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      onDone(await post<Me>("/auth/mfa/verify", { code }));
    } catch (err) {
      setCode("");
      if (err instanceof ApiError && err.status === 401) {
        setError("Неверный код или истекло время входа (5 минут). Проверьте время на телефоне.");
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <Field label={title} error={error}>
        {(id, d) => (
          <Input
            id={id}
            aria-describedby={d}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="000000"
            className="text-center font-mono text-lg tracking-[0.5em]"
            autoFocus
            invalid={!!error}
          />
        )}
      </Field>
      <Button type="submit" variant="primary" className="w-full" loading={busy}>
        Подтвердить
      </Button>
      <button type="button" className="w-full text-center text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400" onClick={onRestart}>
        Войти заново
      </button>
    </form>
  );
}

function Enroll({ onDone, onRestart }: { onDone: (me: Me) => void; onRestart: () => void }) {
  const [data, setData] = useState<EnrollResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const started = useRef(false);

  useEffect(() => {
    // Enrollment creates a new seed; StrictMode must not call it twice.
    if (started.current) return;
    started.current = true;
    post<EnrollResponse>("/auth/mfa/enroll").then(setData, setError);
  }, []);

  if (error) {
    return (
      <div className="space-y-4">
        <ErrorBanner error={error} />
        <Button className="w-full" onClick={onRestart}>
          Войти заново
        </Button>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="flex justify-center py-10 text-slate-400">
        <Spinner />
      </div>
    );
  }
  return (
    <div className="space-y-5">
      <Notice title="Подключите двухфакторную аутентификацию">
        Это первый вход: отсканируйте QR-код приложением-аутентификатором (Aegis, 2FAS, Google Authenticator и т. п.)
        и введите код из него. Без второго фактора вход невозможен.
      </Notice>
      <div className="flex justify-center">
        <QrCode value={data.otpauth_uri} label="QR-код для приложения-аутентификатора" />
      </div>
      <div>
        <p className="label">Или введите ключ вручную</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 break-all rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs dark:bg-slate-800">
            {groupSecret(data.secret)}
          </code>
          <CopyButton value={data.secret} />
        </div>
      </div>
      <CodeForm onDone={onDone} onRestart={onRestart} title="Код из приложения" />
    </div>
  );
}

export function LoginPage() {
  const { user, expired, signedIn } = useAuth();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const next = safeNext(params.get("next"));

  const [step, setStep] = useState<Step>("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user === undefined) return <PageLoader />;
  if (user) return <Navigate to={next} replace />;

  const restart = () => {
    setCsrfToken(null);
    setStep("password");
    setError(null);
  };

  const done = (me: Me) => {
    signedIn(me);
    navigate(next, { replace: true });
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError("Введите имя пользователя и пароль");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await post<LoginResponse>("/auth/login", { username: username.trim(), password });
      setCsrfToken(r.csrf_token);
      setStep(r.mfa_enrolled ? "verify" : "enroll");
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? "Неверное имя пользователя или пароль, либо учётная запись заблокирована"
          : errorMessage(err),
      );
    } finally {
      setPassword("");
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-slate-100 to-slate-50 px-4 py-12 dark:from-slate-950 dark:to-slate-900">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <span className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-brand-600 text-white shadow-lg shadow-brand-600/30">
            <IconShield size={26} />
          </span>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">SecretTrace</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Контроль утечек секретов</p>
        </div>
        <div className="card p-6">
          {expired && step === "password" && (
            <div className="mb-4">
              <Notice tone="amber">Сессия завершена. Войдите снова.</Notice>
            </div>
          )}
          {step === "password" && (
            <form onSubmit={submit} className="space-y-4" noValidate>
              <Field label="Имя пользователя">
                {(id) => (
                  <Input
                    id={id}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    autoFocus
                    maxLength={64}
                  />
                )}
              </Field>
              <Field label="Пароль" error={error}>
                {(id, d) => (
                  <Input
                    id={id}
                    aria-describedby={d}
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    maxLength={256}
                    invalid={!!error}
                  />
                )}
              </Field>
              <Button type="submit" variant="primary" className="w-full" loading={busy}>
                Продолжить
              </Button>
            </form>
          )}
          {step === "enroll" && <Enroll onDone={done} onRestart={restart} />}
          {step === "verify" && <CodeForm onDone={done} onRestart={restart} title="Код из приложения-аутентификатора" />}
        </div>
        <p className="mt-6 text-center text-xs text-slate-400">Все действия записываются в журнал аудита</p>
      </div>
    </div>
  );
}

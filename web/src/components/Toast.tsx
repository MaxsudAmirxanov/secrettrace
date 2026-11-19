import { type ReactNode, createContext, useCallback, useContext, useMemo, useState } from "react";

import { errorMessage } from "../api/client";
import { IconAlert, IconCheck, IconClose } from "./icons";
import { cx } from "./ui";

type Kind = "success" | "error" | "info";
interface Toast {
  id: number;
  kind: Kind;
  text: string;
}

interface ToastApi {
  success: (text: string) => void;
  error: (e: unknown) => void;
  info: (text: string) => void;
}

const Ctx = createContext<ToastApi | null>(null);
let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const push = useCallback(
    (kind: Kind, text: string) => {
      const id = nextId++;
      setToasts((t) => [...t.slice(-3), { id, kind, text }]);
      window.setTimeout(() => dismiss(id), kind === "error" ? 8000 : 4000);
    },
    [dismiss],
  );
  const api = useMemo<ToastApi>(
    () => ({
      success: (t) => push("success", t),
      info: (t) => push("info", t),
      error: (e) => push("error", errorMessage(e)),
    }),
    [push],
  );
  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.kind === "error" ? "alert" : "status"}
            className={cx(
              "pointer-events-auto flex items-start gap-3 rounded-lg border px-4 py-3 text-sm shadow-lg",
              t.kind === "error"
                ? "border-rose-200 bg-white text-rose-800 dark:border-rose-500/40 dark:bg-slate-900 dark:text-rose-300"
                : "border-slate-200 bg-white text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100",
            )}
          >
            {t.kind === "error" ? (
              <IconAlert className="mt-0.5 shrink-0 text-rose-500" />
            ) : (
              <IconCheck className="mt-0.5 shrink-0 text-emerald-500" />
            )}
            <span className="flex-1">{t.text}</span>
            <button type="button" onClick={() => dismiss(t.id)} aria-label="Скрыть" className="text-slate-400 hover:text-slate-600">
              <IconClose size={16} />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useToast outside ToastProvider");
  return ctx;
}

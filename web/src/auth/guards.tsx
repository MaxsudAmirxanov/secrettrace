import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { EmptyState, PageLoader } from "../components/ui";
import { IconLock } from "../components/icons";
import type { Role } from "../api/types";
import { useAuth } from "./AuthContext";

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const location = useLocation();
  if (user === undefined) return <PageLoader />;
  if (user === null) {
    const next = location.pathname + location.search;
    return <Navigate to={next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`} replace />;
  }
  return <>{children}</>;
}

export function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  const { can } = useAuth();
  if (!can(role)) {
    return (
      <EmptyState icon={<IconLock />} title="Недостаточно прав">
        Этот раздел доступен роли «{role === "admin" ? "Администратор" : "Оператор"}» и выше.
      </EmptyState>
    );
  }
  return <>{children}</>;
}

/** Renders children only for users with at least `role` (UI hint; the server enforces). */
export function Can({ role, children }: { role: Role; children: ReactNode }) {
  const { can } = useAuth();
  return can(role) ? <>{children}</> : null;
}

/** Only same-origin paths are accepted as a post-login redirect. */
export function safeNext(next: string | null): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}

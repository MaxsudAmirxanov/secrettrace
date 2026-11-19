import { useQueryClient } from "@tanstack/react-query";
import { type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { ApiError, get, post, setCsrfToken, setUnauthorizedHandler } from "../api/client";
import type { Me, Role } from "../api/types";
import { roleAllows } from "../lib/labels";

interface AuthState {
  /** `undefined` while the session is being checked. */
  user: Me | null | undefined;
  /** Set when the session ended on its own (idle timeout, revoked). */
  expired: boolean;
  signedIn: (me: Me) => void;
  logout: () => Promise<void>;
  can: (role: Role) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [user, setUser] = useState<Me | null | undefined>(undefined);
  const [expired, setExpired] = useState(false);

  const clear = useCallback(() => {
    setCsrfToken(null);
    setUser(null);
    qc.clear();
  }, [qc]);

  useEffect(() => {
    const ctrl = new AbortController();
    get<Me>("/auth/me", undefined, ctrl.signal)
      .then((me) => {
        setCsrfToken(me.csrf_token);
        setUser(me);
      })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        if (!(e instanceof ApiError) || e.status !== 401) console.error("session check failed");
        setUser(null);
      });
    return () => ctrl.abort();
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setExpired(true);
      clear();
    });
    return () => setUnauthorizedHandler(null);
  }, [clear]);

  const signedIn = useCallback((me: Me) => {
    setCsrfToken(me.csrf_token);
    setExpired(false);
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    try {
      await post<undefined>("/auth/logout");
    } finally {
      setExpired(false);
      clear();
    }
  }, [clear]);

  const value = useMemo<AuthState>(
    () => ({ user, expired, signedIn, logout, can: (role) => !!user && roleAllows(user.role, role) }),
    [user, expired, signedIn, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

/** The signed-in user; only for components rendered inside `RequireAuth`. */
export function useUser(): Me {
  const { user } = useAuth();
  if (!user) throw new Error("useUser without a session");
  return user;
}

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";

import { AuthProvider } from "../auth/AuthContext";
import { ToastProvider } from "../components/Toast";

export interface Call {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
}

type Handler = (call: Call) => { status?: number; body?: unknown } | undefined;

/** Mock `fetch` with a router of `"METHOD /path"` → response; records every call. */
export function mockApi(routes: Record<string, Handler | { status?: number; body?: unknown }>) {
  const calls: Call[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = init?.method ?? "GET";
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    const call = { method, url, headers, body };
    calls.push(call);
    const path = url.replace(/^\/api\/v1/, "").split("?")[0];
    const route = routes[`${method} ${path}`];
    const res = typeof route === "function" ? route(call) : route;
    const status = res?.status ?? (route ? 200 : 404);
    const payload = res?.body ?? (status >= 400 ? { title: "err", status } : {});
    return new Response(status === 204 ? null : JSON.stringify(payload), {
      status,
      headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" },
    });
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

export const ME = { id: "u1", username: "alice", role: "operator", csrf_token: "csrf-1" } as const;

export function renderApp(ui: ReactElement, { route = "/", path = "*" }: { route?: string; path?: string } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>
        <ToastProvider>
          <AuthProvider>
            <Routes>
              <Route path={path} element={ui} />
              <Route path="*" element={<div>other page</div>} />
            </Routes>
          </AuthProvider>
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

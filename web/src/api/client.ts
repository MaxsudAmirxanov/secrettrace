/**
 * Minimal fetch wrapper: same-origin cookies, the CSRF header on state-changing
 * requests, RFC 7807 errors as `ApiError`. The CSRF token lives in memory only (it is
 * recovered from `/auth/me` after a reload); nothing is written to browser storage.
 */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly title: string,
    readonly detail: string | undefined,
    readonly requestId: string | undefined,
  ) {
    super(detail ?? title);
    this.name = "ApiError";
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

interface Options {
  body?: unknown;
  query?: Query;
  signal?: AbortSignal;
}

let csrfToken: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

/** Called once per 401 on a non-auth endpoint (expired or revoked session). */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

export function buildPath(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

const STATUS_TITLES: Record<number, string> = {
  400: "Некорректный запрос",
  401: "Требуется вход",
  403: "Недостаточно прав",
  404: "Не найдено",
  409: "Конфликт",
  413: "Слишком большой запрос",
  422: "Ошибка проверки данных",
  429: "Слишком много запросов, подождите минуту",
  500: "Внутренняя ошибка сервера",
  503: "Сервис недоступен",
};

async function toError(resp: Response): Promise<ApiError> {
  let title = STATUS_TITLES[resp.status] ?? `Ошибка ${resp.status}`;
  let detail: string | undefined;
  try {
    const p = (await resp.json()) as { title?: string; detail?: string };
    if (typeof p.detail === "string") detail = p.detail;
    if (!STATUS_TITLES[resp.status] && typeof p.title === "string") title = p.title;
  } catch {
    // Not JSON (proxy error page): keep the generic title.
  }
  return new ApiError(resp.status, title, detail, resp.headers.get("x-request-id") ?? undefined);
}

export async function api<T>(method: string, path: string, opts: Options = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let resp: Response;
  try {
    resp = await fetch(buildPath(`/api/v1${path}`, opts.query), {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new ApiError(0, "Сервер недоступен", "Проверьте соединение", undefined);
  }

  if (!resp.ok) {
    const err = await toError(resp);
    if (resp.status === 401 && !path.startsWith("/auth/")) onUnauthorized?.();
    throw err;
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export const get = <T>(path: string, query?: Query, signal?: AbortSignal) => api<T>("GET", path, { query, signal });
export const post = <T>(path: string, body?: unknown) => api<T>("POST", path, { body });
export const patch = <T>(path: string, body: unknown) => api<T>("PATCH", path, { body });
export const del = <T>(path: string) => api<T>("DELETE", path);

/** Human-readable message for any thrown value. */
export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.detail ? `${e.title}: ${e.detail}` : e.title;
  if (e instanceof Error) return e.message;
  return "Неизвестная ошибка";
}

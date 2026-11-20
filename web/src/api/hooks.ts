import {
  type QueryKey,
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { del, get, patch, post } from "./client";
import type {
  AuditEntry,
  AuditVerify,
  Canary,
  CanaryCreate,
  CanaryDetail,
  CanaryUpdate,
  CreatedCanary,
  CreatedToken,
  Finding,
  Location,
  Overview,
  Page,
  Scan,
  Secret,
  SecretCreate,
  SecretUpdate,
  Source,
  SourceCreate,
  SourceType,
  SourceUpdate,
  TokenInfo,
  User,
  Role,
  TokenKind,
} from "./types";

type Filter = Record<string, string | number | boolean | undefined>;

function usePaged<T>(key: QueryKey, path: string, filter: Filter, opts: { refetchInterval?: number } = {}) {
  return useInfiniteQuery({
    queryKey: [...key, filter],
    queryFn: ({ pageParam, signal }) =>
      get<Page<T>>(path, { ...filter, limit: 50, cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    refetchInterval: opts.refetchInterval,
  });
}

export const flatten = <T>(pages: Page<T>[] | undefined): T[] => pages?.flatMap((p) => p.items) ?? [];

// ── read ────────────────────────────────────────────────────────────────

export const useOverview = () =>
  useQuery({ queryKey: ["overview"], queryFn: ({ signal }) => get<Overview>("/overview", undefined, signal), refetchInterval: 30_000 });

export const useSecrets = (f: Filter) => usePaged<Secret>(["secrets"], "/secrets", f);
export const useSecret = (id: string) =>
  useQuery({ queryKey: ["secret", id], queryFn: ({ signal }) => get<Secret>(`/secrets/${id}`, undefined, signal) });
export const useSecretLocations = (id: string, f: Filter) =>
  usePaged<Location>(["secret-locations", id], `/secrets/${id}/locations`, f);

export const useFindings = (f: Filter) => usePaged<Finding>(["findings"], "/locations", f);

export const useSources = (f: Filter = {}) => usePaged<Source>(["sources"], "/sources", f, { refetchInterval: 15_000 });
export const useSource = (id: string) =>
  useQuery({
    queryKey: ["source", id],
    queryFn: ({ signal }) => get<Source>(`/sources/${id}`, undefined, signal),
    refetchInterval: (q) => (q.state.data?.active_scan ? 3_000 : 30_000),
  });

export const useScans = (f: Filter) => usePaged<Scan>(["scans"], "/scans", f, { refetchInterval: 10_000 });
export const useScan = (id: string) =>
  useQuery({
    queryKey: ["scan", id],
    queryFn: ({ signal }) => get<Scan>(`/scans/${id}`, undefined, signal),
    refetchInterval: (q) => (q.state.data && ["queued", "running"].includes(q.state.data.status) ? 2_000 : false),
  });

export const useCanaries = () =>
  useQuery({ queryKey: ["canaries"], queryFn: ({ signal }) => get<Canary[]>("/canaries", undefined, signal), refetchInterval: 30_000 });
export const useCanary = (id: string) =>
  useQuery({
    queryKey: ["canary", id],
    queryFn: ({ signal }) => get<CanaryDetail>(`/canaries/${id}`, undefined, signal),
    refetchInterval: 15_000,
  });

export const useTokens = () =>
  useQuery({ queryKey: ["tokens"], queryFn: ({ signal }) => get<TokenInfo[]>("/api-tokens", undefined, signal) });
export const useUsers = () =>
  useQuery({ queryKey: ["users"], queryFn: ({ signal }) => get<User[]>("/users", undefined, signal) });
export const useAudit = (f: Filter) => usePaged<AuditEntry>(["audit"], "/audit", f);

// ── write ───────────────────────────────────────────────────────────────

function useInvalidate() {
  const qc = useQueryClient();
  return (...keys: string[]) => Promise.all(keys.map((k) => qc.invalidateQueries({ queryKey: [k] })));
}

export function useCreateSecret() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: SecretCreate) => post<Secret>("/secrets", body),
    onSuccess: () => inv("secrets", "overview"),
  });
}

export function useUpdateSecret(id: string) {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: SecretUpdate) => patch<Secret>(`/secrets/${id}`, body),
    onSuccess: () => inv("secrets", "secret", "secret-locations", "findings", "overview"),
  });
}

export function useCreateSource() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: SourceCreate) => post<Source>("/sources", body),
    onSuccess: () => inv("sources", "overview"),
  });
}

export function useUpdateSource(id: string) {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: SourceUpdate) => patch<Source>(`/sources/${id}`, body),
    onSuccess: () => inv("sources", "source", "scans", "overview"),
  });
}

export function useDeleteSource() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (id: string) => del<undefined>(`/sources/${id}`),
    onSuccess: () => inv("sources", "scans", "overview"),
  });
}

export function useEnqueueScan() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: ({ id, full }: { id: string; full: boolean }) =>
      post<Scan>(`/sources/${id}/scans`, full ? { full: true } : undefined),
    onSuccess: () => inv("sources", "source", "scans", "overview"),
  });
}

export function useCancelScan() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (id: string) => post<Scan>(`/scans/${id}/cancel`),
    onSuccess: () => inv("scans", "scan", "sources", "source", "overview"),
  });
}

export function useCreateCanary() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: CanaryCreate) => post<CreatedCanary>("/canaries", body),
    // api_key canaries are also registered secrets.
    onSuccess: () => inv("canaries", "secrets", "overview"),
  });
}

export function useUpdateCanary(id: string) {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: CanaryUpdate) => patch<Canary>(`/canaries/${id}`, body),
    onSuccess: () => inv("canaries", "canary"),
  });
}

export function useCreateToken() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: {
      name: string;
      kind: TokenKind;
      scopes: string[];
      expires_in_days: number;
      cert_cn?: string;
      source_type?: SourceType;
      source_uri_pattern?: string;
      environment?: string;
    }) =>
      post<CreatedToken>("/api-tokens", body),
    onSuccess: () => inv("tokens"),
  });
}

export function useRevokeToken() {
  const inv = useInvalidate();
  return useMutation({ mutationFn: (id: string) => del<undefined>(`/api-tokens/${id}`), onSuccess: () => inv("tokens") });
}

export function useCreateUser() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (body: { username: string; role: Role; password: string }) => post<User>("/users", body),
    onSuccess: () => inv("users"),
  });
}

export function useUserAction() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (a:
      | { kind: "update"; id: string; body: { role?: Role; is_active?: boolean } }
      | { kind: "reset-mfa" | "unlock"; id: string }
      | { kind: "password"; id: string; password: string }) => {
      switch (a.kind) {
        case "update":
          return patch<User>(`/users/${a.id}`, a.body);
        case "password":
          return post<User>(`/users/${a.id}/password`, { password: a.password });
        default:
          return post<User>(`/users/${a.id}/${a.kind}`);
      }
    },
    onSuccess: () => inv("users", "audit"),
  });
}

export const verifyAudit = () => get<AuditVerify>("/audit/verify");
export const changePassword = (current_password: string, new_password: string) =>
  post<undefined>("/auth/password", { current_password, new_password });

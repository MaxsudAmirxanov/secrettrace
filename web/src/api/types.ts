/** Wire types of the SecretTrace API (see docs/openapi.json). */
import type { Hints } from "../crypto/hints";
import type { SecretType } from "../crypto/secretTypes";

export type { SecretType };
export type Role = "viewer" | "operator" | "admin";
export type SecretStatus = "active" | "expired" | "revoked" | "rotated";
export type SourceType = "git_repo" | "filesystem" | "docker_image" | "k8s" | "ci_log" | "app_log" | "wiki";
export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";
export type ScanTrigger = "manual" | "schedule" | "ci" | "agent";
export type TokenKind = "agent" | "ci" | "automation";

export interface Page<T> {
  items: T[];
  next_cursor?: string;
}

export interface Me {
  id: string;
  username: string;
  role: Role;
  csrf_token: string;
}

export interface LoginResponse {
  mfa_required: boolean;
  mfa_enrolled: boolean;
  csrf_token: string;
}

export interface EnrollResponse {
  otpauth_uri: string;
  secret: string;
}

export interface AllowRule {
  id?: number;
  source_type?: SourceType | null;
  uri_pattern: string;
  path_pattern?: string | null;
  environment?: string | null;
  comment?: string | null;
}

export interface Secret {
  id: string;
  name: string;
  type: SecretType;
  owner: string;
  purpose: string | null;
  masked: string;
  status: SecretStatus;
  is_expired: boolean;
  expires_at: string | null;
  allow_rules: AllowRule[];
  location_count: number;
  violation_count: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecretCreate {
  name: string;
  type: SecretType;
  owner: string;
  purpose?: string;
  digest: string;
  hints: Hints;
  allow_rules: AllowRule[];
  expires_at?: string;
}

export interface SecretUpdate {
  owner?: string;
  purpose?: string | null;
  status?: SecretStatus;
  expires_at?: string | null;
  allow_rules?: AllowRule[];
}

export interface Locator {
  path?: string;
  line?: number;
  column?: number;
  commit?: string;
  blob?: string;
  ref?: string;
  encoding?: string;
}

export interface Location {
  id: string;
  secret_id: string;
  source_id: string | null;
  source_type: SourceType;
  uri: string;
  locator: Locator;
  environment: string | null;
  in_current_state: boolean;
  is_allowed: boolean;
  first_seen: string;
  last_seen: string;
}

export interface SecretRef {
  id: string;
  name: string;
  type: SecretType;
  status: SecretStatus;
  masked: string;
}

export interface Finding {
  id: string;
  secret: SecretRef;
  source_id: string | null;
  source_name: string | null;
  source_type: SourceType;
  uri: string;
  locator: Locator;
  environment: string | null;
  in_current_state: boolean;
  is_allowed: boolean;
  first_seen: string;
  last_seen: string;
}

export interface SourceConfig {
  username?: string;
  max_blob_bytes?: number;
}

export interface Source {
  id: string;
  name: string;
  type: SourceType;
  uri: string;
  environment: string | null;
  credential_ref: string | null;
  schedule: string | null;
  enabled: boolean;
  config: SourceConfig;
  created_at: string;
  last_scan_at: string | null;
  next_scan_at: string | null;
  active_scan: { id: string; status: JobStatus } | null;
}

export interface SourceCreate {
  name: string;
  type: SourceType;
  uri: string;
  environment?: string;
  credential_ref?: string;
  schedule?: string;
  enabled: boolean;
  config?: SourceConfig;
}

export interface SourceUpdate {
  name?: string;
  environment?: string | null;
  credential_ref?: string | null;
  schedule?: string | null;
  enabled?: boolean;
  config?: SourceConfig;
}

export interface ScanStats {
  documents?: number;
  candidates?: number;
  matched?: number;
  violations?: number;
  [key: string]: unknown;
}

export interface Scan {
  id: string;
  source_id: string | null;
  source_name: string | null;
  trigger: ScanTrigger;
  status: JobStatus;
  full_scan: boolean;
  attempts: number;
  requested_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  run_after: string;
  stats: ScanStats;
  error: string | null;
}

export interface TokenInfo {
  id: string;
  name: string;
  kind: TokenKind;
  token_prefix: string;
  scopes: string[];
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface CreatedToken extends TokenInfo {
  token: string;
}

export interface User {
  id: string;
  username: string;
  role: Role;
  mfa_enabled: boolean;
  is_active: boolean;
  is_locked: boolean;
  locked_until: string | null;
  failed_logins: number;
  created_at: string;
  last_login_at: string | null;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor_type: "user" | "token" | "system";
  actor_id: string;
  actor_name: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
}

export interface AuditVerify {
  ok: boolean;
  rows: number;
  head: string | null;
  broken_at: number | null;
  reason: string | null;
}

export interface Overview {
  secrets: { total: number; active: number; expired: number; revoked: number; rotated: number; expiring_soon: number };
  locations: {
    total: number;
    open_violations: number;
    historical_violations: number;
    allowed: number;
    exposed_secrets: number;
  };
  sources: { total: number; enabled: number; scheduled: number };
  scans_24h: Record<JobStatus, number>;
  violations_by_day: { day: string; count: number }[];
  top_exposed: { secret: SecretRef; violations: number }[];
  expiring: { secret: SecretRef; expires_at: string }[];
  recent_violations: Finding[];
  recent_scans: Scan[];
}

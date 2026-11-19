/**
 * Client-side digest: `SHA-256("secrettrace/v1\0" || utf8(normalize(value)))`, lowercase hex.
 * The plaintext never leaves the browser; only this digest is sent (over TLS). JavaScript
 * strings cannot be wiped from memory, so callers drop every reference to the value as soon
 * as the digest is computed (form fields are cleared after submission).
 */
import { type Hints, deriveHints } from "./hints";
import { normalize } from "./normalize";
import type { SecretType } from "./secretTypes";

const DOMAIN = new Uint8Array([...new TextEncoder().encode("secrettrace/v1"), 0]);

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function digestCanonical(canonical: string): Promise<string> {
  const body = new TextEncoder().encode(canonical);
  const input = new Uint8Array(DOMAIN.length + body.length);
  input.set(DOMAIN, 0);
  input.set(body, DOMAIN.length);
  const out = await crypto.subtle.digest("SHA-256", input);
  input.fill(0);
  body.fill(0);
  return toHex(out);
}

export interface Prepared {
  digest: string;
  hints: Hints;
}

/** Normalize, digest and derive hints. Throws `NormalizeFailure` on invalid input. */
export async function prepare(type: SecretType, raw: string): Promise<Prepared> {
  const canonical = normalize(type, raw);
  return { digest: await digestCanonical(canonical), hints: deriveHints(type, canonical) };
}

/** Port of `st_core::hints::derive_hints` (the server re-validates what is sent). */
import { charCount } from "./normalize";
import { type SecretType, isLowEntropy } from "./secretTypes";

/** Public, fixed vendor prefixes, longest first (same list and order as Rust). */
export const KNOWN_PREFIXES = [
  "github_pat_",
  "sk-ant-api",
  "sk_live_",
  "sk_test_",
  "rk_live_",
  "rk_test_",
  "sk-proj-",
  "xoxb-",
  "xoxp-",
  "xapp-",
  "glpat-",
  "glptt-",
  "pypi-",
  "ghp_",
  "gho_",
  "ghu_",
  "ghs_",
  "ghr_",
  "npm_",
  "AKIA",
  "ASIA",
  "AIza",
  "hvs.",
  "hf_",
  "SG.",
] as const;

export const SUFFIX_MIN_LEN = 24;
export const SUFFIX_LEN = 4;

export interface Hints {
  prefix?: string;
  suffix?: string;
  length?: number;
}

export function knownPrefix(value: string): string | undefined {
  return KNOWN_PREFIXES.find((p) => value.startsWith(p));
}

export function deriveHints(type: SecretType, canonical: string): Hints {
  if (isLowEntropy(type)) return {};
  const prefix = knownPrefix(canonical);
  if (prefix === undefined) return {};
  const chars = [...canonical];
  const len = charCount(canonical);
  const hints: Hints = { prefix, length: len };
  if (len >= SUFFIX_MIN_LEN) hints.suffix = chars.slice(len - SUFFIX_LEN).join("");
  return hints;
}

/** Same rendering as `st_core::mask`. */
export function mask(h: Hints): string {
  if (h.prefix && h.suffix) return `${h.prefix}…${h.suffix}`;
  if (h.prefix) return `${h.prefix}…`;
  return "••••••••";
}

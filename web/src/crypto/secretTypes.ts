/** Mirrors `st_core::SecretType` (snake_case on the wire). */
export const SECRET_TYPES = [
  "api_key",
  "password",
  "token",
  "certificate",
  "private_key",
  "ssh_key",
  "db_connection_string",
  "other",
] as const;

export type SecretType = (typeof SECRET_TYPES)[number];

/** Key material whose textual form (PEM, OpenSSH) varies with formatting. */
export function isKeyMaterial(t: SecretType): boolean {
  return t === "certificate" || t === "private_key" || t === "ssh_key";
}

/** Human-chosen values that may have low entropy: no hints are ever stored. */
export function isLowEntropy(t: SecretType): boolean {
  return t === "password" || t === "db_connection_string";
}

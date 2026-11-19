import { describe, expect, it } from "vitest";

import vectors from "../../../testdata/digest_vectors.json";
import { prepare } from "./digest";
import { deriveHints, mask } from "./hints";
import { MAX_SECRET_LEN, NormalizeFailure, normalize } from "./normalize";
import type { SecretType } from "./secretTypes";

interface Vector {
  type: SecretType;
  raw: string;
  canonical: string;
  digest: string;
  hints: { prefix?: string; suffix?: string; length?: number };
}

const fail = (t: SecretType, v: string) => {
  try {
    normalize(t, v);
  } catch (e) {
    return e instanceof NormalizeFailure ? e.code : "other";
  }
  return "ok";
};

describe("shared test vectors (independent implementation)", () => {
  for (const v of vectors.vectors as Vector[]) {
    it(`${v.type}: ${JSON.stringify(v.raw).slice(0, 40)}`, async () => {
      expect(normalize(v.type, v.raw)).toBe(v.canonical);
      const p = await prepare(v.type, v.raw);
      expect(p.digest).toBe(v.digest);
      expect(p.hints).toEqual(v.hints);
    });
  }
});

describe("normalize (mirrors st-core unit tests)", () => {
  it("trims ASCII whitespace but not vertical tab or NBSP", () => {
    expect(normalize("token", "  abcdef123\n")).toBe("abcdef123");
    expect(normalize("token", "\u000babcdef")).toBe("\u000babcdef");
    expect(normalize("token", " abcdef")).toBe(" abcdef");
  });

  it("rejects bad values", () => {
    expect(fail("password", "   ")).toBe("empty");
    expect(fail("password", "abc")).toBe("too_short");
    expect(fail("password", "abc\0defgh")).toBe("contains_nul");
    expect(fail("token", "abcdef\nghijk")).toBe("multi_line");
    expect(fail("token", "a".repeat(MAX_SECRET_LEN + 1))).toBe("too_long");
  });

  it("counts characters, not bytes, for the minimum and code points for astral chars", () => {
    expect(fail("password", "пароль")).toBe("ok");
    expect(fail("password", "парол")).toBe("too_short");
    expect(fail("password", "🔑🔑🔑🔑🔑")).toBe("too_short");
    expect(fail("password", "🔑🔑🔑🔑🔑🔑")).toBe("ok");
  });

  const PEM =
    "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4w\nggE6AgEAAkEAq7BFUpkGp3+XQorKIXQEz9==\n-----END PRIVATE KEY-----\n";

  it("PEM formatting is irrelevant", () => {
    const expected = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAq7BFUpkGp3+XQorKIXQEz9==";
    const crlf = PEM.replaceAll("\n", "\r\n");
    const escaped = PEM.replaceAll("\n", "\\n");
    const indented = PEM.split("\n")
      .filter((l) => l !== "")
      .map((l) => `    ${l}\n`)
      .join("");
    for (const v of [PEM, crlf, escaped, indented]) expect(normalize("private_key", v)).toBe(expected);
  });

  it("skips encapsulated headers and uses the first block", () => {
    const v =
      "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n\nAAAABBBBCCCC\n-----END RSA PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nZZZZZZZZ\n-----END CERTIFICATE-----";
    expect(normalize("private_key", v)).toBe("AAAABBBBCCCC");
  });

  it("PEM errors", () => {
    expect(fail("certificate", "-----BEGIN CERTIFICATE-----\nAAAABBBB\n")).toBe("malformed_pem");
    expect(fail("certificate", "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----")).toBe(
      "malformed_pem",
    );
    expect(fail("token", PEM)).toBe("multi_line");
  });

  it("OpenSSH public keys reduce to the blob", () => {
    expect(normalize("ssh_key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq user@laptop")).toBe(
      "AAAAC3NzaC1lZDI1NTE5AAAAIGq",
    );
    expect(normalize("ssh_key", "ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIGq   other comment")).toBe(
      "AAAAC3NzaC1lZDI1NTE5AAAAIGq",
    );
  });
});

describe("hints", () => {
  it("follow the leak policy", () => {
    expect(deriveHints("api_key", "AKIAIOSFODNN7EXAMPLE")).toEqual({ prefix: "AKIA", length: 20 });
    expect(deriveHints("token", "ghp_0123456789abcdefghijABCDEFGHIJ0123")).toEqual({
      prefix: "ghp_",
      suffix: "0123",
      length: 38,
    });
    expect(deriveHints("token", "github_pat_11AAAAAAAAAAAAAAAAAAAAAA")).toMatchObject({ prefix: "github_pat_" });
    expect(deriveHints("password", "AKIAlooks-like-aws-but-is-a-password")).toEqual({});
    expect(deriveHints("token", "random-internal-token-123456789")).toEqual({});
  });

  it("mask like st-core", () => {
    expect(mask({ prefix: "ghp_", suffix: "Q2X7", length: 40 })).toBe("ghp_…Q2X7");
    expect(mask({ prefix: "AKIA", length: 20 })).toBe("AKIA…");
    expect(mask({})).toBe("••••••••");
  });
});

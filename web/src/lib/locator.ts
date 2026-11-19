import type { Locator } from "../api/types";

/** `config/app.env:12` — path with line (and column) when known. */
export function locatorPath(l: Locator): string {
  if (!l.path) return "—";
  if (l.line === undefined) return l.path;
  return l.column === undefined ? `${l.path}:${l.line}` : `${l.path}:${l.line}:${l.column}`;
}

export function shortCommit(l: Locator): string | null {
  return l.commit ? l.commit.slice(0, 10) : null;
}

/** Only http(s) repository URLs become links; anything else is shown as text. */
export function safeHttpUrl(uri: string): string | null {
  try {
    const u = new URL(uri);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    if (u.username || u.password) return null;
    return u.toString();
  } catch {
    return null;
  }
}

/** Link to the file at the commit for GitHub/GitLab-style HTTPS remotes. */
export function blobUrl(uri: string, l: Locator): string | null {
  const base = safeHttpUrl(uri);
  if (!base || !l.commit || !l.path || !/^[0-9a-f]{7,64}$/.test(l.commit)) return null;
  const repo = base.replace(/\.git$/, "").replace(/\/+$/, "");
  const host = new URL(repo).hostname;
  const path = l.path.split("/").map(encodeURIComponent).join("/");
  const line = l.line === undefined ? "" : `#L${l.line}`;
  if (host === "github.com") return `${repo}/blob/${l.commit}/${path}${line}`;
  if (host.includes("gitlab")) return `${repo}/-/blob/${l.commit}/${path}${line}`;
  return null;
}

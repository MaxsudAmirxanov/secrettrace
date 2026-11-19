import { describe, expect, it } from "vitest";

import { daysUntil, formatDuration, formatRelative } from "./format";
import { roleAllows } from "./labels";
import { blobUrl, locatorPath, safeHttpUrl } from "./locator";

describe("locator", () => {
  it("formats paths", () => {
    expect(locatorPath({ path: "a/b.env", line: 3 })).toBe("a/b.env:3");
    expect(locatorPath({ path: "a/b.env", line: 3, column: 7 })).toBe("a/b.env:3:7");
    expect(locatorPath({})).toBe("—");
  });

  it("links only to plain http(s) URLs", () => {
    expect(safeHttpUrl("https://github.com/acme/app.git")).toBe("https://github.com/acme/app.git");
    expect(safeHttpUrl("javascript:alert(1)")).toBeNull();
    expect(safeHttpUrl("git@github.com:acme/app.git")).toBeNull();
    expect(safeHttpUrl("https://user:pw@github.com/acme/app.git")).toBeNull();
  });

  it("builds blob links for GitHub and GitLab", () => {
    const l = { path: "conf/a b.env", line: 4, commit: "0123456789abcdef0123456789abcdef01234567" };
    expect(blobUrl("https://github.com/acme/app.git", l)).toBe(
      "https://github.com/acme/app/blob/0123456789abcdef0123456789abcdef01234567/conf/a%20b.env#L4",
    );
    expect(blobUrl("https://gitlab.example.com/g/app.git", l)).toContain("/-/blob/");
    expect(blobUrl("https://git.internal/app.git", l)).toBeNull();
    expect(blobUrl("https://github.com/acme/app.git", { ...l, commit: "zz" })).toBeNull();
  });
});

describe("format", () => {
  it("relative times", () => {
    const now = Date.parse("2026-11-20T12:00:00Z");
    expect(formatRelative("2026-11-20T11:59:50Z", now)).toBe("только что");
    expect(formatRelative("2026-11-20T10:00:00Z", now)).toBe("2 часа назад");
    expect(formatRelative("2026-11-23T12:00:00Z", now)).toBe("через 3 дня");
  });

  it("durations and days", () => {
    expect(formatDuration("2026-11-20T12:00:00Z", "2026-11-20T12:01:05Z")).toBe("1 мин 5 с");
    expect(daysUntil("2026-11-25T12:00:00Z", Date.parse("2026-11-20T12:00:00Z"))).toBe(5);
  });

  it("role hierarchy", () => {
    expect(roleAllows("admin", "operator")).toBe(true);
    expect(roleAllows("viewer", "operator")).toBe(false);
  });
});

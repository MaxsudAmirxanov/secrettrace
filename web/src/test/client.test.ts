import { describe, expect, it, vi } from "vitest";

import { ApiError, api, buildPath, setCsrfToken, setUnauthorizedHandler } from "../api/client";
import { safeNext } from "../auth/guards";
import { mockApi } from "./utils";

describe("api client", () => {
  it("sends CSRF only on state-changing requests and same-origin credentials", async () => {
    const calls = mockApi({ "GET /x": { body: {} }, "POST /x": { body: {} } });
    setCsrfToken("t1");
    await api("GET", "/x");
    await api("POST", "/x", { body: { a: 1 } });
    expect(calls[0]?.headers["X-CSRF-Token"]).toBeUndefined();
    expect(calls[1]?.headers["X-CSRF-Token"]).toBe("t1");
    expect(calls[1]?.headers["Content-Type"]).toBe("application/json");
    const init = vi.mocked(fetch).mock.calls[1]?.[1];
    expect(init?.credentials).toBe("same-origin");
    expect(init?.redirect).toBe("error");
    setCsrfToken(null);
  });

  it("maps problem+json and signals 401 outside /auth", async () => {
    mockApi({ "GET /secrets": { status: 401 }, "GET /auth/me": { status: 401 }, "POST /y": { status: 422, body: { detail: "bad name" } } });
    const onUnauth = vi.fn();
    setUnauthorizedHandler(onUnauth);
    await expect(api("GET", "/auth/me")).rejects.toBeInstanceOf(ApiError);
    expect(onUnauth).not.toHaveBeenCalled();
    await expect(api("GET", "/secrets")).rejects.toMatchObject({ status: 401 });
    expect(onUnauth).toHaveBeenCalledOnce();
    await expect(api("POST", "/y")).rejects.toMatchObject({ status: 422, detail: "bad name" });
    setUnauthorizedHandler(null);
  });

  it("builds query strings without empty values", () => {
    expect(buildPath("/a", { q: "x y", empty: "", none: undefined, n: 0, b: false })).toBe("/a?q=x+y&n=0&b=false");
  });
});

describe("post-login redirect", () => {
  it("accepts only same-origin paths", () => {
    expect(safeNext("/secrets?x=1")).toBe("/secrets?x=1");
    for (const bad of [null, "", "https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)"]) {
      expect(safeNext(bad)).toBe("/");
    }
  });
});

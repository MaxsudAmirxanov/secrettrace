import { describe, expect, it } from "vitest";

import { canaryBody, canaryError, canaryState } from "../lib/canary";

describe("canary helpers", () => {
  it("shows a fired canary as red even when disabled", () => {
    expect(canaryState({ enabled: true, hit_count: 0 })).toEqual({ label: "Ждёт", tone: "green" });
    expect(canaryState({ enabled: false, hit_count: 0 }).tone).toBe("gray");
    expect(canaryState({ enabled: true, hit_count: 3 }).tone).toBe("red");
    expect(canaryState({ enabled: false, hit_count: 1 })).toEqual({ label: "Сработала, выключена", tone: "red" });
  });

  it("builds the request body from the form", () => {
    expect(canaryBody({ name: " wiki ", kind: "url", plantedAt: "", memo: " " })).toEqual({ name: "wiki", kind: "url" });
    expect(canaryBody({ name: "env", kind: "api_key", plantedAt: " laptop ", memo: "m" })).toEqual({
      name: "env",
      kind: "api_key",
      planted_at: "laptop",
      memo: "m",
    });
  });

  it("validates lengths like the server", () => {
    expect(canaryError({ name: "a", plantedAt: "", memo: "" })).toBeNull();
    expect(canaryError({ name: "  ", plantedAt: "", memo: "" })).toMatch(/имя/);
    expect(canaryError({ name: "x".repeat(191), plantedAt: "", memo: "" })).toMatch(/190/);
    expect(canaryError({ name: "a", plantedAt: "x".repeat(501), memo: "" })).toMatch(/500/);
  });
});

import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Can, RequireRole } from "../auth/guards";
import { generatePassword, passwordProblem } from "../lib/password";
import { statRows } from "../lib/stats";
import { mockApi, renderApp } from "./utils";

describe("role guards", () => {
  it("hide admin-only content from operators", async () => {
    mockApi({ "GET /auth/me": { body: { id: "u", username: "op", role: "operator", csrf_token: "c" } } });
    renderApp(
      <>
        <Can role="operator">
          <span>op-visible</span>
        </Can>
        <RequireRole role="admin">
          <span>admin-only</span>
        </RequireRole>
      </>,
    );
    expect(await screen.findByText("op-visible")).toBeInTheDocument();
    expect(screen.queryByText("admin-only")).not.toBeInTheDocument();
    expect(screen.getByText("Недостаточно прав")).toBeInTheDocument();
  });
});

describe("helpers", () => {
  it("generated passwords satisfy the policy", () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword();
      expect(p).toHaveLength(20);
      expect(passwordProblem("alice", p)).toBeNull();
    }
    expect(passwordProblem("alice", "alice-is-my-password")).toMatch(/имя пользователя/);
    expect(passwordProblem("bob", "aaaaaaaaaaaaaaa")).toMatch(/повторяющегося/);
    expect(passwordProblem("bob", "short")).toMatch(/12/);
  });

  it("scan stats are labelled and ordered", () => {
    const rows = statRows({ violations: 2, documents: 10, bytes: 2048, custom: 1, note: "text", incremental: 1 });
    expect(rows.map((r) => r.key)).toEqual(["documents", "bytes", "violations", "incremental", "custom"]);
    expect(rows.find((r) => r.key === "bytes")?.value).toBe("2.0 КиБ");
    expect(rows.find((r) => r.key === "violations")?.emphasis).toBe("danger");
  });
});

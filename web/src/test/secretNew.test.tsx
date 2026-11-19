import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import vectors from "../../../testdata/digest_vectors.json";
import { SecretNewPage } from "../pages/SecretNew";
import { ME, mockApi, renderApp } from "./utils";

const VALUE = "ghp_0123456789abcdefghijABCDEFGHIJ0123";
const DIGEST = vectors.vectors.find((v) => v.raw === VALUE)?.digest;

describe("secret registration", () => {
  it("sends only the digest and hints, never the value", async () => {
    const calls = mockApi({
      "GET /auth/me": { body: ME },
      "POST /secrets": (c) => ({ status: 201, body: { id: "s1", name: (c.body as { name: string }).name } }),
    });
    renderApp(<SecretNewPage />);
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText(/^Имя/), "gh-deploy");
    await user.type(screen.getByLabelText(/^Владелец/), "platform");
    const value = screen.getByLabelText(/^Значение секрета/);
    expect(value).toHaveAttribute("type", "password");
    expect(value).toHaveAttribute("autocomplete", "new-password");
    await user.type(value, VALUE);
    expect(await screen.findByText("ghp_…0123")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Зарегистрировать" }));

    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.method === "POST");
    expect(post?.body).toEqual({
      name: "gh-deploy",
      type: "token",
      owner: "platform",
      digest: DIGEST,
      hints: { prefix: "ghp_", suffix: "0123", length: 38 },
      allow_rules: [],
    });
    expect(post?.headers["X-CSRF-Token"]).toBe("csrf-1");
    for (const c of calls) expect(JSON.stringify(c)).not.toContain("0123456789abcdefghij");
  });

  it("validates locally and does not submit invalid values", async () => {
    const calls = mockApi({ "GET /auth/me": { body: ME } });
    renderApp(<SecretNewPage />);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/^Имя/), "x");
    await user.type(screen.getByLabelText(/^Владелец/), "y");
    await user.type(screen.getByLabelText(/^Значение секрета/), "abc");
    await user.click(screen.getByRole("button", { name: "Зарегистрировать" }));
    expect(await screen.findByText(/короче 6 символов/)).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("clears the value after a conflict", async () => {
    mockApi({ "GET /auth/me": { body: ME }, "POST /secrets": { status: 409, body: { title: "Conflict", detail: "exists" } } });
    renderApp(<SecretNewPage />);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/^Имя/), "dup");
    await user.type(screen.getByLabelText(/^Владелец/), "team");
    const value = screen.getByLabelText(/^Значение секрета/);
    await user.type(value, VALUE);
    await user.click(screen.getByRole("button", { name: "Зарегистрировать" }));
    expect(await screen.findByText(/Уже зарегистрирован/)).toBeInTheDocument();
    expect(value).toHaveValue("");
  });
});

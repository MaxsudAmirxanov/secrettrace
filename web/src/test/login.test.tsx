import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { LoginPage } from "../pages/Login";
import { ME, mockApi, renderApp } from "./utils";

describe("login", () => {
  it("password, then TOTP enrollment with a locally drawn QR, then verify", async () => {
    const calls = mockApi({
      "GET /auth/me": { status: 401 },
      "POST /auth/login": { body: { mfa_required: true, mfa_enrolled: false, csrf_token: "pre" } },
      "POST /auth/mfa/enroll": {
        body: { otpauth_uri: "otpauth://totp/SecretTrace:alice?secret=JBSWY3DPEHPK3PXP&issuer=SecretTrace", secret: "JBSWY3DPEHPK3PXP" },
      },
      "POST /auth/mfa/verify": { body: ME },
    });
    renderApp(<LoginPage />, { route: "/login?next=/secrets", path: "/login" });
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Имя пользователя"), "alice");
    await user.type(screen.getByLabelText("Пароль"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Продолжить" }));

    expect(await screen.findByRole("img", { name: /QR-код/ })).toBeInTheDocument();
    expect(screen.getByText("JBSW Y3DP EHPK 3PXP")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Код из приложения"), "123456");
    await user.click(screen.getByRole("button", { name: "Подтвердить" }));

    expect(await screen.findByText("other page")).toBeInTheDocument();
    const enroll = calls.filter((c) => c.url.endsWith("/auth/mfa/enroll"));
    expect(enroll).toHaveLength(1);
    const verify = calls.find((c) => c.url.endsWith("/auth/mfa/verify"));
    expect(verify?.headers["X-CSRF-Token"]).toBe("pre");
    expect(verify?.body).toEqual({ code: "123456" });
    // Nothing reaches a third party: every request is same-origin /api.
    expect(calls.every((c) => c.url.startsWith("/api/v1/"))).toBe(true);
  });

  it("generic error on wrong password and the field is cleared", async () => {
    mockApi({ "GET /auth/me": { status: 401 }, "POST /auth/login": { status: 401 } });
    renderApp(<LoginPage />, { route: "/login", path: "/login" });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Имя пользователя"), "alice");
    const pw = screen.getByLabelText("Пароль");
    await user.type(pw, "nope-nope-nope");
    await user.click(screen.getByRole("button", { name: "Продолжить" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Неверное имя пользователя или пароль/);
    expect(pw).toHaveValue("");
  });

  it("enrolled users go straight to the code; only 6 digits are accepted", async () => {
    mockApi({
      "GET /auth/me": { status: 401 },
      "POST /auth/login": { body: { mfa_required: true, mfa_enrolled: true, csrf_token: "pre" } },
      "POST /auth/mfa/verify": { status: 401 },
    });
    renderApp(<LoginPage />, { route: "/login", path: "/login" });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Имя пользователя"), "alice");
    await user.type(screen.getByLabelText("Пароль"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Продолжить" }));
    const code = await screen.findByLabelText("Код из приложения-аутентификатора");
    await user.type(code, "12ab34567");
    expect(code).toHaveValue("123456");
    await user.click(screen.getByRole("button", { name: "Подтвердить" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/Неверный код/));
    expect(code).toHaveValue("");
  });
});

import { describe, expect, it } from "vitest";

import { bindingError, bindingFields } from "../pages/Tokens";

describe("token bindings", () => {
  it("sends only filled-in fields, trimmed", () => {
    expect(bindingFields({ certCn: " ci-infra ", sourceType: "", uriPattern: "", environment: "" })).toEqual({ cert_cn: "ci-infra" });
    expect(bindingFields({ certCn: "", sourceType: "git_repo", uriPattern: " https://git.example.com/acme/** ", environment: "ci" })).toEqual({
      source_type: "git_repo",
      source_uri_pattern: "https://git.example.com/acme/**",
      environment: "ci",
    });
  });

  it("checks CN and environment like the server", () => {
    expect(bindingError({ certCn: "", environment: "" })).toBeNull();
    expect(bindingError({ certCn: "agent-01.prod", environment: "ci" })).toBeNull();
    expect(bindingError({ certCn: "bad cn", environment: "" })).toMatch(/CN/);
    expect(bindingError({ certCn: "", environment: "x".repeat(65) })).toMatch(/Окружение/);
  });
});

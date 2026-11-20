# Security policy

SecretTrace is alpha software maintained by one person. There is no bug bounty, but every report is read and
answered.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
[Report a vulnerability](https://github.com/MaxsudAmirxanov/secrettrace/security/advisories/new).

Include the affected component (server, worker, CLI, web UI, edge config, PKI script), the steps to
reproduce, and the impact as you see it. Never include real secrets in a report.

What to expect:
- an acknowledgement within 3 days;
- an assessment and a plan within 14 days;
- a fix and a published advisory, with credit to you if you want it.

## Supported versions

There are no releases yet. Only the latest `main` is supported.

## Scope

Of particular interest:
- anything that reveals secret values, digests or fingerprints, or lets someone test guesses faster than the
  documented ingest budget;
- authentication, TOTP, session or CSRF bypasses, and role escalation;
- forging the client-certificate CN, or bypassing the token bindings;
- SSRF, credential leaks or command injection in the git worker;
- canary tokens that can be told apart from ordinary 404 responses;
- audit log tampering that is not detected by `verify-audit`.

The threat model in [`docs/threat-model.md`](docs/threat-model.md) lists the attacks already considered and
their known limitations.

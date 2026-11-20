"""E2E helper for deploy/e2e/run.sh: HTTPS calls to the edge, TOTP sign-in, assertions.

Standard library only; run as `python3 -I api.py <command> …`. Session state (cookie,
CSRF token) lives in $E2E_STATE (a file in the run's private temp directory).

Commands (each prints one JSON document on success, exits 1 with a message on failure):
  login USER PASSWORD             sign in with TOTP enrollment; checks security headers
  token NAME [JSON]               POST /api-tokens with extra fields; prints status + body
  secret NAME DIGEST              POST /secrets; prints the created secret
  allow SECRET_ID URI_PATTERN     PATCH /secrets/{id} allow_rules
  locations SECRET_ID             GET /secrets/{id}/locations (items)
  worker-scan NAME URI            create a git_repo source, enqueue a scan, wait for it
  audit                           GET /audit/verify and the list of audit actions
"""

import base64
import hashlib
import hmac
import json
import os
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["E2E_BASE"].rstrip("/")  # https://localhost:<port>
CTX = ssl.create_default_context(cafile=os.environ["E2E_CA"])
STATE = os.environ["E2E_STATE"]


def fail(msg):
    print(f"api.py: {msg}", file=sys.stderr)
    sys.exit(1)


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save(state):
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)


def call(method, path, body=None, expect=None):
    state = load()
    req = urllib.request.Request(BASE + "/api/v1" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("accept", "application/json")
    if body is not None:
        req.add_header("content-type", "application/json")
    if state.get("cookie"):
        req.add_header("cookie", state["cookie"])
    if state.get("csrf") and method not in ("GET", "HEAD"):
        req.add_header("x-csrf-token", state["csrf"])
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            status, headers, text = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, headers, text = e.code, e.headers, e.read()
    cookie = headers.get("set-cookie")
    data = json.loads(text) if text else None
    if cookie:
        state["cookie"] = cookie.split(";")[0]
    if isinstance(data, dict) and data.get("csrf_token"):
        state["csrf"] = data["csrf_token"]
    save(state)
    if expect is not None and status != expect:
        fail(f"{method} {path}: expected {expect}, got {status}: {data}")
    return status, headers, data


def totp(seed, step=None):
    step = int(time.time() // 30) if step is None else step
    mac = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def cmd_login(user, password):
    save({})
    _, headers, body = call("POST", "/auth/login", {"username": user, "password": password}, expect=200)
    # Edge and server headers on an API response.
    hsts = headers.get("strict-transport-security", "")
    if "max-age=" not in hsts:
        fail(f"no HSTS header: {dict(headers)}")
    for name, want in [("content-security-policy", "default-src 'none'"), ("x-content-type-options", "nosniff")]:
        if want not in (headers.get(name) or ""):
            fail(f"missing {name}: {dict(headers)}")
    cookie = load()["cookie"]
    if not cookie.startswith("__Host-"):
        fail(f"session cookie is not __Host- prefixed: {cookie.split('=')[0]}")
    if body["mfa_enrolled"]:
        fail("fresh admin already has MFA")
    _, _, enroll = call("POST", "/auth/mfa/enroll", expect=200)
    seed = base64.b32decode(enroll["secret"] + "=" * (-len(enroll["secret"]) % 8))
    call("POST", "/auth/mfa/verify", {"code": totp(seed)}, expect=200)
    _, _, me = call("GET", "/auth/me", expect=200)
    print(json.dumps({"user": me["username"], "role": me["role"], "hsts": hsts}))


def cmd_token(name, extra="{}"):
    body = {"name": name, "kind": "ci", "scopes": ["ingest:profile", "ingest:match", "ingest:findings"],
            "expires_in_days": 7, **json.loads(extra)}
    status, _, data = call("POST", "/api-tokens", body)
    print(json.dumps({"status": status, "body": data}))


def cmd_secret(name, digest):
    body = {"name": name, "type": "token", "owner": "e2e", "digest": digest, "hints": {}, "allow_rules": []}
    _, _, data = call("POST", "/secrets", body, expect=201)
    print(json.dumps(data))


def cmd_allow(secret_id, uri_pattern):
    _, _, data = call("PATCH", f"/secrets/{secret_id}",
                      {"allow_rules": [{"source_type": "git_repo", "uri_pattern": uri_pattern}]}, expect=200)
    print(json.dumps(data))


def cmd_locations(secret_id):
    _, _, data = call("GET", f"/secrets/{secret_id}/locations?limit=100", expect=200)
    print(json.dumps(data["items"] if isinstance(data, dict) else data))


def cmd_worker_scan(name, uri):
    _, _, src = call("POST", "/sources", {"name": name, "type": "git_repo", "uri": uri, "environment": "worker"},
                     expect=201)
    _, _, job = call("POST", f"/sources/{src['id']}/scans", {}, expect=None)
    if not isinstance(job, dict) or "id" not in job:
        fail(f"enqueue failed: {job}")
    deadline = time.time() + 180
    while time.time() < deadline:
        _, _, scan = call("GET", f"/scans/{job['id']}", expect=200)
        if scan["status"] in ("succeeded", "failed", "cancelled"):
            print(json.dumps(scan))
            return
        time.sleep(2)
    fail(f"worker scan did not finish in time: {scan}")


def cmd_audit():
    _, _, verify = call("GET", "/audit/verify", expect=200)
    actions, cursor = [], None
    for _ in range(50):
        _, _, page = call("GET", "/audit?limit=200" + (f"&cursor={cursor}" if cursor else ""), expect=200)
        actions += [e["action"] for e in page["items"]]
        cursor = page.get("next_cursor")
        if not cursor:
            break
    print(json.dumps({"verify": verify, "actions": sorted(set(actions))}))


COMMANDS = {"login": cmd_login, "token": cmd_token, "secret": cmd_secret, "allow": cmd_allow,
            "locations": cmd_locations, "worker-scan": cmd_worker_scan, "audit": cmd_audit}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail(__doc__)
    COMMANDS[sys.argv[1]](*sys.argv[2:])

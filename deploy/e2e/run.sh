#!/usr/bin/env bash
# End-to-end test of the real compose stack: images built from this checkout, Postgres,
# migrations, server, worker, TLS edge with mTLS, and the CLI image — driven only from the
# outside (HTTPS, client certificates, `docker compose run`).
#
# Runs as an isolated compose project next to any dev stack: its own project name, host
# ports, edge subnet, secrets, PKI and image tag, all in a private temp directory that is
# removed afterwards together with the project's containers, volumes and images.
#
#   deploy/e2e/run.sh          or   make e2e
#   KEEP=1 deploy/e2e/run.sh   leave the stack and temp directory for inspection
#
# Overrides: E2E_PROJECT (secrettrace-e2e), E2E_HTTPS_PORT (28443), E2E_MTLS_PORT (28444),
# E2E_SUBNET (10.214.0.0/24), E2E_PROXY_IP (10.214.0.10), E2E_TAG (e2e), KEEP_IMAGES=1.
# Needs: docker with compose v2, git, openssl, curl, jq, python3, make.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT="${E2E_PROJECT:-secrettrace-e2e}"
HTTPS_PORT="${E2E_HTTPS_PORT:-28443}"
MTLS_PORT="${E2E_MTLS_PORT:-28444}"
CANARY_PORT="${E2E_CANARY_PORT:-28445}"
TAG="${E2E_TAG:-e2e}"
CLI_IMAGE="secrettrace-cli:$TAG"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/secrettrace-e2e.XXXXXX")"
chmod 700 "$WORK"
STARTED=$(date +%s)

export ST_IMAGE_TAG="$TAG" ST_EDGE_HTTPS_PORT="$HTTPS_PORT" ST_EDGE_MTLS_PORT="$MTLS_PORT"
export ST_CANARY_PORT="$CANARY_PORT" ST_CANARY_BASE_URL="http://localhost:$CANARY_PORT"
export ST_EDGE_SUBNET="${E2E_SUBNET:-10.214.0.0/24}" ST_EDGE_PROXY_IP="${E2E_PROXY_IP:-10.214.0.10}"
export ST_SECRETS_DIR="$WORK/secrets" ST_PKI_DIR="$WORK/pki" ST_WORKER_DIR="$WORK/worker"
export ST_WORKER_ALLOW_LOCAL_REPOS=true ST_WORKER_ALLOWED_HOSTS=git.example.com E2E_REPOS="$WORK/repos"
export E2E_BASE="https://localhost:$HTTPS_PORT" E2E_CA="$WORK/pki/ca/ca.crt" E2E_STATE="$WORK/session.json"

compose() { docker compose -f "$ROOT/docker-compose.yml" -f "$ROOT/deploy/e2e/compose.e2e.yml" -p "$PROJECT" "$@"; }
api() { python3 -I "$ROOT/deploy/e2e/api.py" "$@"; }
step() { printf '\n== %s\n' "$*"; }
pass() { printf '   ok: %s\n' "$*"; }
fail() { printf '\nE2E FAIL: %s\n' "$*" >&2; exit 1; }

teardown() {
  local status=$?
  if [[ "${KEEP:-0}" == 1 ]]; then
    echo "KEEP=1: stack '$PROJECT' and $WORK left running"
    return
  fi
  if [[ $status -ne 0 ]]; then
    echo "--- last server / worker / edge logs" >&2
    compose logs --no-color --tail 60 server worker edge >&2 2>/dev/null || true
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  # The worker's repository copy belongs to uid 65532: remove it as root in a container.
  if [[ -d "$WORK/repos" ]] && docker image inspect "$CLI_IMAGE" >/dev/null 2>&1; then
    docker run --rm --user 0 --entrypoint rm -v "$WORK:/w" "$CLI_IMAGE" -rf /w/repos >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK" 2>/dev/null || echo "warning: could not remove $WORK" >&2
  if [[ "${KEEP_IMAGES:-0}" != 1 ]]; then
    docker image rm "secrettrace-server:$TAG" "secrettrace-worker:$TAG" "$CLI_IMAGE" >/dev/null 2>&1 || true
  fi
  echo "E2E $( [[ $status -eq 0 ]] && echo PASSED || echo FAILED ) in $(( $(date +%s) - STARTED ))s"
}
trap teardown EXIT

# `expect_status CODE curl-args…`: run curl, check the HTTP status, keep the body in $BODY.
expect_status() {
  local want="$1"; shift
  local got
  got="$(curl -sS -o "$WORK/body" -w '%{http_code}' --cacert "$E2E_CA" "$@")" || got="curl-error"
  BODY="$(cat "$WORK/body" 2>/dev/null || true)"
  [[ "$got" == "$want" ]] || fail "expected HTTP $want, got $got: $BODY"
}

# `scan_with CN EXPECTED_EXIT [cli args…]`: the CLI image scans the test repository
# through the mTLS port with the client certificate of CN ("" for none), recording it as
# $SCAN_URI (default https://git.example.com/e2e/app.git).
scan_with() {
  local cn="$1" want="$2"; shift 2
  local tls=()
  if [[ -n "$cn" ]]; then
    tls=(-v "$WORK/pki/clients/$cn:/tls/client:ro"
         -e SECRETTRACE_CLIENT_CERT=/tls/client/client.crt -e SECRETTRACE_CLIENT_KEY=/tls/client/client.key)
  fi
  local code=0
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -v "$WORK/src/app:/repo:ro" -v "$E2E_CA:/tls/ca.crt:ro" "${tls[@]}" \
    -e SECRETTRACE_TOKEN -e SECRETTRACE_CA_CERT=/tls/ca.crt \
    "$CLI_IMAGE" scan git /repo --server "https://localhost:$MTLS_PORT" \
      --source-uri "${SCAN_URI:-https://git.example.com/e2e/app.git}" "$@" >"$WORK/scan.out" 2>"$WORK/scan.err" || code=$?
  SCAN_OUT="$(cat "$WORK/scan.out")"; SCAN_ERR="$(cat "$WORK/scan.err")"
  [[ "$code" == "$want" ]] || fail "scan (cert '${cn:-none}'): expected exit $want, got $code: $SCAN_ERR"
}

step "secrets, PKI and test repository in $WORK"
make -s -C "$ROOT" secrets SECRETS_DIR="$WORK/secrets" WORKER_DIR="$WORK/worker" >/dev/null
export PKI_OUT="$WORK/pki"
"$ROOT/deploy/pki/pki.sh" init >/dev/null
"$ROOT/deploy/pki/pki.sh" server >/dev/null
for cn in e2e-ci e2e-other e2e-revoked; do "$ROOT/deploy/pki/pki.sh" client "$cn" 7 >/dev/null; done
SECRET="ghp_$(openssl rand -hex 18)"
git_c() { git -C "$WORK/src/app" -c user.name=e2e -c user.email=e2e@example.invalid -c commit.gpgsign=false "$@"; }
mkdir -p "$WORK/src/app/config" "$WORK/repos"
git_c init -q -b main
printf 'TOKEN=%s\n' "$SECRET" > "$WORK/src/app/leak.env"
git_c add -A && git_c commit -q -m "leak"
git_c rm -q leak.env
printf 'github_token = "%s"\n' "$SECRET" > "$WORK/src/app/config/app.env"
git_c add -A && git_c commit -q -m "move it"
git clone -q --bare "$WORK/src/app" "$WORK/repos/app.git"
pass "secret in HEAD (config/app.env) and only in history (leak.env)"

step "build images (tag $TAG)"
compose build --quiet
docker build --quiet --target cli -t "$CLI_IMAGE" "$ROOT" >/dev/null
pass "server, worker and cli images; disk free: $(df -h "$ROOT" | awk 'NR==2{print $4}')"

step "start the stack (project $PROJECT, ports $HTTPS_PORT/$MTLS_PORT)"
compose up -d --quiet-pull >/dev/null 2>&1 || { compose up -d; fail "compose up failed"; }
for _ in $(seq 1 90); do
  curl -sf --cacert "$E2E_CA" "$E2E_BASE/readyz" >/dev/null 2>&1 && break
  sleep 2
done
expect_status 200 "$E2E_BASE/readyz"
pass "ready through the TLS edge: $BODY"
published="$(compose port server 8080 2>/dev/null || true)"
[[ ! "$published" =~ :[1-9][0-9]*$ ]] || fail "the server port is published: $published"
pass "server port 8080 is not published"
expect_status 200 --cert "$WORK/pki/clients/e2e-ci/client.crt" --key "$WORK/pki/clients/e2e-ci/client.key" \
  "https://localhost:$MTLS_PORT/healthz"
pass "mTLS port answers /healthz with a client certificate"

step "admin sign-in over HTTPS with TOTP enrollment"
ADMIN_PW="$(openssl rand -hex 16)"
printf '%s\n' "$ADMIN_PW" | compose run --rm --no-deps -T server create-user --username admin --role admin \
  --password-stdin >/dev/null 2>&1 || fail "create-user failed"
api login admin "$ADMIN_PW" >/dev/null
pass "password + TOTP, __Host- cookie, HSTS, CSP and nosniff present"

step "API tokens (client certificates are required)"
status="$(api token unbound | jq -r .status)"
[[ "$status" == 422 ]] || fail "an unbound token was issued (HTTP $status)"
pass "token without cert_cn refused with 422"
reply="$(api token ci '{"cert_cn":"e2e-ci","environment":"ci","source_type":"git_repo","source_uri_pattern":"https://git.example.com/e2e/**"}')"
[[ "$(jq -r .status <<<"$reply")" == 201 ]] || fail "bound token not issued: $reply"
SECRETTRACE_TOKEN="$(jq -r .body.token <<<"$reply")"
export SECRETTRACE_TOKEN
pass "token bound to CN e2e-ci, environment ci, git_repo https://git.example.com/e2e/**"

step "register the secret by digest (computed by the CLI image)"
DIGEST="$(printf '%s' "$SECRET" | docker run --rm -i "$CLI_IMAGE" digest --type token --stdin | jq -r .digest)"
[[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]] || fail "bad digest: $DIGEST"
SECRET_ID="$(api secret e2e-github-token "$DIGEST" | jq -r .id)"
pass "secret $SECRET_ID"

step "CI scan through mTLS: violations → exit 1"
scan_with e2e-ci 1
grep -q '1 registered secret(s) in 2 location(s): 2 violation(s)' <<<"$SCAN_ERR" || fail "unexpected summary: $SCAN_ERR"
[[ "$(wc -l <<<"$SCAN_OUT")" -eq 2 ]] || fail "expected 2 printed rows: $SCAN_OUT"
grep -q "$SECRET" <<<"$SCAN_OUT$SCAN_ERR" && fail "the secret value appeared in CLI output"
grep -q '"digest"' <<<"$SCAN_OUT" && fail "digests printed without --show-digests"
locs="$(api locations "$SECRET_ID")"
summary="$(jq -c '[.[] | {path: .locator.path, current: .in_current_state, allowed: .is_allowed, env: .environment, uri}] | sort_by(.path)' <<<"$locs")"
want='[{"path":"config/app.env","current":true,"allowed":false,"env":"ci","uri":"https://git.example.com/e2e/app.git"},{"path":"leak.env","current":false,"allowed":false,"env":"ci","uri":"https://git.example.com/e2e/app.git"}]'
[[ "$summary" == "$want" ]] || fail "locations: $summary"
pass "2 locations recorded (HEAD + history), environment from the token binding"

step "allow rule for the repository → exit 0"
api allow "$SECRET_ID" 'https://git.example.com/e2e/**' >/dev/null
[[ "$(api locations "$SECRET_ID" | jq '[.[] | select(.is_allowed)] | length')" == 2 ]] || fail "allow rule not re-evaluated"
pass "existing locations re-evaluated as allowed"
scan_with e2e-ci 0
pass "rescan exits 0"
scan_with e2e-ci 1 --fail-on found
pass "--fail-on found still exits 1"

step "negative paths"
start_body='{"source":{"type":"git_repo","uri":"https://git.example.com/e2e/app.git"}}'
expect_status 403 -H "Authorization: Bearer $SECRETTRACE_TOKEN" -H "X-SecretTrace-Client-CN: e2e-ci" \
  -H 'content-type: application/json' -d "$start_body" "$E2E_BASE/api/v1/ingest/scans"
grep -q 'mTLS port' <<<"$BODY" || fail "unexpected body: $BODY"
pass "ingest on the TLS port: 403, a spoofed client-CN header changes nothing"
expect_status 403 -H "Authorization: Bearer $SECRETTRACE_TOKEN" -H 'content-type: application/json' \
  -d "$start_body" "https://localhost:$MTLS_PORT/api/v1/ingest/scans"
jq -e '.detail | test("client certificate is required")' <<<"$BODY" >/dev/null || fail "unexpected body: $BODY"
pass "mTLS port without a certificate: 403 problem+json"
scan_with e2e-other 2
grep -q 'returned 401' <<<"$SCAN_ERR" || fail "unexpected error: $SCAN_ERR"
pass "valid certificate with another CN: 401 (exit 2)"
SCAN_URI=https://git.example.com/other/app.git scan_with e2e-ci 2
grep -q 'may only report sources matching' <<<"$SCAN_ERR" || fail "unexpected error: $SCAN_ERR"
pass "source outside the token binding: 403 with an explanation (exit 2)"
scan_with e2e-ci 2 --environment prod
grep -q 'may only report environment' <<<"$SCAN_ERR" || fail "unexpected error: $SCAN_ERR"
pass "environment outside the binding: 403 (exit 2)"
scan_with e2e-revoked 2
grep -q 'returned 401' <<<"$SCAN_ERR" || fail "before revocation the edge should pass it on: $SCAN_ERR"
"$ROOT/deploy/pki/pki.sh" revoke e2e-revoked >/dev/null
compose exec -T edge nginx -s reload >/dev/null 2>&1
sleep 2
revoked_dir="$(ls -d "$WORK"/pki/clients/e2e-revoked.revoked-*)"
expect_status 403 --cert "$revoked_dir/client.crt" --key "$revoked_dir/client.key" \
  -H "Authorization: Bearer $SECRETTRACE_TOKEN" -H 'content-type: application/json' -d "$start_body" \
  "https://localhost:$MTLS_PORT/api/v1/ingest/scans"
jq -e '.detail | test("rejected")' <<<"$BODY" >/dev/null || fail "unexpected body: $BODY"
pass "revoked certificate after CRL refresh + reload: 403"

step "server-side scan by the worker (file:// source)"
docker run --rm --user 0 --entrypoint chown -v "$WORK/repos:/r" "$CLI_IMAGE" -R 65532:65532 /r
scan="$(api worker-scan worker-app file:///srv/e2e-repos/app.git)"
[[ "$(jq -r .status <<<"$scan")" == succeeded ]] || fail "worker scan: $scan"
worker_locs="$(api locations "$SECRET_ID" | jq -c '[.[] | select(.uri == "file:///srv/e2e-repos/app.git") | {path: .locator.path, current: .in_current_state, env: .environment}] | sort_by(.path)')"
[[ "$worker_locs" == '[{"path":"config/app.env","current":true,"env":"worker"},{"path":"leak.env","current":false,"env":"worker"}]' ]] \
  || fail "worker locations: $worker_locs"
pass "worker cloned, scanned and recorded both locations"

step "canary tokens through the canary listener"
url_c="$(api canary e2e-link url)"
url="$(jq -r .value <<<"$url_c")"; url_id="$(jq -r .canary.id <<<"$url_c")"
[[ "$url" == "http://localhost:$CANARY_PORT/"* ]] || fail "canary link: $url"
key_c="$(api canary e2e-env api_key)"
key="$(jq -r .value <<<"$key_c")"; key_id="$(jq -r .canary.id <<<"$key_c")"
endpoint="$(jq -r .endpoint <<<"$key_c")"
[[ "$key" =~ ^ak_[a-z2-7]{40}$ ]] || fail "canary key: $key"
[[ "$(jq -r .canary.secret_id <<<"$key_c")" =~ ^[0-9a-f-]{36}$ ]] || fail "api_key canary not registered as a secret"
miss="$(curl -s -w ' %{http_code}' "http://localhost:$CANARY_PORT/static/nothing.png")"
hit="$(curl -s -w ' %{http_code}' -A 'e2e-bot/1.0' "$url.png?ref=wiki")"
[[ "$hit" == "$miss" && "$hit" == *" 404" ]] || fail "hit and miss must look the same: '$hit' vs '$miss'"
curl -s -o /dev/null -H "Authorization: Bearer $key" "$endpoint/charges"
# The other listeners clear the canary headers: a forged hit through :443 records nothing.
curl -s -o /dev/null --cacert "$E2E_CA" -H 'X-SecretTrace-Canary: 1' \
  -H "X-SecretTrace-Original-URI: ${url#http://localhost:$CANARY_PORT}" "$E2E_BASE/_canary"
url_d="$(api canary-get "$url_id")"; key_d="$(api canary-get "$key_id")"
[[ "$(jq -c '[.hit_count, (.hits | length), .hits[0].via, .hits[0].user_agent]' <<<"$url_d")" == '[1,1,"path","e2e-bot/1.0"]' ]] \
  || fail "url canary hits: $url_d"
jq -e '.hits[0].path | test("\\{token\\}\\.png\\?ref=wiki$")' <<<"$url_d" >/dev/null || fail "stored path: $url_d"
[[ "$(jq -c '[.hit_count, .hits[0].via, .hits[0].path]' <<<"$key_d")" == '[1,"bearer","/v1/charges"]' ]] || fail "key canary hits: $key_d"
grep -q "$key" <<<"$url_d$key_d" && fail "a canary value appeared in the API"
pass "link and fake key fired (path / bearer), identical 404 for hit and miss, forged hit via :443 ignored"
compose logs --no-color edge 2>/dev/null | grep -q "${key:3:20}" && fail "the canary key reached the edge log"
compose logs --no-color edge 2>/dev/null | grep -q "${url##*/}" && fail "the canary token reached the edge log"
pass "no token in the edge access log"

step "audit chain"
compose run --rm --no-deps -T server verify-audit >"$WORK/verify.out" 2>&1 || { cat "$WORK/verify.out"; fail "verify-audit failed"; }
pass "secrettrace-server verify-audit"
audit="$(api audit)"
[[ "$(jq -r .verify.ok <<<"$audit")" == true ]] || fail "audit/verify: $audit"
for action in db.migrate user.create auth.login.success api_token.create secret.create secret.update \
              ingest.scan_start ingest.match ingest.findings ingest.scan_complete source.create scan.enqueue scan.finish \
              canary.create; do
  jq -e --arg a "$action" '.actions | index($a)' <<<"$audit" >/dev/null || fail "audit has no $action: $audit"
done
pass "$(jq -r .verify.rows <<<"$audit") rows verified; expected actions present"

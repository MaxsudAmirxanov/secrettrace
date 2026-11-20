#!/usr/bin/env bash
# SecretTrace PKI for the TLS edge: a private CA, the edge's server certificate and client
# certificates for agents and CI (mTLS on :8443). Everything lands in deploy/pki/out/
# (gitignored). Requires openssl 1.1.1+ (3.x recommended).
#
#   pki.sh init                         CA (EC P-256, 10 years) and an empty CRL
#   pki.sh server [NAME…]               edge certificate for localhost, 127.0.0.1 and NAMEs
#   pki.sh client CN [DAYS]             client certificate (default 365 days); CN is what an
#                                       API token is bound to (cert_cn)
#   pki.sh revoke CN                    revoke the current certificate of CN and refresh the CRL
#   pki.sh crl                          re-issue the CRL (it is valid for CRL_DAYS; nginx
#                                       rejects every client once it expires)
#   pki.sh list                         issued certificates and their state
#
# After `revoke` or `crl`: docker compose exec edge nginx -s reload
set -euo pipefail
umask 077

OUT="${PKI_OUT:-$(cd "$(dirname "$0")" && pwd)/out}"
CA="$OUT/ca"
CRL_DAYS="${CRL_DAYS:-90}"

die() { echo "pki: $*" >&2; exit 1; }

valid_cn() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }

need_ca() { [[ -f "$CA/ca.crt" ]] || die "no CA yet: run '$0 init' first"; }

ca_config() {
  cat > "$CA/openssl.cnf" <<EOF
[ ca ]
default_ca = st_ca

[ st_ca ]
dir               = $CA
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
new_certs_dir     = \$dir/issued
certificate       = \$dir/ca.crt
private_key       = \$dir/ca.key
default_md        = sha256
default_crl_days  = $CRL_DAYS
policy            = st_policy
unique_subject    = no
copy_extensions   = none
email_in_dn       = no

[ st_policy ]
commonName             = supplied
organizationName       = optional

[ ca_ext ]
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash

[ server_ext ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
subjectAltName         = \${ENV::ST_SAN}

[ client_ext ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
EOF
}

gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

refresh_crl() {
  ST_SAN=DNS:unused openssl ca -batch -config "$CA/openssl.cnf" -gencrl -out "$CA/crl.pem" 2>/dev/null
  chmod 644 "$CA/crl.pem"
  echo "pki: CRL valid for $CRL_DAYS days: $CA/crl.pem"
}

cmd_init() {
  [[ -f "$CA/ca.key" ]] && die "a CA already exists in $CA (remove $OUT to start over)"
  mkdir -p "$CA/issued" "$OUT/server" "$OUT/clients"
  : > "$CA/index.txt"
  echo 1000 > "$CA/serial"
  echo 1000 > "$CA/crlnumber"
  ca_config
  gen_key "$CA/ca.key"
  ST_SAN=DNS:unused openssl req -new -x509 -key "$CA/ca.key" -sha256 -days 3650 \
    -subj "/O=SecretTrace/CN=SecretTrace CA" -config "$CA/openssl.cnf" -extensions ca_ext -out "$CA/ca.crt"
  chmod 644 "$CA/ca.crt"
  refresh_crl
  echo "pki: CA ready: $CA/ca.crt (give this file to clients as --ca-cert)"
}

cmd_server() {
  need_ca
  local san="DNS:localhost,IP:127.0.0.1,IP:::1" name
  for name in "$@"; do
    if [[ "$name" =~ ^[0-9.]+$ || "$name" == *:* ]]; then san+=",IP:$name"
    elif [[ "$name" =~ ^[A-Za-z0-9.*-]+$ ]]; then san+=",DNS:$name"
    else die "invalid host name: $name"; fi
  done
  local dir="$OUT/server"
  mkdir -p "$dir"
  gen_key "$dir/server.key"
  openssl req -new -key "$dir/server.key" -subj "/O=SecretTrace/CN=${1:-localhost}" -out "$dir/server.csr"
  ST_SAN="$san" openssl ca -batch -notext -config "$CA/openssl.cnf" -extensions server_ext -days 397 \
    -in "$dir/server.csr" -out "$dir/server.crt" 2>/dev/null
  # Full chain for nginx; the key must be readable by nginx (uid 101) through the bind
  # mount. The out/ directory (0700) keeps it private on the host.
  cat "$dir/server.crt" "$CA/ca.crt" > "$dir/fullchain.crt"
  chmod 644 "$dir/server.key" "$dir/server.crt" "$dir/fullchain.crt"
  rm -f "$dir/server.csr"
  echo "pki: server certificate for $san: $dir/fullchain.crt"
}

cmd_client() {
  need_ca
  local cn="${1:-}" days="${2:-365}"
  valid_cn "$cn" || die "CN must be 1-64 chars of [A-Za-z0-9._-]"
  [[ "$days" =~ ^[0-9]+$ && "$days" -ge 1 && "$days" -le 825 ]] || die "DAYS must be 1-825"
  local dir="$OUT/clients/$cn"
  [[ -f "$dir/client.crt" ]] && die "$cn already has a certificate; revoke it first ('$0 revoke $cn')"
  mkdir -p "$dir"
  gen_key "$dir/client.key"
  openssl req -new -key "$dir/client.key" -subj "/O=SecretTrace/CN=$cn" -out "$dir/client.csr"
  ST_SAN=DNS:unused openssl ca -batch -notext -config "$CA/openssl.cnf" -extensions client_ext -days "$days" \
    -in "$dir/client.csr" -out "$dir/client.crt" 2>/dev/null
  rm -f "$dir/client.csr"
  echo "pki: client certificate CN=$cn for $days days:"
  echo "  $dir/client.crt  (SECRETTRACE_CLIENT_CERT)"
  echo "  $dir/client.key  (SECRETTRACE_CLIENT_KEY; keep it secret, e.g. a CI file variable)"
  echo "  bind the API token to it: cert_cn = $cn"
}

cmd_revoke() {
  need_ca
  local cn="${1:-}"
  valid_cn "$cn" || die "CN must be 1-64 chars of [A-Za-z0-9._-]"
  local dir="$OUT/clients/$cn"
  [[ -f "$dir/client.crt" ]] || die "no current certificate for $cn"
  ST_SAN=DNS:unused openssl ca -batch -config "$CA/openssl.cnf" -revoke "$dir/client.crt" 2>/dev/null
  mv "$dir" "$dir.revoked-$(date -u +%Y%m%dT%H%M%SZ)"
  refresh_crl
  echo "pki: $cn revoked; reload nginx: docker compose exec edge nginx -s reload"
}

cmd_list() {
  need_ca
  # index.txt: status, expiry, revocation, serial, file, subject
  awk -F'\t' '{ s = ($1 == "V") ? "valid" : ($1 == "R") ? "revoked" : "expired";
                printf "%-8s serial %s expires %s %s\n", s, $4, $2, $6 }' "$CA/index.txt"
}

case "${1:-}" in
  init) shift; cmd_init "$@" ;;
  server) shift; cmd_server "$@" ;;
  client) shift; cmd_client "$@" ;;
  revoke) shift; cmd_revoke "$@" ;;
  crl) need_ca; refresh_crl ;;
  list) cmd_list ;;
  *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

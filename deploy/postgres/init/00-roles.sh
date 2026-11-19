#!/bin/sh
# Runs once on first container start (docker-entrypoint-initdb.d), as the superuser.
# Creates two roles:
#   st_owner — owns the database/schema, used only by `secrettrace-server migrate`
#   st_app   — runtime role; gets least-privilege grants from migration 0001
# Passwords come from Docker secrets (*_FILE) or, for throwaway test containers, env.
set -eu

read_secret() {
    file_var="$1_FILE"
    eval "file=\${$file_var:-}"
    eval "value=\${$1:-}"
    if [ -n "$file" ]; then
        tr -d '\r\n' < "$file"
    elif [ -n "$value" ]; then
        printf '%s' "$value"
    else
        echo "init: neither $1 nor $1_FILE is set" >&2
        exit 1
    fi
}

OWNER_PW="$(read_secret ST_OWNER_DB_PASSWORD)"
APP_PW="$(read_secret ST_APP_DB_PASSWORD)"
DB="${POSTGRES_DB:-secrettrace}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB" \
     -v owner_pw="$OWNER_PW" -v app_pw="$APP_PW" -v db="$DB" <<'SQL'
CREATE ROLE st_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE st_app   LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
ALTER DATABASE :"db" OWNER TO st_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO st_app;
SQL

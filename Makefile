SHELL := /bin/sh
SECRETS_DIR := deploy/secrets
TEST_PG := secrettrace-test-pg
TEST_DB_URL := postgres://postgres:test@127.0.0.1:54329/secrettrace

.PHONY: help secrets up down logs build admin test test-unit test-db db-up db-down lint fmt audit

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

secrets: ## Generate local secret files (never overwrites existing ones)
	@umask 077; mkdir -p $(SECRETS_DIR); chmod 700 $(SECRETS_DIR)
	@for f in postgres_password owner_db_password app_db_password; do \
	  [ -s $(SECRETS_DIR)/$$f ] || openssl rand -hex 32 > $(SECRETS_DIR)/$$f; done
	@[ -s $(SECRETS_DIR)/owner_database_url ] || printf 'postgres://st_owner:%s@postgres:5432/secrettrace' \
	  "$$(cat $(SECRETS_DIR)/owner_db_password)" > $(SECRETS_DIR)/owner_database_url
	@[ -s $(SECRETS_DIR)/app_database_url ] || printf 'postgres://st_app:%s@postgres:5432/secrettrace' \
	  "$$(cat $(SECRETS_DIR)/app_db_password)" > $(SECRETS_DIR)/app_database_url
	@[ -s $(SECRETS_DIR)/pepper_keys ] || printf '1:%s\n' "$$(openssl rand -base64 32)" > $(SECRETS_DIR)/pepper_keys
	@[ -s $(SECRETS_DIR)/data_key ] || openssl rand -base64 32 > $(SECRETS_DIR)/data_key
	@# Files are bind-mounted into containers running as other UIDs; the 0700 directory keeps them private on the host.
	@chmod 644 $(SECRETS_DIR)/*
	@echo "secrets ready in $(SECRETS_DIR)/ (back up pepper_keys and data_key: losing them invalidates fingerprints / TOTP enrollments)"

build: ## Build release binaries
	cargo build --release --locked

up: secrets ## Start the stack (postgres, migrate, server)
	docker compose up -d --build

down: ## Stop the stack (data volume is kept)
	docker compose down

admin: ## Create an admin user: make admin NAME=alice (NAME, not USER: $$USER is your login)
	@[ -n "$(NAME)" ] || { echo "usage: make admin NAME=<username>"; exit 1; }
	docker compose run --rm --no-deps -it server create-user --username "$(NAME)" --role admin

logs: ## Follow server logs
	docker compose logs -f server

db-up: ## Start a throwaway Postgres for tests on 127.0.0.1:54329
	@docker rm -f $(TEST_PG) >/dev/null 2>&1 || true
	@docker run -d --name $(TEST_PG) -e POSTGRES_PASSWORD=test -e POSTGRES_DB=secrettrace \
	  -e ST_OWNER_DB_PASSWORD=owner-test -e ST_APP_DB_PASSWORD=app-test \
	  -v "$(CURDIR)/deploy/postgres/init:/docker-entrypoint-initdb.d:ro" \
	  -p 127.0.0.1:54329:5432 postgres:17-alpine >/dev/null
	@i=0; until docker logs $(TEST_PG) 2>&1 | grep -q "init process complete" && \
	  docker exec $(TEST_PG) pg_isready -U postgres -d secrettrace >/dev/null 2>&1; do \
	  i=$$((i+1)); [ $$i -gt 60 ] && { echo "postgres did not start"; exit 1; }; sleep 1; done
	@echo "test postgres ready: $(TEST_DB_URL)"

db-down: ## Remove the test Postgres
	@docker rm -f $(TEST_PG) >/dev/null 2>&1 || true

test-unit: ## Unit tests only (no database)
	cargo test --workspace --lib --bins
	cargo test -p st-core -p st-extract -p st-source -p st-cli

test-db: db-up ## Full test suite including Postgres integration tests
	DATABASE_URL=$(TEST_DB_URL) cargo test --workspace

test: test-db ## Alias for test-db

lint: ## rustfmt check + clippy (warnings are errors)
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

fmt: ## Format code
	cargo fmt --all

audit: ## Check dependencies for known vulnerabilities (needs cargo-audit)
	cargo audit

# syntax=docker/dockerfile:1.7
FROM rust:1.89-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml clippy.toml ./
COPY crates ./crates
COPY migrations ./migrations
COPY testdata ./testdata
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p st-server \
 && cp target/release/secrettrace-server /secrettrace-server

# Web UI: static build only; node never reaches a runtime image.
FROM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY web ./
COPY testdata /src/testdata
RUN npm run build

# Worker: needs git and ssh to fetch repositories. Same binary, non-root, no package
# caches. Build with `--target worker`.
FROM debian:bookworm-slim AS worker
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nonroot \
 && install -d -o 65532 -g 65532 -m 0700 /var/lib/secrettrace /var/lib/secrettrace/worker
COPY --from=build /secrettrace-server /usr/local/bin/secrettrace-server
USER 65532:65532
ENV ST_WORKER_DATA_DIR=/var/lib/secrettrace/worker
ENTRYPOINT ["/usr/local/bin/secrettrace-server"]
CMD ["worker"]

# API server (default target, last): no shell, no package manager, non-root.
FROM gcr.io/distroless/cc-debian12:nonroot AS server
COPY --from=build /secrettrace-server /usr/local/bin/secrettrace-server
COPY --from=web /src/web/dist /usr/share/secrettrace/web
ENV ST_WEB_DIR=/usr/share/secrettrace/web
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/secrettrace-server"]
CMD ["serve"]

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

# Minimal runtime: no shell, no package manager, non-root.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /secrettrace-server /usr/local/bin/secrettrace-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/secrettrace-server"]
CMD ["serve"]

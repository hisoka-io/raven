# Operator binary image for raven-railgun. Build context MUST be the repo
# root, since the adapter path-depends on crates/ outside its own workspace:
#   docker build -t raven-railgun -f adapters/railgun/Dockerfile .
# SIGTERM starts the node's 15 s stop budget: a final commit still running when it is spent is
# abandoned, and its instance recovers from its last snapshot and WAL. The budget is past Docker's
# default 10 s stop timeout, so run with --stop-timeout 30.

FROM rust:1.98.0-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev clang lld git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# allowlist COPY, so nothing else from the root (local secrets, scratch) lands in
# a build layer. Whole directories, not named crates: the external path-deps
# inherit `version.workspace`/`lints.workspace` from the root manifest, so cargo
# loads every root workspace member even to build one adapter binary.
COPY rust-toolchain.toml Cargo.toml Cargo.lock README.md ./
COPY crates ./crates
COPY benches ./benches
COPY adapters/railgun ./adapters/railgun

RUN cargo build --release --locked \
        --manifest-path adapters/railgun/Cargo.toml \
        --bin raven-railgun
RUN strip /build/adapters/railgun/target/release/raven-railgun || true

FROM debian:bookworm-slim AS runtime
# slim, not distroless: operators want sh + curl for healthcheck/exec; tini forwards SIGTERM
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1500 raven \
 && useradd  --system --uid 1500 --gid 1500 --home-dir /data --shell /usr/sbin/nologin raven

# a template only: its token is REPLACE_ME, which boot refuses, so CMD reads the operator's copy
COPY --from=build /build/adapters/railgun/examples/mainnet-ppoi.toml \
     /etc/raven-railgun/mainnet-ppoi.toml
COPY --from=build /build/adapters/railgun/target/release/raven-railgun \
     /usr/local/bin/raven-railgun
RUN strip /usr/local/bin/raven-railgun || true

# data: instance dirs; secrets: operator-mounted config + bearer token. Created owned by raven
# first, since a fresh volume copies the image dir's owner and a root-owned one is unwritable.
RUN mkdir -p /srv/raven/data /srv/raven/secrets \
 && chown raven:raven /srv/raven/data /srv/raven/secrets \
 && chmod 0750 /srv/raven/data /srv/raven/secrets
VOLUME ["/srv/raven/data", "/srv/raven/secrets"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:8080/v1/health/ready || exit 1
STOPSIGNAL SIGTERM
USER raven:raven
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/raven-railgun"]
CMD ["serve-production", "--config", "/srv/raven/secrets/mainnet.toml"]

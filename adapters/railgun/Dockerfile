# Operator binary image for raven-railgun. Build context MUST be the repo
# root, since the adapter path-depends on crates/ outside its own workspace:
#   docker build -t raven-railgun -f adapters/railgun/Dockerfile .

FROM rust:1.85-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev clang lld git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# allowlist COPY, so nothing else from root (run/ secrets, no-commit/) lands in
# a build layer. Whole directories, not named crates: the external path-deps
# inherit `version.workspace`/`lints.workspace` from the root manifest, so cargo
# loads every root workspace member even to build one adapter binary.
COPY rust-toolchain.toml Cargo.toml Cargo.lock README.md ./
COPY crates ./crates
COPY benches ./benches
COPY adapters/railgun ./adapters/railgun

RUN cargo build --release \
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

COPY --from=build /build/adapters/railgun/examples/mainnet-6-instance.toml \
     /etc/raven-railgun/mainnet-6-instance.toml
COPY --from=build /build/adapters/railgun/examples/rpc-pool.example.toml \
     /etc/raven-railgun/rpc-pool.example.toml
COPY --from=build /build/adapters/railgun/target/release/raven-railgun \
     /usr/local/bin/raven-railgun
RUN strip /usr/local/bin/raven-railgun || true

# data: instance dirs; snapshots: export drop-zone; secrets: operator-mounted config + bearer + key
VOLUME ["/srv/raven/data", "/srv/raven/snapshots", "/srv/raven/secrets"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:8080/v1/health/ready || exit 1
USER raven:raven
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/raven-railgun"]
CMD ["serve-production", "--config", "/srv/raven/secrets/mainnet.toml"]

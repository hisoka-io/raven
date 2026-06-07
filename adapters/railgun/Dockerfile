# Operator binary image for `raven-railgun`.
#
# Build context MUST be the repo root: the adapter path-depends on
# ../../crates/inspire (a self-contained workspace submodule).
#   docker build -t raven-railgun -f adapters/railgun/Dockerfile .

FROM rust:1.85-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev clang lld git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# Explicit allowlist COPY. The adapter's only external path-dep is
# crates/inspire; nothing else from root is needed. This never pulls
# run/ (secrets) or no-commit/ into a build layer.
COPY rust-toolchain.toml ./
COPY crates/inspire ./crates/inspire
COPY adapters/railgun ./adapters/railgun

RUN cargo build --release \
        --manifest-path adapters/railgun/Cargo.toml \
        --bin raven-railgun
RUN strip /build/adapters/railgun/target/release/raven-railgun || true

FROM debian:bookworm-slim AS runtime
# bookworm-slim (not distroless): operators want sh + curl for the
# healthcheck and docker exec. tini forwards SIGTERM to the binary.
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

# /srv/raven/data instance dirs, /srv/raven/snapshots export drop-zone,
# /srv/raven/secrets operator-mounted (config + bearer + ed25519 key).
VOLUME ["/srv/raven/data", "/srv/raven/snapshots", "/srv/raven/secrets"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:8080/v1/health/ready || exit 1
USER raven:raven
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/raven-railgun"]

# serve-production --config <toml> selects the multi-instance path; the
# TOML carries the bearer token, bind, RPC config, and per-instance
# data_dirs. Override the argv or mount path via docker run as needed.
CMD ["serve-production", "--config", "/srv/raven/secrets/mainnet.toml"]

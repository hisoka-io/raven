# The raven-railgun node for Railway. Its build stage is the operator Dockerfile's, line for line
# (check-deploy.sh holds them equal); the runtime differs in three ways: no VOLUME, since Railway
# refuses the keyword and attaches its own volume; both network templates in the image; and an
# entrypoint that renders the config from Railway's variables. up.sh stages the build context.

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
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1500 raven \
 && useradd  --system --uid 1500 --gid 1500 --home-dir /data --shell /usr/sbin/nologin raven

COPY --from=build /build/adapters/railgun/examples/mainnet-ppoi.toml \
     /build/adapters/railgun/examples/sepolia-ppoi.toml \
     /etc/raven-railgun/
COPY --from=build /build/adapters/railgun/target/release/raven-railgun \
     /usr/local/bin/raven-railgun
COPY adapters/railgun/deploy/railway/entrypoint.sh /usr/local/bin/raven-railway-entrypoint
RUN chmod 0755 /usr/local/bin/raven-railway-entrypoint

EXPOSE 8080
STOPSIGNAL SIGTERM
# Starts as root only to hand a root-owned volume to uid 1500; the node itself never runs as root.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/raven-railway-entrypoint"]

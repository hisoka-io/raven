# The Howl node. Build from the repository root, with the adapters/howl submodule checked out:
#   docker build -f adapters/howl-node/deploy/Dockerfile -t howl-node .
# entrypoint.sh lists the variables a container is configured with.

FROM rust:1.98.0-slim-bookworm AS build
WORKDIR /build
# Allowlist COPY, so nothing else from the root (local secrets, scratch) lands in a build layer.
# The root manifest and its members come too: the path dependencies on crates/ inherit their
# version and lints from it, so cargo loads that workspace to build them.
COPY rust-toolchain.toml Cargo.toml Cargo.lock README.md ./
COPY crates ./crates
COPY benches ./benches
COPY adapters/howl ./adapters/howl
COPY adapters/howl-node ./adapters/howl-node
ARG CARGO_BUILD_JOBS
RUN cargo build --release --locked \
        --manifest-path adapters/howl-node/Cargo.toml -p howl-node \
 && strip adapters/howl-node/target/release/howl-node

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1500 howl \
 && useradd --system --uid 1500 --gid 1500 --home-dir /data --shell /usr/sbin/nologin howl \
 && install -d -o 1500 -g 1500 -m 0700 /data
COPY --from=build /build/adapters/howl-node/target/release/howl-node /usr/local/bin/howl-node
COPY adapters/howl-node/deploy/entrypoint.sh /usr/local/bin/howl-node-entrypoint
RUN chmod 0755 /usr/local/bin/howl-node-entrypoint

# The table and the node's key material. A new volume replays the chain from the deployment block.
VOLUME ["/data"]
ENV PORT=8645
EXPOSE 8645
STOPSIGNAL SIGTERM
# Liveness: the routes answer. It stays 200 while the follower retries a failing endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/howl/v1/health" >/dev/null || exit 1
# Starts as root only to hand a root-owned volume to uid 1500; the node itself never runs as root.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/howl-node-entrypoint"]

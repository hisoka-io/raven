#!/usr/bin/env bash
# Red-proof for check-deploy.sh: each mutation reintroduces one defect in a COPY of the files the
# gate reads, and the gate must fail naming it. The real tree is never written to.
set -uo pipefail

adapter=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
gate=$adapter/scripts/check-deploy.sh
scratch=$(mktemp -d "${TMPDIR:-/tmp}/check-deploy-selftest.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
failed=0

fresh() {
  rm -rf "$scratch/a"
  mkdir -p "$scratch/a/cli/src" "$scratch/a/http/src" "$scratch/a/deploy/railway" "$scratch/a/examples"
  cp "$adapter"/Dockerfile* "$scratch/a/"
  cp "$adapter/examples/mainnet-ppoi.toml" "$adapter/examples/sepolia-ppoi.toml" "$scratch/a/examples/"
  cp "$adapter/cli/src/serve_production_multi.rs" "$scratch/a/cli/src/"
  cp "$adapter/http/src/lib.rs" "$scratch/a/http/src/"
  cp "$adapter"/deploy/railway/* "$scratch/a/deploy/railway/"
  cp "$adapter/deploy/lib.sh" "$adapter/deploy/Caddyfile" "$adapter/deploy/deploy.sh" "$scratch/a/deploy/"
}

run_gate() { DEPLOY_CHECK_ROOT=$scratch/a "$gate" 2>&1; }

expect() {  # expect <label> <text the gate must print> <file> <sed expression>
  local label=$1 want=$2 file=$scratch/a/$3 out
  fresh
  sed -i -e "$4" "$file"
  if cmp -s "$file" "$adapter/$3"; then
    echo "FAIL $label: the mutation changed nothing"; failed=1; return
  fi
  if out=$(run_gate); then
    echo "FAIL $label: the gate passed"; failed=1
  elif [[ $out != *"$want"* ]]; then
    echo "FAIL $label: the gate failed without naming it: $out"; failed=1
  else
    echo "ok   $label"
  fi
}

fresh
if out=$(run_gate); then echo "ok   clean copy passes"; else echo "FAIL clean copy: $out"; failed=1; fi

expect "cargo build without --locked" "without --locked" Dockerfile.ppoi-replay 's/ --locked//'
expect "no STOPSIGNAL" "no STOPSIGNAL SIGTERM" Dockerfile '/^STOPSIGNAL SIGTERM$/d'
expect "stale stop bound in the Dockerfile" "could not read" Dockerfile \
  "s/^# SIGTERM starts the node's [0-9]* s stop budget.*/# Shutdown can wait 5 s per instance./"
expect "STOP_BUDGET moved" "STOP_BUDGET is 12 s" cli/src/serve_production_multi.rs \
  '/const STOP_BUDGET/s/from_secs([0-9]*)/from_secs(12)/'
expect "stop timeout too short" "under twice STOP_BUDGET" deploy/lib.sh 's/^STOP_TIMEOUT=30$/STOP_TIMEOUT=10/'
expect "cf-connecting-ip passed through" "cf-connecting-ip" deploy/Caddyfile '/header_up -Cf-Connecting-Ip/d'
expect "Caddy on a dual-stack socket" "IPv4 only" deploy/Caddyfile 's/default_bind tcp4\//default_bind /'
expect "port published on every address" "beyond loopback" deploy/deploy.sh \
  's/--publish "127.0.0.1:/--publish "0.0.0.0:/'
expect "default seats past the memory cap" "do not fit" deploy/deploy.sh 's/^max_sessions=32 /max_sessions=64 /'
expect "default memory cap too small" "do not fit" deploy/deploy.sh 's/ memory=10g$/ memory=4g/'
expect "seat size changed, help figure not" "does not state" deploy/lib.sh 's/^SEAT_MIB=24$/SEAT_MIB=12/'
expect "seat size for another row" "record_size is not 512" examples/mainnet-ppoi.toml \
  's/^record_size = 512$/record_size = 1024/'
# shellcheck disable=SC2016  # sed expressions, not shell
expect "an eighth instance" "does not state" examples/mainnet-ppoi.toml \
  '$a [[instance]]'
expect "Railway build stage drifted" "build stage" deploy/railway/Dockerfile 's/ --locked//'
# shellcheck disable=SC2016  # sed expressions, not shell
expect "Railway image declares a VOLUME" "declares a VOLUME" deploy/railway/Dockerfile \
  '$a VOLUME ["/srv/raven/data"]'
expect "Railway drain under the stop budget" "under twice STOP_BUDGET" deploy/railway/configure.sh \
  's/^\( *drainingSeconds:\) 30,$/\1 20,/'
expect "Railway health check on a route the node lacks" "not a route" deploy/railway/configure.sh \
  's|^\( *healthcheckPath:\) .*|\1 "/v1/health/alive",|'
expect "entrypoint keeps the template token" "token source" deploy/railway/entrypoint.sh \
  '/REPLACE_ME"\$. ""$/d'
# shellcheck disable=SC2016
expect "entrypoint binds a fixed port" "does not bind" deploy/railway/entrypoint.sh \
  's/0.0.0.0:\$port/0.0.0.0:8080/'
expect "a template that trusts forwarding headers" "trusts forwarding headers" examples/sepolia-ppoi.toml \
  's/^trust_proxy_header = false$/trust_proxy_header = true/'
expect "template bind reshaped" "cannot render sepolia" examples/sepolia-ppoi.toml 's/^bind = /bind  = /'
expect "a data dir off the volume" "cannot render mainnet" examples/mainnet-ppoi.toml \
  's|^data_dir = "/srv/raven/data/ppoi-paths-ofac-6"|data_dir = "/var/lib/ofac-6"|'
expect "Railway token set unsealed" "without sealing" deploy/railway/configure.sh \
  "0,/isSealed: true}'/s//isSealed: false}'/"
# shellcheck disable=SC2016
expect "Railway token set by a plain upsert" "without sealing" deploy/railway/configure.sh \
  '$a jq -n --arg v x '"'"'{i: {name: "RAVEN_BEARER_TOKEN", value: $v}}'"'"' | gql'

exit $failed

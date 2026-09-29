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
  mkdir -p "$scratch/a/cli/src" "$scratch/a/deploy"
  cp "$adapter"/Dockerfile* "$scratch/a/"
  cp "$adapter/cli/src/serve_production_multi.rs" "$scratch/a/cli/src/"
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

exit $failed

#!/usr/bin/env bash
# Run the CI gates that fail on a narrow local check, before pushing.
#
# The repo is thirteen separate cargo workspaces, each with its own fmt and clippy job, plus two
# MSRV jobs and the hygiene scripts. Checking only the crate you edited passes locally and reds CI,
# which is how four green jobs broke in one push. This runs all of them in one command.
#
# It deliberately does NOT run the test suites: those take tens of minutes and are sharded in CI.
# Use --with-tests for the fast per-workspace ones. Lint and hygiene are what narrow checking misses.
#
#   scripts/preflight.sh              fmt + clippy + hygiene, every workspace
#   scripts/preflight.sh --msrv       also both MSRV toolchains (slow, needs 1.89 and 1.91)
#   scripts/preflight.sh --with-tests also the detached-workspace test suites
#   scripts/preflight.sh --fast       hygiene + fmt only, no clippy (seconds)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

MSRV=0 WITH_TESTS=0 FAST=0
for a in "$@"; do
  case "$a" in
    --msrv) MSRV=1 ;;
    --with-tests) WITH_TESTS=1 ;;
    --fast) FAST=1 ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "preflight: unknown flag $a" >&2; exit 2 ;;
  esac
done

OFFLINE="${PREFLIGHT_OFFLINE:---offline}"
fail=0
declare -a FAILED=()

run() { # run <label> <cmd...>
  local label="$1"; shift
  printf '  %-46s' "$label"
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then echo "ok"; else
    echo "FAIL (rc=$rc)"; fail=1; FAILED+=("$label")
    printf '%s\n' "$out" | grep -E '^(error|warning: unused)' | head -4 | sed 's/^/        /'
    printf '%s\n' "$out" | grep -E '^\s+--> ' | head -4 | sed 's/^/        /'
  fi
}

echo "== hygiene (seconds, and the gate a comment can trip) =="
run "repo hygiene"            bash scripts/check-repo-hygiene.sh
run "repo hygiene selftest"   bash scripts/check-repo-hygiene-selftest.sh
[ -x adapters/railgun/scripts/check-hygiene.sh ] && \
  run "railgun hygiene"       bash adapters/railgun/scripts/check-hygiene.sh
run "ci filter names"         bash scripts/check-ci-filter-names.sh

echo
echo "== cargo fmt --check, every workspace =="
run "root"          cargo fmt --all -- --check
run "railgun"       cargo fmt --manifest-path adapters/railgun/Cargo.toml \
                      -p raven-railgun-cli -p raven-railgun-core -p raven-railgun-engine \
                      -p raven-railgun-http -p raven-railgun-indexer -p raven-railgun-mock-ppoi \
                      -p raven-railgun-persistence -p raven-railgun-poseidon \
                      -p raven-railgun-ppoi-mirror -p raven-railgun-testkit -- --check
run "client-wasm"   cargo fmt --manifest-path adapters/railgun/client-wasm/Cargo.toml -- --check
run "howl"          cargo fmt --manifest-path adapters/howl/Cargo.toml --all -- --check
run "inspire"       cargo fmt --manifest-path crates/inspire/Cargo.toml -- --check
run "isimplepir"    cargo fmt --manifest-path crates/isimplepir/Cargo.toml -- --check
run "binary-fuse"   cargo fmt --manifest-path crates/binary-fuse-filter/Cargo.toml -- --check
run "eth-state"     cargo fmt --manifest-path examples/eth-state/Cargo.toml -- --check
run "b1-bench"      cargo fmt --manifest-path benches/b1-bench/Cargo.toml -- --check
run "b2-bench"      cargo fmt --manifest-path benches/b2-bench/Cargo.toml -- --check
run "bench-compare" cargo fmt --manifest-path tools/bench-compare/Cargo.toml -- --check

if [ "$FAST" = 0 ]; then
  echo
  echo "== cargo clippy -D warnings, every workspace (the slow part) =="
  run "root"           cargo clippy --workspace --all-targets $OFFLINE -- -D warnings
  run "railgun"        cargo clippy --manifest-path adapters/railgun/Cargo.toml --workspace --all-targets $OFFLINE -- -D warnings
  run "howl"           cargo clippy --manifest-path adapters/howl/Cargo.toml --all-targets $OFFLINE -- -D warnings
  run "inspire"        cargo clippy --manifest-path crates/inspire/Cargo.toml --all-targets $OFFLINE -- -D warnings
  run "inspire modsw"  cargo clippy --manifest-path crates/inspire/Cargo.toml --all-targets --features mod-switch-response $OFFLINE -- -D warnings
  run "isimplepir"     cargo clippy --manifest-path crates/isimplepir/Cargo.toml --all-targets $OFFLINE -- -D warnings
  run "binary-fuse"    cargo clippy --manifest-path crates/binary-fuse-filter/Cargo.toml --all-targets $OFFLINE -- -D warnings
  run "eth-state"      cargo clippy --manifest-path examples/eth-state/Cargo.toml --all-targets $OFFLINE -- -D warnings
  run "b1-bench"       cargo clippy --manifest-path benches/b1-bench/Cargo.toml --features inspire --all-targets $OFFLINE -- -D warnings
  run "b2-bench"       cargo clippy --manifest-path benches/b2-bench/Cargo.toml --all-targets $OFFLINE -- -D warnings
  run "bench-compare"  cargo clippy --manifest-path tools/bench-compare/Cargo.toml --all-targets $OFFLINE -- -D warnings
  # wasm32 is a separate target and catches things the native lint cannot.
  if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    run "wasm32 raven-client" cargo clippy -p raven-client --all-targets --target wasm32-unknown-unknown $OFFLINE -- -D warnings
    run "wasm32 client-wasm"  cargo clippy --manifest-path adapters/railgun/client-wasm/Cargo.toml --all-targets --target wasm32-unknown-unknown $OFFLINE -- -D warnings
  else
    echo "  wasm32 target not installed -- SKIPPED (CI will still run it)"
  fi
fi

if [ "$MSRV" = 1 ]; then
  echo
  echo "== MSRV clippy (separate toolchains; a newer lint set is not the gate) =="
  for m in Cargo.toml adapters/howl/Cargo.toml adapters/railgun/client-wasm/Cargo.toml \
           benches/b2-bench/Cargo.toml crates/isimplepir/Cargo.toml tools/bench-compare/Cargo.toml; do
    RUSTUP_TOOLCHAIN=1.89 run "1.89 $m" cargo clippy --manifest-path "$m" --all-targets $OFFLINE -- -D warnings
  done
  RUSTUP_TOOLCHAIN=1.89 run "1.89 root --all-features" cargo clippy --manifest-path Cargo.toml --workspace --all-features --all-targets $OFFLINE -- -D warnings
  RUSTUP_TOOLCHAIN=1.89 run "1.89 inspire --all-features" cargo clippy --manifest-path crates/inspire/Cargo.toml --all-features --all-targets $OFFLINE -- -D warnings
  RUSTUP_TOOLCHAIN=1.91 run "1.91 railgun" cargo clippy --manifest-path adapters/railgun/Cargo.toml --workspace --all-targets $OFFLINE -- -D warnings
  RUSTUP_TOOLCHAIN=1.91 run "1.91 eth-state" cargo clippy --manifest-path examples/eth-state/Cargo.toml --all-targets $OFFLINE -- -D warnings
fi

if [ "$WITH_TESTS" = 1 ]; then
  echo
  echo "== detached-workspace tests (the railgun shards are too slow for preflight) =="
  run "inspire"      cargo test --manifest-path crates/inspire/Cargo.toml $OFFLINE
  run "isimplepir"   cargo test --manifest-path crates/isimplepir/Cargo.toml $OFFLINE
  run "binary-fuse"  cargo test --manifest-path crates/binary-fuse-filter/Cargo.toml $OFFLINE
  run "howl"         cargo test --manifest-path adapters/howl/Cargo.toml --all-targets $OFFLINE
  run "bench-compare" cargo test --manifest-path tools/bench-compare/Cargo.toml $OFFLINE
fi

echo
if [ "$fail" = 0 ]; then
  echo "preflight: OK"
else
  echo "preflight: ${#FAILED[@]} gate(s) failed:"
  printf '  - %s\n' "${FAILED[@]}"
fi
exit $fail

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${RAVEN_TOOLCHAIN_SCAN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PINNED_TOOLCHAIN="1.98.0"
MSRV_189="1.89"
MSRV_191="1.91"
PINNED_DOCKER_TAG="1.98.0-slim-bookworm"
MSRV_189_MANIFESTS='Cargo.toml|adapters/howl/Cargo.toml|adapters/railgun/client-wasm/Cargo.toml|benches/b1-bench/Cargo.toml|benches/b2-bench/Cargo.toml|crates/inspire/Cargo.toml|crates/isimplepir/Cargo.toml|tools/bench-compare/Cargo.toml'
MSRV_189_PACKAGES='bench-compare,howl-poseidon2,howl-record,raven-b1-bench,raven-b2-bench,raven-bench,raven-client,raven-core,raven-crypto-primitives,raven-indexer,raven-inspire,raven-inspire-cache,raven-inspire-client-wasm,raven-inspire-session,raven-isimplepir,raven-railgun-core,raven-railgun-persistence,raven-railgun-poseidon,raven-railgun-ppoi-mirror,raven-server,raven-storage'
MSRV_189_EXTRA_PACKAGES='raven-railgun-core,raven-railgun-persistence,raven-railgun-poseidon,raven-railgun-ppoi-mirror'
MSRV_189_OVERRIDE_MANIFESTS='adapters/railgun/core/Cargo.toml|adapters/railgun/persistence/Cargo.toml|adapters/railgun/poseidon/Cargo.toml|adapters/railgun/ppoi-mirror/Cargo.toml'
MSRV_191_MANIFESTS='adapters/railgun/Cargo.toml|examples/eth-state/Cargo.toml'
MSRV_191_PACKAGES='eth-state,raven-railgun-cli,raven-railgun-core,raven-railgun-engine,raven-railgun-http,raven-railgun-indexer,raven-railgun-mock-ppoi,raven-railgun-persistence,raven-railgun-poseidon,raven-railgun-ppoi-mirror,raven-railgun-testkit'

failed=0
pinned_actions=0
msrv_189_actions=0
msrv_191_actions=0
msrv_189_overrides=0
msrv_191_overrides=0
docker_builders=0
toolchain_files=0
nextest_installers=0
cargo_binstall_invocations=0

fail() {
  printf 'TOOLCHAIN PIN ERROR: %s\n' "$1" >&2
  failed=1
}

while IFS= read -r -d '' toolchain_file; do
  toolchain_files=$((toolchain_files + 1))
  channel="$(awk -F'"' '/^[[:space:]]*channel[[:space:]]*=/ { print $2 }' "$toolchain_file")"
  if [[ "$channel" != "$PINNED_TOOLCHAIN" ]]; then
    fail "$toolchain_file channel is '${channel:-missing}', expected '$PINNED_TOOLCHAIN'"
  fi
done < <(find "$REPO_ROOT" \
  -path "$REPO_ROOT/.git" -prune -o \
  -path "$REPO_ROOT/no-commit" -prune -o \
  -path '*/target' -prune -o \
  -type f \( -name rust-toolchain -o -name rust-toolchain.toml \) -print0)

if [[ "$toolchain_files" -eq 0 ]]; then
  fail "no rust-toolchain file found"
fi

check_manifest_floors() {
  local manifests="$1"
  local expected="$2"
  local relative
  local manifest
  local actual
  local entries
  IFS='|' read -r -a entries <<< "$manifests"
  for relative in "${entries[@]}"; do
    manifest="$REPO_ROOT/$relative"
    if [[ ! -f "$manifest" ]]; then
      fail "MSRV $expected manifest set is missing $relative"
      continue
    fi
    actual="$(awk -F'"' '/^rust-version[[:space:]]*=/ { print $2; exit }' "$manifest")"
    if [[ "$actual" != "$expected" ]]; then
      fail "$relative declares '${actual:-missing}', expected '$expected'"
    fi
  done
}

check_manifest_floors "$MSRV_189_MANIFESTS" "$MSRV_189"
check_manifest_floors "$MSRV_189_OVERRIDE_MANIFESTS" "$MSRV_189"
check_manifest_floors "$MSRV_191_MANIFESTS" "$MSRV_191"
check_manifest_floors "crates/binary-fuse-filter/Cargo.toml" "1.85"

known_floor_manifests="|$MSRV_189_MANIFESTS|$MSRV_189_OVERRIDE_MANIFESTS|$MSRV_191_MANIFESTS|crates/binary-fuse-filter/Cargo.toml|"
while IFS= read -r -d '' manifest; do
  declared="$(awk -F'"' '/^rust-version[[:space:]]*=/ { print $2; exit }' "$manifest")"
  [[ -n "$declared" ]] || continue
  relative="${manifest#"$REPO_ROOT/"}"
  if [[ "$known_floor_manifests" != *"|$relative|"* ]]; then
    fail "$relative declares rust-version '$declared' but is absent from the MSRV manifest inventory"
  fi
done < <(find "$REPO_ROOT" \
  -path "$REPO_ROOT/.git" -prune -o \
  -path "$REPO_ROOT/no-commit" -prune -o \
  -path '*/target' -prune -o \
  -type f -name Cargo.toml -print0)

while IFS= read -r -d '' workflow; do
  line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    if [[ "$line" =~ dtolnay/rust-toolchain@([^[:space:]#]+) ]]; then
      selector="${BASH_REMATCH[1]}"
      case "$selector" in
        "$PINNED_TOOLCHAIN")
          pinned_actions=$((pinned_actions + 1))
          ;;
        "$MSRV_189")
          msrv_189_actions=$((msrv_189_actions + 1))
          if [[ "$workflow" != "$REPO_ROOT/.github/workflows/ci.yml" ]]; then
            fail "$workflow:$line_number uses the MSRV 1.89 selector outside the root workflow"
          fi
          ;;
        "$MSRV_191")
          msrv_191_actions=$((msrv_191_actions + 1))
          if [[ "$workflow" != "$REPO_ROOT/.github/workflows/ci.yml" ]]; then
            fail "$workflow:$line_number uses the MSRV 1.91 selector outside the root workflow"
          fi
          ;;
        *)
          fail "$workflow:$line_number uses floating or divergent Rust selector '$selector'"
          ;;
      esac
    fi
    if [[ "$line" =~ actions-rs/toolchain@ ]]; then
      fail "$workflow:$line_number uses unsupported actions-rs/toolchain; use the pinned dtolnay selector"
    fi
    if [[ "$line" =~ toolchain:[[:space:]]*(stable|beta|nightly) ]]; then
      fail "$workflow:$line_number contains floating toolchain input '${BASH_REMATCH[1]}'"
    fi
    if [[ "$line" =~ cargo[[:space:]]+\+(stable|beta|nightly) ]]; then
      fail "$workflow:$line_number invokes floating cargo +${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ rustup[[:space:]]+(default|install|toolchain[[:space:]]+install|run)[[:space:]]+(stable|beta|nightly) ]]; then
      fail "$workflow:$line_number invokes floating rustup selector '${BASH_REMATCH[2]}'"
    fi
    if [[ "$line" =~ taiki-e/install-action@nextest ]]; then
      nextest_installers=$((nextest_installers + 1))
    fi
    if [[ "$line" == *'RUSTUP_TOOLCHAIN: "1.89"'* || "$line" == *'RUSTUP_TOOLCHAIN: 1.89'* ]]; then
      msrv_189_overrides=$((msrv_189_overrides + 1))
    fi
    if [[ "$line" == *'RUSTUP_TOOLCHAIN: "1.91"'* || "$line" == *'RUSTUP_TOOLCHAIN: 1.91'* ]]; then
      msrv_191_overrides=$((msrv_191_overrides + 1))
    fi
    if [[ "$line" =~ cargo-binstall ]]; then
      cargo_binstall_invocations=$((cargo_binstall_invocations + 1))
    fi
  done < "$workflow"
done < <(find "$REPO_ROOT" \
  -path "$REPO_ROOT/.git" -prune -o \
  -path "$REPO_ROOT/no-commit" -prune -o \
  -path '*/target' -prune -o \
  -type f \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \) -print0)

if [[ "$pinned_actions" -eq 0 ]]; then
  fail "no CI job selects the shipping Rust toolchain"
fi
if [[ "$msrv_189_actions" -ne 1 ]]; then
  fail "expected exactly one MSRV 1.89 action, found $msrv_189_actions"
fi
if [[ "$msrv_191_actions" -ne 1 ]]; then
  fail "expected exactly one MSRV 1.91 action, found $msrv_191_actions"
fi
if [[ "$msrv_189_overrides" -ne 1 ]]; then
  fail "expected one MSRV 1.89 override, found $msrv_189_overrides"
fi
if [[ "$msrv_191_overrides" -ne 1 ]]; then
  fail "expected one MSRV 1.91 override, found $msrv_191_overrides"
fi

check_msrv_job() {
  local job="$1"
  local floor="$2"
  local expected_manifests="$3"
  local expected_packages="$4"
  local expected_extra_packages="${5:-}"
  local workflow="$REPO_ROOT/.github/workflows/ci.yml"
  local block
  local actual_manifests
  local actual_packages
  local actual_extra_packages
  local extra_packages
  block="$(awk -v header="  $job:" '
    $0 == header { inside = 1 }
    inside && $0 ~ /^  [[:alnum:]_-]+:$/ && $0 != header { exit }
    inside { print }
  ' "$workflow")"
  if [[ -z "$block" ]]; then
    fail "missing $job job"
    return
  fi
  actual_manifests="$(awk -F'"' '/^[[:space:]]+MSRV_MANIFESTS:/ { print $2; exit }' <<< "$block")"
  actual_packages="$(awk -F'"' '/^[[:space:]]+MSRV_PACKAGES:/ { print $2; exit }' <<< "$block")"
  actual_extra_packages="$(awk -F'"' '/^[[:space:]]+MSRV_EXTRA_PACKAGES:/ { print $2; exit }' <<< "$block")"
  if [[ "$actual_manifests" != "$expected_manifests" ]]; then
    fail "MSRV $floor manifest set is '${actual_manifests:-missing}', expected '$expected_manifests'"
  fi
  if [[ "$actual_packages" != "$expected_packages" ]]; then
    fail "MSRV $floor package set is '${actual_packages:-missing}', expected '$expected_packages'"
  fi
  if [[ "$actual_extra_packages" != "$expected_extra_packages" ]]; then
    fail "MSRV $floor extra package set is '${actual_extra_packages:-missing}', expected '${expected_extra_packages:-none}'"
  fi
  if [[ "$block" != *'cargo metadata --manifest-path "$manifest"'* \
    || "$block" != *'actual_packages'* \
    || "$block" != *'MSRV_PACKAGES'* ]]; then
    fail "MSRV $floor job does not verify its selected package names"
  fi
  if [[ "$block" != *'cargo check --manifest-path "$manifest"'* ]]; then
    fail "MSRV $floor job does not compile every manifest in its inventory"
  fi
  if [[ -n "$expected_extra_packages" ]]; then
    local package
    local without_package
    local occurrences
    IFS=',' read -r -a extra_packages <<< "$expected_extra_packages"
    for package in "${extra_packages[@]}"; do
      without_package="${block//"$package"/}"
      occurrences=$(((${#block} - ${#without_package}) / ${#package}))
      if [[ "$occurrences" -lt 3 ]]; then
        fail "MSRV $floor job names $package in its inventory but does not compile it explicitly"
      fi
    done
  fi
}

check_msrv_job "msrv-1-89" "$MSRV_189" "$MSRV_189_MANIFESTS" "$MSRV_189_PACKAGES" \
  "$MSRV_189_EXTRA_PACKAGES"
check_msrv_job "msrv-1-91" "$MSRV_191" "$MSRV_191_MANIFESTS" "$MSRV_191_PACKAGES"

while IFS= read -r -d '' script; do
  case "$script" in
    "$REPO_ROOT/scripts/check-rust-toolchain-pin.sh"|"$REPO_ROOT/scripts/check-rust-toolchain-pin-selftest.sh")
      continue
      ;;
  esac
  line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    if [[ "$line" =~ cargo[[:space:]]+\+(stable|beta|nightly) ]]; then
      fail "$script:$line_number invokes floating cargo +${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ rustup[[:space:]]+(default|install|toolchain[[:space:]]+install|run)[[:space:]]+(stable|beta|nightly) ]]; then
      fail "$script:$line_number invokes floating rustup selector '${BASH_REMATCH[2]}'"
    fi
    if [[ "$line" =~ (RUSTUP_TOOLCHAIN|RUST_TOOLCHAIN|TOOLCHAIN)=(stable|beta|nightly) ]]; then
      fail "$script:$line_number assigns floating selector '${BASH_REMATCH[2]}'"
    fi
  done < "$script"
done < <(find "$REPO_ROOT" \
  -path "$REPO_ROOT/.git" -prune -o \
  -path "$REPO_ROOT/no-commit" -prune -o \
  -path '*/target' -prune -o \
  -type f \( -name '*.sh' -o -name Makefile -o -name '*.mk' \) -print0)

while IFS= read -r -d '' dockerfile; do
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^FROM[[:space:]]+rust:([^[:space:]]+) ]]; then
      docker_builders=$((docker_builders + 1))
      if [[ "${BASH_REMATCH[1]}" != "$PINNED_DOCKER_TAG" ]]; then
        fail "$dockerfile uses rust:${BASH_REMATCH[1]}, expected rust:$PINNED_DOCKER_TAG"
      fi
    fi
  done < "$dockerfile"
done < <(find "$REPO_ROOT" \
  -path "$REPO_ROOT/.git" -prune -o \
  -path "$REPO_ROOT/no-commit" -prune -o \
  -path '*/target' -prune -o \
  -type f -name 'Dockerfile*' -print0)

if [[ "$docker_builders" -eq 0 ]]; then
  fail "no Rust Docker builder selector found"
fi

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

printf 'Rust toolchain selectors pinned: channel=%s files=%d CI=%d MSRV=1.89/21+1.91/11 overrides=%d Docker=%d nextest=%d cargo-binstall=%d\n' \
  "$PINNED_TOOLCHAIN" "$toolchain_files" "$pinned_actions" \
  "$((msrv_189_overrides + msrv_191_overrides))" "$docker_builders" \
  "$nextest_installers" "$cargo_binstall_invocations"

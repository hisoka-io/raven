#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$SCRIPT_DIR/check-rust-toolchain-pin.sh"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

MSRV_189_MANIFESTS='Cargo.toml|adapters/howl-node/Cargo.toml|adapters/howl-node/client-wasm/Cargo.toml|adapters/railgun/client-wasm/Cargo.toml|benches/b1-bench/Cargo.toml|crates/inspire/Cargo.toml|tools/bench-compare/Cargo.toml'
MSRV_189_PACKAGES='bench-compare,howl-client-wasm,howl-node,howl-store,howl-wire,raven-b1-bench,raven-bench,raven-client,raven-core,raven-inspire,raven-inspire-cache,raven-inspire-client-wasm,raven-inspire-session,raven-railgun-core,raven-railgun-persistence,raven-railgun-poseidon,raven-railgun-ppoi-mirror,raven-server,raven-storage'
MSRV_189_EXTRA_PACKAGES='raven-railgun-core,raven-railgun-persistence,raven-railgun-poseidon,raven-railgun-ppoi-mirror'
MSRV_189_OVERRIDE_MANIFESTS='adapters/railgun/core/Cargo.toml|adapters/railgun/persistence/Cargo.toml|adapters/railgun/poseidon/Cargo.toml|adapters/railgun/ppoi-mirror/Cargo.toml'
MSRV_191_MANIFESTS='adapters/eth-state/Cargo.toml|adapters/railgun/Cargo.toml'
MSRV_191_PACKAGES='eth-state,raven-railgun-cli,raven-railgun-core,raven-railgun-engine,raven-railgun-http,raven-railgun-indexer,raven-railgun-persistence,raven-railgun-poseidon,raven-railgun-ppoi-mirror,raven-railgun-ppoi-replay,raven-railgun-testkit'

write_manifest() {
  local relative="$1"
  local version="$2"
  mkdir -p "$(dirname "$FIXTURE_ROOT/$relative")"
  printf '[workspace.package]\nrust-version = "%s"\n' "$version" > "$FIXTURE_ROOT/$relative"
}

mkdir -p "$FIXTURE_ROOT/.github/workflows" "$FIXTURE_ROOT/crates/inspire/.github/workflows" \
  "$FIXTURE_ROOT/adapters/railgun" "$FIXTURE_ROOT/scripts"
printf '[toolchain]\nchannel = "1.98.0"\n' > "$FIXTURE_ROOT/rust-toolchain.toml"
IFS='|' read -r -a floor_189_manifests <<< "$MSRV_189_MANIFESTS"
for manifest in "${floor_189_manifests[@]}"; do write_manifest "$manifest" "1.89"; done
IFS='|' read -r -a floor_189_overrides <<< "$MSRV_189_OVERRIDE_MANIFESTS"
for manifest in "${floor_189_overrides[@]}"; do write_manifest "$manifest" "1.89"; done
IFS='|' read -r -a floor_191_manifests <<< "$MSRV_191_MANIFESTS"
for manifest in "${floor_191_manifests[@]}"; do write_manifest "$manifest" "1.91"; done

cat > "$FIXTURE_ROOT/.github/workflows/ci.yml" <<EOF
jobs:
  shipping:
    steps:
      - uses: dtolnay/rust-toolchain@1.98.0
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-nextest@0.9.129
  lanes:
    steps:
      - uses: taiki-e/install-action@v2
        with:
          tool: "cargo-nextest@0.9.129"
  fuzz:
    env:
      FUZZ_TOOLCHAIN: nightly-2026-09-23
    steps:
      - uses: dtolnay/rust-toolchain@1.98.0
      - run: rustup toolchain install "\$FUZZ_TOOLCHAIN" --profile minimal
      - run: cargo "+\$FUZZ_TOOLCHAIN" fuzz build --fuzz-dir fuzz
  msrv-1-89:
    env:
      RUSTUP_TOOLCHAIN: "1.89"
      MSRV_MANIFESTS: "$MSRV_189_MANIFESTS"
      MSRV_PACKAGES: "$MSRV_189_PACKAGES"
      MSRV_EXTRA_PACKAGES: "$MSRV_189_EXTRA_PACKAGES"
    steps:
      - uses: dtolnay/rust-toolchain@1.89
        with:
          components: clippy
      - run: |
          actual_packages="selected"
          cargo metadata --manifest-path "\$manifest"
          if [ "\$actual_packages" != "\$MSRV_PACKAGES" ]; then exit 1; fi
          cargo check --manifest-path "\$manifest"
          cargo check -p raven-railgun-core
          cargo check -p raven-railgun-persistence
          cargo check -p raven-railgun-poseidon
          cargo check -p raven-railgun-ppoi-mirror
          cargo clippy --manifest-path "\$manifest" --all-targets -- -D warnings
          cargo clippy --all-targets -p raven-railgun-core -p raven-railgun-persistence -p raven-railgun-poseidon -p raven-railgun-ppoi-mirror -- -D warnings
  msrv-1-91:
    env:
      RUSTUP_TOOLCHAIN: "1.91"
      MSRV_MANIFESTS: "$MSRV_191_MANIFESTS"
      MSRV_PACKAGES: "$MSRV_191_PACKAGES"
    steps:
      - uses: dtolnay/rust-toolchain@1.91
        with:
          components: clippy
      - run: |
          actual_packages="selected"
          cargo metadata --manifest-path "\$manifest"
          if [ "\$actual_packages" != "\$MSRV_PACKAGES" ]; then exit 1; fi
          cargo check --manifest-path "\$manifest"
          cargo clippy --manifest-path "\$manifest" --all-targets -- -D warnings
EOF
printf '%s\n' \
  'jobs:' \
  '  test:' \
  '    steps:' \
  '      - uses: dtolnay/rust-toolchain@1.98.0' \
  > "$FIXTURE_ROOT/crates/inspire/.github/workflows/ci.yml"
printf 'FROM rust:1.98.0-slim-bookworm AS build\n' > "$FIXTURE_ROOT/adapters/railgun/Dockerfile"

GOOD_WORKFLOW="$FIXTURE_ROOT/ci.good.yml"
cp "$FIXTURE_ROOT/.github/workflows/ci.yml" "$GOOD_WORKFLOW"
output="$(RAVEN_TOOLCHAIN_SCAN_ROOT="$FIXTURE_ROOT" "$CHECKER")"
if [[ "$output" != *"dated-nightly=1"* ]]; then
  printf 'selftest failed: the dated nightly env pin was not counted: %s\n' "$output" >&2
  exit 1
fi

expect_rejection() {
  local expected="$1"
  local label="$2"
  local output
  if output="$(RAVEN_TOOLCHAIN_SCAN_ROOT="$FIXTURE_ROOT" "$CHECKER" 2>&1)"; then
    printf 'selftest failed: %s was accepted\n' "$label" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'selftest failed: %s was rejected for the wrong reason: %s\n' "$label" "$output" >&2
    exit 1
  fi
}

sed -i 's/channel = "1.98.0"/channel = "stable"/' "$FIXTURE_ROOT/rust-toolchain.toml"
expect_rejection "channel is 'stable', expected '1.98.0'" "floating rust-toolchain channel"
printf '[toolchain]\nchannel = "1.98.0"\n' > "$FIXTURE_ROOT/rust-toolchain.toml"

printf '%s\n' \
  'jobs:' \
  '  planted-float:' \
  '    steps:' \
  '      - uses: dtolnay/rust-toolchain@stable' \
  > "$FIXTURE_ROOT/.github/workflows/planted.yml"
expect_rejection "floating or divergent Rust selector 'stable'" "planted @stable selector"
rm "$FIXTURE_ROOT/.github/workflows/planted.yml"

printf 'cargo +nightly check\n' > "$FIXTURE_ROOT/scripts/planted.sh"
expect_rejection "invokes floating cargo + 'nightly'" "planted shell selector"
rm "$FIXTURE_ROOT/scripts/planted.sh"

# A dated nightly is one fixed build and passes in every form; a bare or host-only nightly, or
# a date that is not YYYY-MM-DD, floats wherever it is written, an env value included.
expect_acceptance() {
  local dated="$1"
  local label="$2"
  local output
  if ! output="$(RAVEN_TOOLCHAIN_SCAN_ROOT="$FIXTURE_ROOT" "$CHECKER" 2>&1)"; then
    printf 'selftest failed: %s was refused: %s\n' "$label" "$output" >&2
    exit 1
  fi
  if [[ "$output" != *"dated-nightly=$dated"* ]]; then
    printf 'selftest failed: %s: expected dated-nightly=%s: %s\n' "$label" "$dated" "$output" >&2
    exit 1
  fi
}
printf '%s\n' \
  'FUZZ_TOOLCHAIN=nightly-2026-09-23' \
  'cargo +nightly-2026-09-23 fuzz build' \
  'rustup toolchain install "nightly-2026-09-23"' \
  > "$FIXTURE_ROOT/scripts/planted.sh"
printf '%s\n' \
  'jobs:' \
  '  dated:' \
  '    env:' \
  '      RUSTUP_TOOLCHAIN: "nightly-2026-09-23"' \
  '    steps:' \
  '      - uses: dtolnay/rust-toolchain@1.98.0' \
  '        with:' \
  '          toolchain: nightly-2026-09-23' \
  > "$FIXTURE_ROOT/.github/workflows/planted.yml"
expect_acceptance 6 "dated nightlies in a script, an env value and an action input"
rm "$FIXTURE_ROOT/scripts/planted.sh" "$FIXTURE_ROOT/.github/workflows/planted.yml"

plant_workflow_line() {
  printf 'jobs:\n  planted:\n    steps:\n      - run: true\n%s\n' "$1" \
    > "$FIXTURE_ROOT/.github/workflows/planted.yml"
}
sed -i 's/FUZZ_TOOLCHAIN: nightly-2026-09-23/FUZZ_TOOLCHAIN: nightly/' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "sets a floating toolchain variable 'nightly'" "bare nightly in a job env"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"
sed -i 's/FUZZ_TOOLCHAIN: nightly-2026-09-23/FUZZ_TOOLCHAIN: "nightly"/' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "sets a floating toolchain variable 'nightly'" "quoted bare nightly in a job env"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"
sed -i 's/FUZZ_TOOLCHAIN: nightly-2026-09-23/FUZZ_TOOLCHAIN: nightly-2026-9-23/' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "sets a floating toolchain variable 'nightly-2026-9-23'" "undated nightly-like env"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"
plant_workflow_line '    env: { RUST_TOOLCHAIN: stable }'
expect_rejection "sets a floating toolchain variable 'stable'" "flow-style stable env value"
plant_workflow_line '        run: cargo +nightly-x86_64-unknown-linux-gnu fuzz build'
expect_rejection "invokes floating cargo + 'nightly-x86_64-unknown-linux-gnu'" "host-only nightly"
plant_workflow_line '          toolchain: nightly'
expect_rejection "contains floating toolchain input 'nightly'" "bare nightly action input"
plant_workflow_line '        run: rustup toolchain install "nightly" --profile minimal'
expect_rejection "invokes floating rustup selector 'nightly'" "quoted bare rustup nightly"
rm "$FIXTURE_ROOT/.github/workflows/planted.yml"
printf 'export FUZZ_TOOLCHAIN=nightly\n' > "$FIXTURE_ROOT/scripts/planted.sh"
expect_rejection "assigns floating selector 'nightly'" "bare nightly script variable"
rm "$FIXTURE_ROOT/scripts/planted.sh"

sed -i 's/rust:1.98.0-slim-bookworm/rust:latest/' "$FIXTURE_ROOT/adapters/railgun/Dockerfile"
expect_rejection "uses rust:latest, expected rust:1.98.0-slim-bookworm" \
  "floating Docker builder tag"
printf 'FROM rust:1.98.0-slim-bookworm AS build\n' > "$FIXTURE_ROOT/adapters/railgun/Dockerfile"

sed -i 's/,raven-inspire-session//' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "MSRV 1.89 package set" "missing new raven-inspire-session package"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/cargo check --manifest-path "\$manifest"/d' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "MSRV 1.89 job does not compile every manifest" "vacuous floor job"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/^  msrv-1-89:/,/^  msrv-1-91:/ {/cargo clippy/d;}' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "MSRV 1.89 job does not lint every manifest" "clippy-free 1.89 floor job"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/^  msrv-1-91:/,$ {/cargo clippy/d;}' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "MSRV 1.91 job does not lint every manifest" "clippy-free 1.91 floor job"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/cargo clippy --all-targets/s/ -p raven-railgun-core//' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "does not compile and lint it explicitly" "unlinted 1.89 leaf package"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/^  msrv-1-91:/,$ {/cargo clippy/s/ -- -D warnings//;}' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "clippy command lacks --all-targets -- -D warnings" \
  "warning-tolerant 1.91 clippy"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i 's/rust-version = "1.91"/rust-version = "1.89"/' \
  "$FIXTURE_ROOT/adapters/railgun/Cargo.toml"
expect_rejection "adapters/railgun/Cargo.toml declares '1.89', expected '1.91'" \
  "manifest/CI floor mismatch"
write_manifest "adapters/railgun/Cargo.toml" "1.91"

sed -i 's/rust-version = "1.89"/rust-version = "1.91"/' \
  "$FIXTURE_ROOT/adapters/railgun/core/Cargo.toml"
expect_rejection "adapters/railgun/core/Cargo.toml declares '1.91', expected '1.89'" \
  "incorrect 1.89 leaf override"
write_manifest "adapters/railgun/core/Cargo.toml" "1.89"

rm "$FIXTURE_ROOT/adapters/railgun/core/Cargo.toml"
expect_rejection "MSRV 1.89 manifest set is missing adapters/railgun/core/Cargo.toml" \
  "missing 1.89 leaf override"
write_manifest "adapters/railgun/core/Cargo.toml" "1.89"

write_manifest "extras/untracked/Cargo.toml" "1.89"
expect_rejection "extras/untracked/Cargo.toml declares rust-version '1.89' but is absent" \
  "untracked floor declaration"
rm -rf "$FIXTURE_ROOT/extras"

# An independent submodule pins itself: its floor, toolchain file and workflows are not this
# scan's, and the same files anywhere else still are.
write_manifest "adapters/howl/Cargo.toml" "1.89"
printf '[toolchain]\nchannel = "stable"\n' > "$FIXTURE_ROOT/adapters/howl/rust-toolchain.toml"
mkdir -p "$FIXTURE_ROOT/adapters/howl/.github/workflows"
printf 'jobs:\n  t:\n    steps:\n      - uses: dtolnay/rust-toolchain@stable\n' \
  > "$FIXTURE_ROOT/adapters/howl/.github/workflows/ci.yml"
if ! output="$(RAVEN_TOOLCHAIN_SCAN_ROOT="$FIXTURE_ROOT" "$CHECKER" 2>&1)"; then
  printf 'selftest failed: an independent submodule was scanned: %s\n' "$output" >&2
  exit 1
fi
cp -r "$FIXTURE_ROOT/adapters/howl" "$FIXTURE_ROOT/adapters/not-independent"
expect_rejection "adapters/not-independent/Cargo.toml declares rust-version '1.89' but is absent" \
  "the same files outside the independent submodule"
rm -rf "$FIXTURE_ROOT/adapters/howl" "$FIXTURE_ROOT/adapters/not-independent"

sed -i '/RUSTUP_TOOLCHAIN: "1.91"/d; s|rust-toolchain@1.91|rust-toolchain@1.98.0|' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "MSRV 1.91 action" "accidental 1.98-only floor"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

# nextest: gates parse its text output, so every job must install the one release they were
# proven against. An unpinned install took 0.9.146 and failed a healthy tree.
sed -i '0,/uses: taiki-e\/install-action@v2/s//uses: taiki-e\/install-action@nextest/' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "installs an unpinned nextest" "tool-named install-action ref"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '0,/tool: cargo-nextest@0.9.129/s//tool: cargo-nextest/' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "installs nextest as 'cargo-nextest', which floats" "versionless tool input"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '0,/tool: cargo-nextest@0.9.129/s//tool: nextest@0.9/' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "installs nextest as 'nextest@0.9', which floats" "minor-only tool pin"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i 's/tool: "cargo-nextest@0.9.129"/tool: "cargo-nextest@0.9.146"/' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "CI installs divergent nextest versions: 0.9.129 0.9.146" "two pinned nextest versions"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i 's/cargo-nextest@0.9.129/cargo-nextest@0.9.146/' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "CI installs nextest 0.9.146, expected 0.9.129" "one pin, not the proven release"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '0,/uses: taiki-e\/install-action@v2/s//uses: taiki-e\/install-action@v2\n        with: { tool: cargo-nextest }\n      - uses: taiki-e\/install-action@v2/' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "installs nextest as 'cargo-nextest', which floats" "flow-style tool input"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '0,/tool: cargo-nextest@0.9.129/s//tool: cargo-nextest@0.9.129\n      - run: curl -LsSf https:\/\/get.nexte.st\/latest\/linux | tar zxf - -C ~\/.cargo\/bin/' \
  "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "downloads nextest from nexte.st" "curl install from get.nexte.st"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/tool: /d' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "no CI job installs nextest" "no nextest install at all"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/RUSTUP_TOOLCHAIN: "1.89"/d' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "MSRV 1.89 override" "shadowed 1.89 floor"
cp "$GOOD_WORKFLOW" "$FIXTURE_ROOT/.github/workflows/ci.yml"

sed -i '/RUSTUP_TOOLCHAIN: "1.91"/d' "$FIXTURE_ROOT/.github/workflows/ci.yml"
expect_rejection "MSRV 1.91 override" "shadowed 1.91 floor"

printf 'toolchain pin selftest: all five scan families, the nextest pin, the dated nightly and MSRV job invariants held against their mutations\n'

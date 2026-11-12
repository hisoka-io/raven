#!/usr/bin/env bash
# Fuzzes every target (or the ones named) for SECONDS each, from a corpus seeded with honest bodies
# (examples/seeds.rs). A crash fails the run; its input stays under fuzz/artifacts/<target>/.
#
#   fuzz/run.sh <seconds> [target...]
#
# FUZZ_TOOLCHAIN names the nightly cargo-fuzz builds with; ci.yml's fuzz job sets the pinned one.
set -euo pipefail
cd "$(dirname "$0")"
secs=${1:?usage: fuzz/run.sh <seconds> [target...]}
shift
tc=${FUZZ_TOOLCHAIN:?set FUZZ_TOOLCHAIN to the nightly to build with}
if [ $# -gt 0 ]; then
  targets=("$@")
else
  mapfile -t targets < <(cargo "+$tc" fuzz list --fuzz-dir .)
fi
[ ${#targets[@]} -gt 0 ] || { echo "fuzz/run.sh: no targets" >&2; exit 1; }

# a Howl set-1 node keeps its key material on disk; inside the build tree, never the system's
export TMPDIR="$PWD/target/fuzz-tmp"
mkdir -p "$TMPDIR"

# fresh honest seeds each run; what a run adds to the corpus stays
cargo "+$tc" run --quiet --release --example seeds -- corpus

failed=()
for target in "${targets[@]}"; do
  echo "::group::fuzz ${target} for ${secs} s"
  # the largest seed sets max_len, so a key-sized body stays reachable
  if ! cargo "+$tc" fuzz run --fuzz-dir . "$target" "corpus/$target" -- \
      -max_total_time="$secs" -print_final_stats=1; then
    failed+=("$target")
  fi
  echo "::endgroup::"
done
if [ ${#failed[@]} -gt 0 ]; then
  echo "fuzz/run.sh: crashed: ${failed[*]} (inputs under fuzz/artifacts/)" >&2
  exit 1
fi
echo "fuzz/run.sh: ${#targets[@]} target(s), ${secs} s each, no crash"

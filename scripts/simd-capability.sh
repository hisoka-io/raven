#!/usr/bin/env bash
# Which AVX-512 kernels this host can run, one KEY=0|1 line per kernel, ready for $GITHUB_ENV.
# Each kernel's differential is made strict on exactly the hosts that carry its own flags, so a
# runner with one kernel's flags and not the other's still gates the one it can run.
#
#   scripts/simd-capability.sh [cpuinfo]     default /proc/cpuinfo
#
#   RAVEN_HAS_AVX512_IFMA             avx512f + avx512ifma: the IFMA52 packing and Montgomery kernels
#   RAVEN_HAS_AVX512_SPECIAL_MODULUS  avx512f + avx512bw + avx512dq + avx512vl: the special-modulus kernel
#
# These mirror the runtime checks the kernels dispatch on; a change to either side moves both.
set -euo pipefail

cpuinfo="${1:-/proc/cpuinfo}"
[[ -r "$cpuinfo" ]] || { echo "simd-capability: cannot read $cpuinfo" >&2; exit 2; }
# every core reports the same set, and a host with no flags line has no AVX-512
flags=" $(awk -F: '/^flags[[:space:]]*:/ { print $2; exit }' "$cpuinfo") "

has_all() {
  local f
  for f in "$@"; do
    [[ "$flags" == *" $f "* ]] || { echo 0; return; }
  done
  echo 1
}

echo "RAVEN_HAS_AVX512_IFMA=$(has_all avx512f avx512ifma)"
echo "RAVEN_HAS_AVX512_SPECIAL_MODULUS=$(has_all avx512f avx512bw avx512dq avx512vl)"

#!/usr/bin/env bash
# simd-capability.sh against CPU flag sets of real host families, including the two that split the
# kernels (special-modulus flags without IFMA) and flag names that contain a required one.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/simd-capability.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
failed=0

base="fpu sse sse2 ssse3 sse4_1 sse4_2 avx avx2 fma bmi2"
check() { # name flags want-ifma want-special-modulus
  local name=$1 flags=$2 want="RAVEN_HAS_AVX512_IFMA=$3 RAVEN_HAS_AVX512_SPECIAL_MODULUS=$4" got
  printf 'processor\t: 0\nflags\t\t: %s\n\nprocessor\t: 1\nflags\t\t: %s\n' "$flags" "$flags" > "$scratch/cpuinfo"
  got="$("$SCRIPT" "$scratch/cpuinfo" | tr '\n' ' ' | sed 's/ $//')"
  if [[ "$got" == "$want" ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name: got '$got', want '$want'"
    failed=1
  fi
}

check "Ice Lake server (both kernels)" "$base avx512f avx512dq avx512ifma avx512cd avx512bw avx512vl avx512vbmi" 1 1
check "Skylake server (special modulus only)" "$base avx512f avx512dq avx512cd avx512bw avx512vl" 0 1
check "Zen 3 (neither)" "$base" 0 0
check "IFMA listed without F" "$base avx512ifma avx512bw avx512dq avx512vl" 0 0
check "no VL" "$base avx512f avx512dq avx512ifma avx512bw" 1 0
check "only longer names that contain avx512f" "$base avx512fp16 avx512bw avx512dq avx512vl avx512ifma" 0 0
check "required flag last on the line" "$base avx512bw avx512dq avx512vl avx512ifma avx512f" 1 1
printf 'processor\t: 0\n' > "$scratch/cpuinfo"
check_noflags="$("$SCRIPT" "$scratch/cpuinfo" | tr '\n' ' ')"
if [[ "$check_noflags" == "RAVEN_HAS_AVX512_IFMA=0 RAVEN_HAS_AVX512_SPECIAL_MODULUS=0 " ]]; then
  echo "ok   no flags line"
else
  echo "FAIL no flags line: $check_noflags"
  failed=1
fi
if "$SCRIPT" "$scratch/absent" > /dev/null 2>&1; then
  echo "FAIL an unreadable cpuinfo passed"
  failed=1
else
  echo "ok   unreadable cpuinfo refused"
fi

SKIPS="$ROOT/scripts/simd-skips.sh"
skips() { # name log-body required want-rc
  local name=$1 rc=0
  printf '%b' "$2" > "$scratch/log"
  "$SKIPS" "$scratch/log" "$3" > "$scratch/out" 2>&1 || rc=$?
  if [[ "$rc" == "$4" ]]; then
    echo "ok   simd-skips: $name"
  else
    echo "FAIL simd-skips: $name: rc $rc, want $4"
    cat "$scratch/out"
    failed=1
  fi
}
ran='test x ... ok\n\ntest result: ok. 1 passed; 0 failed\n'
skipped='---- x stdout ----\nLOUD SKIP: x did NOT run - host lacks AVX-512 F/BW/DQ/VL\n\ntest result: ok. 1 passed\n'
skips "ran, required" "$ran" 1 0
skips "ran, not required" "$ran" 0 0
skips "skipped where required" "$skipped" 1 1
skips "skipped where not required" "$skipped" 0 0
skips "empty log" "" 0 2
skips "log with no test result" "error: could not compile\n" 1 2
printf '%b' "$skipped" > "$scratch/log"
if "$SKIPS" "$scratch/log" 0 | grep -q '^::warning title=AVX-512 differential skipped::LOUD SKIP: x'; then
  echo "ok   simd-skips: a skip that is not required is annotated"
else
  echo "FAIL simd-skips: a skip that is not required left no annotation"
  failed=1
fi
exit "$failed"

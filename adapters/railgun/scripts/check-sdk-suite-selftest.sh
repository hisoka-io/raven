#!/usr/bin/env bash
# Red-proof for the sdk-tests lane: a green `pnpm test` is evidence only if the suite
# CAN go red. This workstream found four separate cannot-fail tests inside the SDK suite,
# so the lane's own greenness was not evidence of anything.
#
# Model: check-wasm-bundle-size-selftest.sh. Copies the SDK tree to a scratch dir OUTSIDE
# the repo (a fresh CI checkout has no writable scratch inside it, and nothing this script
# does should ever land in the working tree),
# deletes the schema-envelope version guard there (the exact mutation that once left the
# WHOLE suite green — M3, w4d-sdk — and is now killed by
# tests/t1_end_to_end_real_decode.test.ts), runs the suite in the copy, and FAILS if the
# suite comes back green. The real tree is never modified and no git command is run.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
REPO_ROOT="$(cd "${ADAPTER_ROOT}/../.." && pwd)"

# Scratch OUTSIDE the repo entirely, so a CI checkout gets no written-into directory and
# a local run cannot leave a copy of the tree behind. Overridable; a scratch that IS the
# repo root, the SDK, or inside the repo is refused rather than trusted.
owns_scratch=0
if [[ -n "${SDK_SELFTEST_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_SELFTEST_SCRATCH"
  SCRATCH="$(cd "$SDK_SELFTEST_SCRATCH" && pwd)"
else
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sdk-suite-selftest.XXXXXX")"
  owns_scratch=1
fi
if [[ -z "$SCRATCH" || "$SCRATCH" == "$REPO_ROOT" || "$SCRATCH" == "$SDK" || "$SCRATCH" == "$REPO_ROOT"/* ]]; then
  echo "check-sdk-suite-selftest: refusing to use ${SCRATCH} as scratch" >&2
  exit 3
fi

if [[ ! -d "${SDK}/node_modules" ]]; then
  echo "check-sdk-suite-selftest: ${SDK}/node_modules missing — run pnpm install first" >&2
  exit 3
fi

work="${SCRATCH}/copy-$$"
mkdir -p "$work"
cleanup() {
  rm -rf "$work" "${SCRATCH}/poseidon"
  if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$SCRATCH"; fi
}
trap cleanup EXIT

# Copy sources and tests; link dependencies. cp -a nothing that contains a target/.
cp -a "${SDK}/src" "${SDK}/tests" "${SDK}/tsconfig.json" "${SDK}/package.json" "$work/"
ln -s "${SDK}/node_modules" "$work/node_modules"

# tests/poseidon_parity.test.ts reads the Rust-emitted KAT from a SIBLING package,
# ../../poseidon/tests/fixtures/. Without it the copy reds with an ENOENT that has
# nothing to do with the mutation - a red for the wrong reason, which is the exact
# thing this script exists to refuse. Recreate that sibling beside the copy.
POSEIDON_FIXTURES="${ADAPTER_ROOT}/poseidon/tests/fixtures"
if [[ ! -d "$POSEIDON_FIXTURES" ]]; then
  echo "check-sdk-suite-selftest: missing ${POSEIDON_FIXTURES} — the copy would red for the wrong reason" >&2
  exit 3
fi
mkdir -p "${SCRATCH}/poseidon/tests"
cp -a "$POSEIDON_FIXTURES" "${SCRATCH}/poseidon/tests/"

MUT_FILE="$work/src/raven-poi-node-interface.ts"
NEEDLE='if (envelope !== 1) {'
count="$(/usr/bin/grep -c "$NEEDLE" "$MUT_FILE" || true)"
if [[ "$count" -ne 1 ]]; then
  echo "check-sdk-suite-selftest: expected exactly 1 envelope-guard site, found ${count} — the mutation no longer applies; update this selftest" >&2
  exit 3
fi

# Delete the guard block (5 lines starting at the needle) in the COPY only.
python3 - "$MUT_FILE" <<'PYEOF'
import io, sys
p = sys.argv[1]
s = io.open(p, encoding="utf-8").read()
needle = """  if (envelope !== 1) {
    throw RavenError.decodeError(
      `${label}: unexpected schema envelope version ${envelope}`,
    );
  }
"""
n = s.count(needle)
if n != 1:
    raise SystemExit(f"needle count {n} != 1 — mutation did not apply")
io.open(p, "w", encoding="utf-8").write(s.replace(needle, ""))
PYEOF
if ! /usr/bin/grep -q 'unexpected schema envelope version' "$MUT_FILE"; then
  echo "  mutation applied: schema-envelope version guard deleted in the copy"
else
  echo "check-sdk-suite-selftest: mutation failed to apply" >&2
  exit 3
fi

out="$work/vitest-out.txt"
( cd "$work" && ./node_modules/.bin/vitest run --config tests/vitest.config.ts >"$out" 2>&1 )
suite_exit=$?

if [[ "$suite_exit" -eq 0 ]]; then
  echo "check-sdk-suite-selftest: FAILED - the suite stayed GREEN with the envelope guard deleted; the lane cannot detect the silent-wrong-bytes class it exists for." >&2
  tail -5 "$out" >&2
  exit 1
fi
# Match the FAILING-test marker, not the file name. A bare filename grep is satisfied by
# the reporter's line for a file that PASSED, so it would accept a red caused by anything
# at all - a vacuous check inside the anti-vacuity script.
if ! /usr/bin/grep -qE '^ *(×|✗|FAIL).*refuses an unknown schema envelope version' "$out"; then
  echo "check-sdk-suite-selftest: FAILED - the suite went red but NOT via the discriminating envelope test; the red is for the wrong reason." >&2
  tail -20 "$out" >&2
  exit 1
fi
# And it must be the ONLY red: an unrelated failure alongside it would still satisfy the
# check above while meaning the copy, not the mutation, is what broke. BOTH lines are
# required - a file that throws while COLLECTING (a fixture the copy did not bring along)
# raises `Test Files N failed` but adds NO failed test, so the `Tests` line alone reads
# clean while a whole file never ran. Measured: that exact hole hid a missing
# poseidon_parity fixture behind a green selftest.
if ! /usr/bin/grep -qE '^ *Tests +1 failed' "$out" \
  || ! /usr/bin/grep -qE '^ *Test Files +1 failed' "$out"; then
  echo "check-sdk-suite-selftest: FAILED - something beyond the envelope test reddened or failed to collect; the scratch copy is not a faithful copy." >&2
  /usr/bin/grep -E '^ *(×|Tests |Test Files)' "$out" >&2
  exit 1
fi
echo "check-sdk-suite-selftest: the suite goes red under the envelope-guard deletion (exit ${suite_exit}), via exactly the discriminating test."

#!/usr/bin/env bash
# Red-proof for check-no-mutation-residue.sh. The gate ships with the proof that it can fail.
#
# This file exists because the gate SHIPPED BLIND. It globbed only '*.proptest-regressions' — the
# suffix form proptest writes for integration tests — and could not see the DIRECTORY form
# (<crate>/proptest-regressions/<module>.txt) that in-src proptests write. A live seed sat in
# adapters/railgun/http/ while the gate reported clean (M-065). Its prose red-proof had used the
# one shape its author had in front of him.
#
# So every case below is a DIFFERENT SHAPE of the same subject, which is the rule M-065 adopted.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/check-no-mutation-residue.sh
ALLOW=scripts/src-change-allowlist.txt
# A src file that is NOT allowlisted, so touching it must be seen as residue. Chosen for being
# tiny and outside every lane's write set.
VICTIM=crates/crypto-primitives/src/lib.rs
[ -f "$VICTIM" ] || { echo "selftest fixture missing: ${VICTIM}" >&2; exit 1; }
if /usr/bin/grep -qxF "$VICTIM" "$ALLOW"; then
  echo "SELFTEST FIXTURE STALE: ${VICTIM} is now allowlisted, so case 1 would prove nothing." >&2
  echo "  Re-point VICTIM at a src file absent from ${ALLOW}." >&2
  exit 1
fi

BV=$(mktemp)
cp "$VICTIM" "$BV"
DIRFORM=adapters/railgun/http/proptest-regressions
SUFFIXFORM=crates/storage/tests/zz_selftest_only.proptest-regressions
# Restore installed BEFORE any mutation: a killed run must not leave one applied.
trap 'cp "$BV" "$VICTIM"; rm -f "$BV" "$SUFFIXFORM"; rm -rf "$DIRFORM"' EXIT

fails=0
expect() {  # expect <want-nonzero:0|1> <label>
  bash "$GATE" > /dev/null 2>&1
  local rc=$? want="$1" label="$2"
  if [ "$want" = 1 ] && [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: ${label} did not trip the gate" >&2; fails=1
  elif [ "$want" = 0 ] && [ "$rc" -ne 0 ]; then
    echo "SELFTEST FAIL: ${label} tripped the gate but should not have (exit ${rc})" >&2; fails=1
  else
    echo "  ok: ${label} -> exit ${rc}"
  fi
  cp "$BV" "$VICTIM"; rm -f "$SUFFIXFORM"; rm -rf "$DIRFORM"
}

echo "check-no-mutation-residue-selftest.sh: three shapes the gate must catch, plus the control"

# Control FIRST: if the tree is already dirty, every other case is meaningless.
bash "$GATE" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "SELFTEST CANNOT RUN: the gate is already failing on the unmutated tree." >&2
  echo "  Clean the residue it reports, then re-run this selftest." >&2
  exit 1
fi
echo "  ok: the unmutated tree -> exit 0"

# 1. An unallowlisted production-source change - the classic interrupted mutation.
printf '\n// selftest residue marker\n' >> "$VICTIM"
expect 1 "an unallowlisted src change"

# 2. proptest's SUFFIX form (integration tests under tests/).
printf '# seeds\ncc deadbeef # shrinks to n = 1\n' > "$SUFFIXFORM"
expect 1 "a suffix-form .proptest-regressions file"

# 3. proptest's DIRECTORY form (in-src #[cfg(test)] proptests). THE SHAPE THAT WAS BLIND.
mkdir -p "$DIRFORM"
printf '# seeds\ncc deadbeef # shrinks to n = 1\n' > "$DIRFORM/selftest.txt"
expect 1 "a DIRECTORY-form proptest-regressions file (the shape M-065 found invisible)"

if [ "$fails" -ne 0 ]; then
  echo "check-no-mutation-residue-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-no-mutation-residue-selftest.sh: all cases behaved as required."

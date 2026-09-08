#!/usr/bin/env bash
# Red-proof for check-ignore-coverage.sh. Four cases it must fail on, plus the control.
set -uo pipefail
cd "$(dirname "$0")/.."
ALLOW=scripts/ignore-coverage-allowlist.txt
CI=.github/workflows/ci.yml
# Deliberately outside every lane write set: writing to a directory another agent
# owns is how concurrent work gets clobbered, and this selftest mutates its victim.
VICTIM=crates/isimplepir/tests/deterministic_a.rs
BA=$(mktemp); BC=$(mktemp); BV=$(mktemp)
cp "$ALLOW" "$BA"; cp "$CI" "$BC"; cp "$VICTIM" "$BV"
# Restore installed BEFORE any mutation - a killed run must not leave one applied.
trap 'cp "$BA" "$ALLOW"; cp "$BC" "$CI"; cp "$BV" "$VICTIM"; rm -f "$BA" "$BC" "$BV"' EXIT

fails=0

# A selftest fixture that names specific tree contents is a DEPENDENCY on those contents, and
# this file's case 3 has now gone stale twice for that reason alone (once when W4-11 deleted the
# test it named, once when W3-27 deleted the ci.yml clause it edited). Both times the symptom was
# identical to a broken gate - "did not trip" - which is the worst possible diagnostic, because
# the honest reading of a stale fixture is "I proved nothing", not "the gate is broken".
# applied() forces the mutation to prove it landed, so the two failures can never be confused.
applied() {  # applied <needle> <label>
  if [ "$(/usr/bin/grep -cF "$1" "$CI")" -lt 1 ]; then
    echo "SELFTEST FIXTURE STALE: ${label:-$2} - the mutation did not apply, so this case" >&2
    echo "  proved NOTHING about the gate. Re-point the fixture; do not trust a green run." >&2
    fails=1; return 1
  fi
  return 0
}

expect() {  # expect <want-exit-nonzero:0|1> <label>
  bash scripts/check-ignore-coverage.sh > /dev/null 2>&1
  local rc=$? want="$1" label="$2"
  if [ "$want" = 1 ] && [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: ${label} did not trip the gate" >&2; fails=1
  elif [ "$want" = 0 ] && [ "$rc" -ne 0 ]; then
    echo "SELFTEST FAIL: ${label} tripped the gate but should not have (exit ${rc})" >&2; fails=1
  else
    echo "  ok: ${label} -> exit ${rc}"
  fi
  cp "$BA" "$ALLOW"; cp "$BC" "$CI"; cp "$BV" "$VICTIM"
}

echo "check-ignore-coverage-selftest.sh:"

# 1. A brand-new ignored test in a binary no lane selects.
python3 - <<'PYEOF'
import pathlib
p = pathlib.Path('crates/isimplepir/tests/deterministic_a.rs')
p.write_text(p.read_text() + '\n#[test]\n#[ignore = "selftest fixture"]\nfn a_selftest_only_uncovered_ignore() {}\n')
PYEOF
expect 1 "a new ignored test in an unselected binary"

# 2. Dropping a lane's binary from ci.yml orphans every ignored test in it.
sed -i 's/binary(migrate_encoder_real_sigkill) + //' "$CI"
expect 1 "a lane losing a binary that carried ignored tests"

# 3. Subtracting a name by hand removes that test's only lane. W3-27 emptied the subtraction
# clause entirely, so this case now INTRODUCES one rather than editing one - which is the shape
# a future regression would actually take, and it no longer depends on a clause existing.
# The victim must be an #[ignore]d test the cli-ignored filter currently runs.
sed -i 's/binary(smart_policy_lifecycle)"/binary(smart_policy_lifecycle) - (test(auto_spawned_consumers_drain_wal_on_sigterm))"/' "$CI"
if applied 'test(auto_spawned_consumers_drain_wal_on_sigterm)' "an ignored test newly excluded by name"; then
  expect 1 "an ignored test newly excluded by name"
else
  cp "$BA" "$ALLOW"; cp "$BC" "$CI"; cp "$BV" "$VICTIM"
fi

# 4. Emptying the allowlist must fail: 42 entries become unexplained.
: > "$ALLOW"
expect 1 "an emptied allowlist"

# Control: unmutated, the gate must PASS. A gate that always fails is not a gate.
expect 0 "the unmutated tree"

if [ "$fails" -ne 0 ]; then
  echo "check-ignore-coverage-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-ignore-coverage-selftest.sh: all cases behaved as required."

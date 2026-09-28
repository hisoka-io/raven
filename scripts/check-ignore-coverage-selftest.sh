#!/usr/bin/env bash
# Red-proof for check-ignore-coverage.sh. Seven cases it must fail on, plus the control.
set -uo pipefail
cd "$(dirname "$0")/.."
ALLOW=scripts/ignore-coverage-allowlist.txt
CI=.github/workflows/ci.yml
# Deliberately outside every lane write set: writing to a directory another agent
# owns is how concurrent work gets clobbered, and this selftest mutates its victim.
VICTIM=crates/inspire-cache/tests/public_surface.rs
# A test inside a submodule, which a top-level grep never reaches.
SUB_VICTIM=adapters/eth-state/tests/consume_both.rs
BA=$(mktemp); BC=$(mktemp); BV=$(mktemp); BS=$(mktemp)
cp "$ALLOW" "$BA"; cp "$CI" "$BC"; cp "$VICTIM" "$BV"; cp "$SUB_VICTIM" "$BS"
# Restore installed BEFORE any mutation - a killed run must not leave one applied.
trap 'cp "$BA" "$ALLOW"; cp "$BC" "$CI"; cp "$BV" "$VICTIM"; cp "$BS" "$SUB_VICTIM"; rm -f "$BA" "$BC" "$BV" "$BS"' EXIT

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
  cp "$BA" "$ALLOW"; cp "$BC" "$CI"; cp "$BV" "$VICTIM"; cp "$BS" "$SUB_VICTIM"
}

echo "check-ignore-coverage-selftest.sh:"

# 1. A bare ignore is invalid even before coverage is considered.
python3 - <<'PYEOF'
import pathlib
p = pathlib.Path('crates/inspire-cache/tests/public_surface.rs')
p.write_text(p.read_text() + '\n#[test]\n#[ignore]\nfn a_selftest_bare_ignore() {}\n')
PYEOF
expect 1 "a bare ignore"

# 2. A reason with no citable trigger is incomplete or stale.
python3 - <<'PYEOF'
import pathlib
p = pathlib.Path('crates/inspire-cache/tests/public_surface.rs')
p.write_text(p.read_text() + '\n#[test]\n#[ignore = "selftest stale reason"]\nfn a_selftest_stale_reason() {}\n')
PYEOF
expect 1 "a false or stale reason without a citable trigger"

# 3. A fully reasoned ignore still needs a coverage lane or allowlist entry.
python3 - <<'PYEOF'
import pathlib
p = pathlib.Path('crates/inspire-cache/tests/public_surface.rs')
p.write_text(p.read_text() + '\n#[test]\n#[ignore = "1 ms. Trigger: selftest missing allowlist entry."]\nfn a_selftest_only_uncovered_ignore() {}\n')
PYEOF
expect 1 "a new reasoned ignore missing from the allowlist"

# 4. Dropping a lane's binary from ci.yml orphans every ignored test in it. The victim must be
# a binary with an #[ignore]d test that only this lane runs.
sed -i 's/ + binary(production_cell) + / + /' "$CI"
if cmp -s "$BC" "$CI"; then
  echo "SELFTEST FIXTURE STALE: case 4 - binary(production_cell) is in no lane filter, so" >&2
  echo "  this case proved NOTHING about the gate. Re-point the fixture." >&2
  fails=1
else
  expect 1 "a lane losing a binary that carried ignored tests"
fi

# 5. Subtracting a name by hand removes that test's only lane. W3-27 emptied the subtraction
# clause entirely, so this case now INTRODUCES one rather than editing one - which is the shape
# a future regression would actually take, and it no longer depends on a clause existing.
# The victim must be an #[ignore]d test the cli-ignored filter currently runs.
sed -i 's/binary(smart_policy_lifecycle)"/binary(smart_policy_lifecycle) - (test(auto_spawned_consumers_drain_wal_on_sigterm))"/' "$CI"
if applied 'test(auto_spawned_consumers_drain_wal_on_sigterm)' "an ignored test newly excluded by name"; then
  expect 1 "an ignored test newly excluded by name"
else
  cp "$BA" "$ALLOW"; cp "$BC" "$CI"; cp "$BV" "$VICTIM"
fi

# 6. Emptying the allowlist must fail: every uncovered entry becomes unexplained.
: > "$ALLOW"
expect 1 "an emptied allowlist"

# 7. The same uncovered ignore inside a submodule. The census once searched only the top level
# and one named submodule, so an ignored test in any other submodule was never counted.
python3 - <<'PYEOF'
import pathlib
p = pathlib.Path('adapters/eth-state/tests/consume_both.rs')
p.write_text(p.read_text() + '\n#[test]\n#[ignore = "1 ms. Trigger: selftest missing allowlist entry."]\nfn a_selftest_submodule_ignore() {}\n')
PYEOF
expect 1 "a new reasoned ignore inside a submodule missing from the allowlist"

# Control: unmutated, the gate must PASS. A gate that always fails is not a gate.
expect 0 "the unmutated tree"

if [ "$fails" -ne 0 ]; then
  echo "check-ignore-coverage-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-ignore-coverage-selftest.sh: all cases behaved as required."

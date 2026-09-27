#!/usr/bin/env bash
# Red-proof for check-ci-filter-names.sh. The gate ships with the proof that it can fail.
#
# The first draft of the gate PASSED this file's case 1, because its name class was [a-z_0-9] and
# the mutation introduced an uppercase letter, so the term was silently skipped. A gate that cannot
# see part of its own input is worse than no gate; that is why this selftest exists.
set -uo pipefail
cd "$(dirname "$0")/.."

# The show-config reader on saved outputs of both releases CI has met. 0.9.146 appended
# "(from FILE)" to every override line and the gate rejected a healthy tree, so both shapes must
# parse to the same groups, and an unknown line must fail naming the release that printed it.
show_config_fixtures() {
  local dir=scripts/fixtures/check-ci-filter-names/show-config version out release bad=0
  local want="group chaos-subprocess max-threads 1: 4 test(s)
  raven-railgun-cli::auto_spawn_races concurrent_chain_event_floods_dedupe_to_one_spawn
  raven-railgun-cli::auto_spawn_races kill_during_spawn::after_add_live_before_log_kill_leaves_orphan_engine_no_log
  raven-railgun-cli::migrate_encoder_real_sigkill real_sigkill_at_post_manifest_bump_yields_fully_migrated_state
  raven-railgun-cli::migrate_encoder_real_sigkill real_sigkill_at_post_re_encode_no_disk_mutation_then_resume_succeeds
group planted-empty-group max-threads 1: 0 test(s)
group planted-single-group max-threads 2: 1 test(s)
  raven-railgun-cli::bootstrap_from_subsquid bootstrap_concurrent_run_lock_contention"
  for release in 0.9.129 0.9.146; do
    version="cargo-nextest ${release}"
    if out=$(bash scripts/check-ci-filter-names.sh --show-config-fixture "$version" "${dir}/nextest-${release}.txt" 2>&1) \
        && [ "$out" = "$want" ]; then
      echo "  ok: show-config shape of ${release} -> the same groups and members"
    else
      echo "SELFTEST FAIL: show-config output of ${release} is misread" >&2
      diff <(printf '%s\n' "$want") <(printf '%s\n' "$out") >&2
      bad=1
    fi
  done
  version="cargo-nextest 0.9.999-planted"
  if out=$(bash scripts/check-ci-filter-names.sh --show-config-fixture "$version" "${dir}/unknown-override-shape.txt" 2>&1); then
    echo "SELFTEST FAIL: an unknown show-config line was accepted" >&2
    bad=1
  elif ! /usr/bin/grep -qF -- "${version}: its show-config output is not the shape this gate reads" <<< "$out"; then
    echo "SELFTEST FAIL: an unknown show-config line failed without naming the release: ${out}" >&2
    bad=1
  else
    echo "  ok: unknown show-config line -> fails naming ${version}"
  fi
  return "$bad"
}

# `--selected` asks nextest, so it is proven where the test binaries are built, not in the hygiene
# job. It reads copies through FILTER_GATE_*: nothing tracked is mutated on this path.
if [ "${1:-}" = "--selected" ]; then
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  adapter=adapters/railgun/.config/nextest.toml
  real_configs=".config/nextest.toml=Cargo.toml ${adapter}=adapters/railgun/Cargo.toml"
  fails=0

  # One red run carries all seven plants - each gate run lists every binary ~80 times - and each
  # headline is asserted by itself, so one check going quiet cannot hide behind the other six.
  # The chaos group loses wal_chaos_layer_b: the regression the group exists to prevent.
  sed -e 's/^\[test-groups\]$/[test-groups]\nplanted-empty-group = { max-threads = 1 }\nplanted-single-group = { max-threads = 1 }/' \
      -e 's/ + binary(wal_chaos_layer_b)"$/"/' "$adapter" > "$scratch/nextest.toml"
  if cmp -s "$adapter" "$scratch/nextest.toml" || /usr/bin/grep -q 'binary(wal_chaos_layer_b)' "$scratch/nextest.toml"; then
    echo "SELFTEST CANNOT RUN: the plants no longer apply to ${adapter}" >&2
    exit 1
  fi
  cat >> "$scratch/nextest.toml" <<'PLANT'

[[profile.default.overrides]]
filter = "test(/no_such_test_planted/)"
retries = 0

[[profile.default.overrides]]
filter = "test(=bootstrap_concurrent_run_lock_contention)"
test-group = "planted-single-group"
PLANT
  cp .github/workflows/ci.yml "$scratch/ci.yml"
  cat >> "$scratch/ci.yml" <<'PLANT'
  planted-dead-regex-term:
    runs-on: ubuntu-latest
    steps:
      - run: cargo nextest run --manifest-path adapters/railgun/Cargo.toml --cargo-profile ci-test -E 'test(/./) + test(/no_such_test_planted/)'
  planted-shell-variable-filter:
    runs-on: ubuntu-latest
    steps:
      - run: cargo nextest run --manifest-path adapters/railgun/Cargo.toml --cargo-profile ci-test -E "$FILTER"
  planted-dead-alternative:
    runs-on: ubuntu-latest
    steps:
      - run: cargo nextest run --manifest-path adapters/railgun/Cargo.toml --cargo-profile ci-test -E 'test(/kill_during_spawn|no_such_alternative_planted/)'
PLANT

  echo "check-ci-filter-names-selftest.sh --selected: seven plants the gate must name, then the control"
  red=$(FILTER_GATE_WORKFLOW="$scratch/ci.yml" \
        FILTER_GATE_NEXTEST_CONFIGS=".config/nextest.toml=Cargo.toml $scratch/nextest.toml=adapters/railgun/Cargo.toml" \
        bash scripts/check-ci-filter-names.sh --selected 2>&1 > /dev/null)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: the planted copies did not trip the gate (exit 0)" >&2
    fails=1
  fi
  while IFS= read -r headline; do
    if /usr/bin/grep -qF -- "$headline" <<< "$red"; then
      echo "  ok: named -> ${headline}"
    else
      echo "SELFTEST FAIL: the gate did not report '${headline}'" >&2
      fails=1
    fi
  done <<EXPECTED
FILTER SELECTS NOTHING: $scratch/nextest.toml profile.default.overrides
TEST GROUP HOLDS NOTHING: $scratch/nextest.toml test-groups.planted-empty-group
FILTER TERM SELECTS NOTHING: $scratch/ci.yml planted-dead-regex-term
FILTER NOT EVALUATED: $scratch/ci.yml planted-shell-variable-filter
FILTER ALTERNATIVE SELECTS NOTHING: $scratch/ci.yml planted-dead-alternative
TEST GROUP CONSTRAINS NOTHING: $scratch/nextest.toml test-groups.planted-single-group
SPAWN AND KILL TEST NOT SERIALISED: $scratch/nextest.toml raven-railgun-persistence::wal_chaos_layer_b
EXPECTED
  # exactly the seven: a gate that fails everything would name them too
  named=$(/usr/bin/grep -cE '^[A-Z][A-Z ]+: ' <<< "$red" || true)
  if [ "$named" -ne 7 ]; then
    echo "SELFTEST FAIL: expected exactly 7 failures from 7 plants, the gate reported ${named}" >&2
    printf '%s\n' "$red" >&2
    fails=1
  fi

  show_config_fixtures || fails=1

  # the same overrides aimed at the real files: if this is red, the run above proved nothing
  if FILTER_GATE_WORKFLOW=.github/workflows/ci.yml FILTER_GATE_NEXTEST_CONFIGS="$real_configs" \
       bash scripts/check-ci-filter-names.sh --selected > /dev/null 2>&1; then
    echo "  ok: unmutated tree -> exit 0"
  else
    echo "SELFTEST FAIL: --selected rejects the UNMUTATED tree" >&2
    fails=1
  fi

  if [ "$fails" -ne 0 ]; then
    echo "check-ci-filter-names-selftest.sh --selected: the gate is not discriminating." >&2
    exit 1
  fi
  echo "check-ci-filter-names-selftest.sh --selected: all cases behaved as required."
  exit 0
fi

CI=.github/workflows/ci.yml
BAK=$(mktemp)
cp "$CI" "$BAK"
# Case 5 hides a real test file, so its restore is part of the same trap.
VICTIM=adapters/railgun/engine/tests/t1_status_closure.rs
VBAK=$(mktemp)
cp "$VICTIM" "$VBAK"
# Restore installed BEFORE any mutation: a killed run must not leave one applied.
trap 'cp "$BAK" "$CI"; cp "$VBAK" "$VICTIM"; rm -f "$BAK" "$VBAK"' EXIT

fails=0
expect_fail() {
  local label="$1"
  # a sed whose pattern left the workflow proves nothing: the gate passes an unmutated file
  if [ "${2:-}" != "workflow-untouched" ] && cmp -s "$BAK" "$CI"; then
    echo "SELFTEST CANNOT RUN: ${label}: the mutation no longer applies to ${CI}" >&2
    fails=1
    return
  fi
  bash scripts/check-ci-filter-names.sh > /dev/null 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: ${label} did not trip the gate (exit 0)" >&2
    fails=1
  else
    echo "  ok: ${label} -> exit ${rc}"
  fi
  cp "$BAK" "$CI"
}

echo "check-ci-filter-names-selftest.sh: six cases the gate must fail on, submodule cases, then the classifier fixtures"

sed -i 's/test(insert_rejects_overflow_past_capacity)/test(insert_rejects_overflow_past_capacity_RENAMED)/' "$CI"
expect_fail "a test() term renamed to a nonexistent test (uppercase in the name)"

sed -i 's/test(insert_rejects_overflow_past_capacity)/test(no_such_test_anywhere)/' "$CI"
expect_fail "a test() term renamed to a nonexistent test (lowercase)"

sed -i 's/binary(engine_dedup_extends_to_encoder)/binary(a_target_that_does_not_exist)/' "$CI"
expect_fail "a binary() term naming a deleted target"

sed -i '/-p raven-railgun-testkit/d' "$CI"
expect_fail "a workspace member dropped from every -p list"

cp scripts/fixtures/check-ci-filter-names/workspace-member-outside-lanes.yml "$CI"
expect_fail "a workspace member named only outside the fmt and test jobs"

# Case 6: the file a binary() names is deleted in the WORKING TREE but still in the index -
# exactly what an uncommitted lane deletion looks like. The gate's first version resolved
# names with `git ls-files`, which answers from the index, so it stayed green while the
# nightly lane would have died at nextest exit 94. ci.yml is untouched here on purpose:
# the mutation is the missing file, not the filter.
rm -f "$VICTIM"
expect_fail "a binary() whose file is deleted in the working tree but still in the index" workflow-untouched
cp "$VBAK" "$VICTIM"

# Submodules. A name defined only inside one must resolve, and discovery must list its nextest
# config: a top-level git listing never enters a submodule, so both were blind to them once.
printf '# test(consume_both) binary(consume_both)\n' >> "$CI"
if [ ! -f adapters/eth-state/tests/consume_both.rs ]; then
  echo "SELFTEST CANNOT RUN: adapters/eth-state/tests/consume_both.rs is gone" >&2
  fails=1
elif bash scripts/check-ci-filter-names.sh > /dev/null 2>&1; then
  echo "  ok: test() and binary() defined only inside a submodule -> resolve"
else
  echo "SELFTEST FAIL: a name defined only inside the adapters/eth-state submodule is a leak" >&2
  fails=1
fi
cp "$BAK" "$CI"
if bash scripts/check-ci-filter-names.sh --nextest-configs 2>/dev/null \
     | /usr/bin/grep -qx 'adapters/eth-state/.config/nextest.toml=adapters/eth-state/Cargo.toml'; then
  echo "  ok: discovery lists the adapters/eth-state submodule's nextest config"
else
  echo "SELFTEST FAIL: discovery does not list adapters/eth-state/.config/nextest.toml" >&2
  fails=1
fi

# An uninitialised submodule, in a scratch superproject so nothing real is emptied: every pass
# refuses it by name, and once checked out its configs are discovered, nested ones included.
sub=$(mktemp -d)
trap 'cp "$BAK" "$CI"; cp "$VBAK" "$VICTIM"; rm -rf "$BAK" "$VBAK" "$sub"' EXIT
mkdir -p "$sub/scripts" "$sub/.config" "$sub/mod/inner/.config"
cp scripts/check-ci-filter-names.sh "$sub/scripts/"
: > "$sub/ci.yml"
: > "$sub/.config/nextest.toml"
git -C "$sub" init -q
git -C "$sub" update-index --add --cacheinfo "160000,$(printf '%040d' 1),mod"
for mode in names --nextest-configs --selected; do
  arg=$mode; [ "$mode" = names ] && arg=
  # shellcheck disable=SC2086
  if out=$(FILTER_GATE_WORKFLOW="$sub/ci.yml" bash "$sub/scripts/check-ci-filter-names.sh" $arg 2>&1); then
    echo "SELFTEST FAIL: ${mode} accepted an uninitialised submodule" >&2
    fails=1
  elif ! /usr/bin/grep -qF 'submodule mod is not checked out' <<< "$out"; then
    echo "SELFTEST FAIL: ${mode} failed on an uninitialised submodule without naming it: ${out}" >&2
    fails=1
  else
    echo "  ok: ${mode} with an uninitialised submodule -> refuses, naming it"
  fi
done
git -C "$sub/mod" init -q
: > "$sub/mod/inner/.config/nextest.toml"
want=".config/nextest.toml=./Cargo.toml
mod/inner/.config/nextest.toml=mod/inner/Cargo.toml"
got=$(FILTER_GATE_WORKFLOW="$sub/ci.yml" bash "$sub/scripts/check-ci-filter-names.sh" --nextest-configs 2>&1)
if [ "$got" = "$want" ]; then
  echo "  ok: checked-out submodule -> its nested nextest config is discovered"
else
  echo "SELFTEST FAIL: discovery in a checked-out submodule is wrong" >&2
  diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") >&2
  fails=1
fi
rm -rf "$sub"

# The spawn-and-kill classifier --selected uses, on fixtures: every verdict must match.
fixtures=scripts/fixtures/check-ci-filter-names/spawn-and-kill
expected="spawns and kills: ${fixtures}/drop-then-kill.rs
does not: ${fixtures}/kill-in-comment-and-string.rs
spawns and kills: ${fixtures}/kills-in-module.rs
spawns and kills: ${fixtures}/kills-in-test.rs
does not: ${fixtures}/kills-only-in-drop.rs
does not: ${fixtures}/kills-without-spawn.rs
spawns and kills: ${fixtures}/path-module.rs
does not: ${fixtures}/spawn-named-only-in-comment.rs"
roots=$(sed -E 's/^[a-z ]+: //' <<< "$expected")
# shellcheck disable=SC2086
got=$(bash scripts/check-ci-filter-names.sh --spawn-and-kill $roots 2>&1)
if [ "$got" = "$expected" ]; then
  echo "  ok: spawn-and-kill classifier -> all $(wc -l <<< "$expected") fixture verdicts"
else
  echo "SELFTEST FAIL: the spawn-and-kill classifier disagrees with its fixtures" >&2
  diff <(printf '%s\n' "$expected") <(printf '%s\n' "$got") >&2
  fails=1
fi

show_config_fixtures || fails=1

# And the control: unmutated, the gate must PASS. A gate that always fails is not a gate.
bash scripts/check-ci-filter-names.sh > /dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "SELFTEST FAIL: the gate rejects the UNMUTATED tree (exit ${rc})" >&2
  fails=1
else
  echo "  ok: unmutated tree -> exit 0"
fi

if [ "$fails" -ne 0 ]; then
  echo "check-ci-filter-names-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-ci-filter-names-selftest.sh: all cases behaved as required."

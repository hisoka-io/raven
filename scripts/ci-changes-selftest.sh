#!/usr/bin/env bash
# Red-proof for ci-changes.sh. A wrong rule skips a gate on exactly the change it guards, and a
# skipped job reads as green, so the rules are proven three ways:
#   - fixtures: change sets whose selected jobs are known, each asserted as an exact set;
#   - the workflow: every job either reads one of the selector's outputs or is one of the jobs that
#     always run, every output is read, every read fails open, and every manifest a job names is one
#     its output was computed from;
#   - the sources: a file a Rust source include!s, or joins onto CARGO_MANIFEST_DIR, is an input of
#     every job its source is.
# Then the CI mode on synthetic events, and the fail-open paths. Needs cargo (metadata only).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

GATE=scripts/ci-changes.sh
CI=.github/workflows/ci.yml
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
bad() { echo "SELFTEST FAIL: $*" >&2; fails=1; }

keys=$(bash "$GATE" --keys) || { echo "SELFTEST CANNOT RUN: ${GATE} --keys failed" >&2; exit 1; }

# expect <label> <comma-separated keys that must be true, or ALL, or NONE> <path>...
expect() {
  local label="$1" want="$2"; shift 2
  printf '%s\n' "$@" > "$work/paths"
  local got
  got=$(bash "$GATE" --paths "$work/paths" 2>&1 | awk -F= '$2 == "true" { print $1 }' | paste -sd, -)
  case "$want" in
    ALL) want=$(paste -sd, <<< "$keys") ;;
    NONE) want="" ;;
  esac
  want=$(tr ',' '\n' <<< "$want" | /usr/bin/grep -v '^$' | sort | paste -sd, -)
  got=$(tr ',' '\n' <<< "$got" | /usr/bin/grep -v '^$' | sort | paste -sd, -)
  if [ "$got" = "$want" ]; then
    echo "  ok: ${label} -> ${got:-no filtered job}"
  else
    bad "${label}: selected '${got}', expected '${want}'"
  fi
}

echo "ci-changes-selftest.sh: fixtures, the workflow, the sources, CI mode"

RAILGUN_SET=docs,railgun,msrv_1_89,msrv_1_91,sdk
expect "docs only" NONE README.md SECURITY.md CONTRIBUTING.md adapters/railgun/ppoi-replay/README.md
expect "the SDK only" sdk adapters/railgun/sdk/src/client-pir.ts adapters/railgun/sdk/package.json
expect "the SDK README ships in the package" sdk adapters/railgun/sdk/README.md
expect "an SDK gate script" sdk adapters/railgun/scripts/check-sdk-pack.sh
expect "an SDK fixture adapter tests include" "$RAILGUN_SET" adapters/railgun/sdk/tests/fixtures/path10_row.hex
expect "an adapter crate" "$RAILGUN_SET" adapters/railgun/engine/src/lib.rs
expect "the adapter core the client wasm links" "$RAILGUN_SET,wasm" adapters/railgun/core/src/lib.rs
expect "the adapter's nextest config" "$RAILGUN_SET,lane_counts" adapters/railgun/.config/nextest.toml
expect "an adapter example config its tests read" "$RAILGUN_SET" adapters/railgun/examples/mainnet-ppoi.toml
expect "the client wasm" wasm,msrv_1_89,sdk adapters/railgun/client-wasm/src/lib.rs
expect "one detached workspace" bench_compare,bench_gate,msrv_1_89 tools/bench-compare/src/main.rs
expect "the committed bench baselines" bench_compare,bench_gate benches/baselines/b1-two-packing-cell-2e16x32.json
expect "the eth-state submodule" eth_state,msrv_1_91 adapters/eth-state
expect "the inspire submodule" root,docs,wasm,railgun,inspire,eth_state,b1_bench,bench_gate,msrv_1_89,msrv_1_91,sdk crates/inspire
expect "a framework crate" root,docs,wasm,railgun,eth_state,msrv_1_89,msrv_1_91,sdk crates/core/src/lib.rs
expect "the root lockfile" root,docs,wasm,msrv_1_89 Cargo.lock
expect "the howl submodule, which no workspace depends on" NONE adapters/howl
expect "the workflow" ALL .github/workflows/ci.yml
expect "the lane pins" ALL .github/expected-lane-counts.tsv
expect "a gate script" ALL scripts/assert-lane-counts.sh
expect "the toolchain pin" ALL rust-toolchain.toml
expect "the cargo config" ALL .cargo/config.toml
expect "a path no rule claims" ALL a-new-top-level-dir/file.txt
expect "docs beside a Rust change" "$RAILGUN_SET" README.md adapters/railgun/http/src/lib.rs

# --- the workflow -------------------------------------------------------------------------------
bash "$GATE" --manifests > "$work/manifests"
check_workflow() {  # check_workflow <workflow>: the selector's contract with that file
python3 - "$1" "$work/manifests" <<'PY'
import re, shlex, sys, yaml

workflow, manifests_file = sys.argv[1], sys.argv[2]
doc = yaml.safe_load(open(workflow))
jobs = doc["jobs"]
manifests = {}
for line in open(manifests_file):
    key, _, rest = line.rstrip("\n").partition("\t")
    manifests[key] = set(rest.split())
# always run: cheap, or already scheduled on their own terms
UNFILTERED = {"changes", "hygiene", "advisories", "secret-scan", "production-cell-closure"}
READ = re.compile(r"needs\.changes\.outputs\.([A-Za-z0-9_]+)\s*(==|!=)\s*'([^']*)'")
errors = []

declared = set((jobs.get("changes") or {}).get("outputs") or {})
if declared != set(manifests):
    errors.append(f"changes job outputs {sorted(declared)} are not the selector's keys {sorted(manifests)}")
for key in declared:
    if jobs["changes"]["outputs"][key].replace(" ", "") != "${{steps.select.outputs.%s}}" % key:
        errors.append(f"changes output {key} is not steps.select.outputs.{key}")

used = set()
for name, job in jobs.items():
    text = yaml.safe_dump(job, width=10**6)
    reads = READ.findall(text)
    for key, op, value in reads:
        used.add(key)
        if key not in manifests:
            errors.append(f"{name}: reads an output the selector does not write: {key}")
        if (op, value) != ("!=", "false"):
            errors.append(f"{name}: tests {key} {op} '{value}'; only != 'false' fails open")
    if name in UNFILTERED:
        if reads:
            errors.append(f"{name}: listed as always-run but reads the selector")
        continue
    if not reads:
        errors.append(f"{name}: reads no selector output and is not an always-run job; "
                      "add it to a key in scripts/ci-changes.sh, or to UNFILTERED here")
        continue
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    if "changes" not in needs:
        errors.append(f"{name}: reads the selector without needing the changes job")
    job_keys = {k for k, _, _ in reads}
    covered = set().union(*(manifests[k] for k in job_keys if k in manifests))
    # every manifest the job's commands name must be one its key was computed from
    runs = "\n".join((s.get("run") or "") for s in job.get("steps") or [])
    runs = runs.replace("\\\n", " ")
    env = job.get("env") or {}
    named = set(str(env.get("MSRV_MANIFESTS", "")).split("|")) - {""}
    for command in re.split(r"\n|&&|;", runs):
        if command.lstrip().startswith("#"):
            continue
        try:
            tokens = shlex.split(command, comments=True)
        except ValueError:
            tokens = command.split()
        for i, token in enumerate(tokens):
            if token == "--manifest-path" and i + 1 < len(tokens) and not tokens[i + 1].startswith("$"):
                named.add(tokens[i + 1])
            elif token.startswith("--manifest-path="):
                named.add(token.split("=", 1)[1])
        if (len(tokens) > 1 and tokens[0] == "cargo"
                and tokens[1] in ("check", "clippy", "test", "doc", "fmt", "build", "nextest")
                and not any(t.startswith("--manifest-path") for t in tokens)):
            named.add("Cargo.toml")
    for manifest in sorted(named - covered):
        errors.append(f"{name}: builds {manifest}, which no output it reads was computed from")

for key in sorted(set(manifests) - used):
    errors.append(f"output {key} is read by no job")

for error in errors:
    print(f"  {error}", file=sys.stderr)
sys.exit(1 if errors else 0)
PY
}
if ! check_workflow "$CI"; then
  bad "the workflow and the selector disagree (above)"
else
  echo "  ok: every job reads a selector output or always runs, each read fails open, and each named manifest is covered"
fi

# The same check must be able to fail: a job that reads nothing, and a read that fails closed.
sed -e "s/needs.changes.outputs.bench_gate != 'false'/true/" "$CI" > "$work/ci-unread.yml"
sed -e "s/needs.changes.outputs.inspire != 'false'/needs.changes.outputs.inspire == 'true'/" "$CI" > "$work/ci-closed.yml"
for plant in ci-unread:"reads no selector output" ci-closed:"only != 'false' fails open"; do
  file=${plant%%:*} needle=${plant#*:}
  if cmp -s "$CI" "$work/$file.yml"; then
    bad "plant ${file} no longer applies to ${CI}"
  elif out=$(check_workflow "$work/$file.yml" 2>&1); then
    bad "plant ${file} passed the workflow check"
  elif ! /usr/bin/grep -qF -- "$needle" <<< "$out"; then
    bad "plant ${file} failed without saying '${needle}'"
  else
    echo "  ok: planted ${file} -> refused: ${needle}"
  fi
done

# --- the sources ----------------------------------------------------------------------------------
# A path a Rust file reads through include_str!/include_bytes!, or joins onto CARGO_MANIFEST_DIR,
# must be an input of every job that compiles the read: a job building the reader's crate's tests,
# or any job building the crate at all when the read sits outside tests/, benches/, examples/ and
# #[cfg(test)]. Otherwise changing only that file skips the job.
bash "$GATE" --members > "$work/members"
python3 - "$work/reads" <<'PY'
import os, re, subprocess, sys
INCLUDE = re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"\s*\)')
JOIN = re.compile(r'CARGO_MANIFEST_DIR"\)\s*\)\s*\.join\(\s*"([^"]+)"\s*\)')
TEST_MOD = re.compile(r'#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{')


def test_regions(text):
    regions = []
    for m in TEST_MOD.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        regions.append((m.start(), i))
    return regions


roots = [""] + [line.split("\t", 1)[1] for line in subprocess.run(
    ["git", "ls-files", "--stage"], capture_output=True, text=True, check=True).stdout.splitlines()
    if line.startswith("160000 ")]
with open(sys.argv[1], "w") as out:
    for root in roots:
        listing = subprocess.run(["git", "-C", root or ".", "ls-files", "--", "*.rs"],
                                 capture_output=True, text=True)
        for rel in listing.stdout.splitlines():
            path = os.path.join(root, rel) if root else rel
            try:
                text = open(path, encoding="utf-8").read()
            except OSError:
                continue
            crate = os.path.dirname(path)
            while crate and not os.path.isfile(os.path.join(crate, "Cargo.toml")):
                crate = os.path.dirname(crate)
            inside = os.path.relpath(path, crate or ".").split(os.sep)[0]
            regions = test_regions(text)
            for pattern, base in ((INCLUDE, os.path.dirname(path)), (JOIN, crate)):
                for m in pattern.finditer(text):
                    test_only = inside in ("tests", "benches", "examples") or any(
                        a <= m.start() < b for a, b in regions)
                    target = os.path.normpath(os.path.join(base, m.group(1)))
                    out.write(f"{path}\t{target}\t{crate or '.'}\t{'test' if test_only else 'lib'}\n")
PY
uncovered() {  # uncovered <reads>: each read whose target a compiling job's key does not hold
  cut -f1 "$1" > "$work/readers"
  cut -f2 "$1" > "$work/targets"
  bash "$GATE" --claims "$work/readers" > "$work/reader-claims"
  bash "$GATE" --claims "$work/targets" > "$work/target-claims"
  python3 - "$1" "$work/reader-claims" "$work/target-claims" "$work/members" <<'PY'
import sys
reads = [l.rstrip("\n").split("\t") for l in open(sys.argv[1])]
readers = [l.rstrip("\n").split("\t")[1] for l in open(sys.argv[2])]
targets = [l.rstrip("\n").split("\t")[1] for l in open(sys.argv[3])]
members = {k: set(v.split()) for k, _, v in (l.rstrip("\n").partition("\t") for l in open(sys.argv[4]))}
for (path, target, crate, kind), have_r, have_t in zip(reads, readers, targets):
    have_t = set(have_t.split(",")) - {""}
    for key in filter(None, have_r.split(",")):
        compiled = kind == "lib" or crate in members.get(key, set())
        if compiled and key not in have_t:
            print(f"  {path} reads {target}, which job key {key} does not hold")
PY
}
missing=$(uncovered "$work/reads")
# red-proof: an adapter test that reads a README, which no job holds, and a framework lib that
# reads an SDK fixture, which the adapter jobs hold and the root build does not
printf '%s\n' "adapters/railgun/engine/tests/planted.rs	README.md	adapters/railgun/engine	test" \
  "crates/core/src/planted.rs	adapters/railgun/sdk/tests/fixtures/planted.hex	crates/core	lib" > "$work/planted-reads"
planted=$(uncovered "$work/planted-reads")
if /usr/bin/grep -qF "planted.rs reads README.md, which job key railgun does not hold" <<< "$planted" \
   && /usr/bin/grep -qF "crates/core/src/planted.rs reads adapters/railgun/sdk/tests/fixtures/planted.hex, which job key root does not hold" <<< "$planted"; then
  echo "  ok: planted out-of-crate reads -> named"
else
  bad "planted out-of-crate reads were not named: ${planted}"
fi
reads=$(wc -l < "$work/reads")
if [ "$reads" -lt 10 ]; then
  bad "only ${reads} out-of-crate reads found; the scan has gone blind"
elif [ -n "$missing" ]; then
  bad "a file a Rust source reads is missing from its jobs' inputs:"
  printf '%s\n' "$missing" >&2
else
  echo "  ok: every file one of ${reads} include!/CARGO_MANIFEST_DIR reads names is an input of its reader's jobs"
fi

# --- CI mode --------------------------------------------------------------------------------------
event() {  # event <name> <json> -> key=value lines on stdout, notes on stderr
  printf '%s\n' "$2" > "$work/event.json"
  : > "$work/output"
  GITHUB_EVENT_NAME="$1" GITHUB_EVENT_PATH="$work/event.json" GITHUB_OUTPUT="$work/output" \
    GITHUB_STEP_SUMMARY="$work/summary" GITHUB_SHA="$(git rev-parse HEAD)" bash "$GATE" 2>"$work/notes"
}
all_true() { [ "$(/usr/bin/grep -c '=true$' "$work/output")" -eq "$(wc -l <<< "$keys")" ]; }
all_false() { [ "$(/usr/bin/grep -c '=false$' "$work/output")" -eq "$(wc -l <<< "$keys")" ]; }

head=$(git rev-parse HEAD)
event schedule '{}' > /dev/null
all_true && echo "  ok: a nightly run selects every job" || bad "a schedule event did not select every job"
push="{\"ref\":\"refs/heads/main\",\"after\":\"${head}\"}"
CI_CHANGES_LAST_GREEN="" event push "$push" > /dev/null
all_true && echo "  ok: a branch with no green run selects every job" || bad "no green run did not select every job"
CI_CHANGES_LAST_GREEN="$(printf '%040d' 7)" event push "$push" > /dev/null
all_true && echo "  ok: a last green commit missing from the clone selects every job" \
  || bad "a last green commit absent from the clone did not select every job"
(unset CI_CHANGES_LAST_GREEN GH_TOKEN; event push "$push" > /dev/null)
all_true && echo "  ok: no way to ask the runs API selects every job" || bad "an unanswerable runs API did not select every job"
CI_CHANGES_LAST_GREEN="$head" event push "$push" > /dev/null
if all_false && /usr/bin/grep -q '^0 changed path' "$work/notes"; then
  echo "  ok: a push with nothing since the last green run selects no filtered job, and says it diffed"
else
  bad "a push at its last green commit was not diffed to zero paths"; cat "$work/notes" >&2
fi
event pull_request "{\"pull_request\":{\"base\":{\"sha\":\"${head}\"},\"head\":{\"sha\":\"${head}\"}}}" > /dev/null
all_false && echo "  ok: a pull request is diffed from its merge base" || bad "an empty pull request was not diffed"
[ "$(wc -l < "$work/output")" -eq "$(wc -l <<< "$keys")" ] || bad "GITHUB_OUTPUT does not carry one line per key"
# A real range, when the clone holds one: the head commit against its parent.
if parent=$(git rev-parse -q --verify HEAD~1 2>/dev/null); then
  CI_CHANGES_LAST_GREEN="$parent" event push "$push" > /dev/null
  if /usr/bin/grep -q "^$(git diff --name-only --no-renames "$parent" HEAD | wc -l) changed path" "$work/notes"; then
    echo "  ok: the head commit is diffed against its parent ($(head -n 1 "$work/notes"))"
  else
    bad "the head commit was not diffed against its parent"; cat "$work/notes" >&2
  fi
fi

# Fails open when cargo cannot answer, never closed.
printf 'adapters/railgun/engine/src/lib.rs\n' > "$work/paths"
if CI_CHANGES_CARGO=false bash "$GATE" --paths "$work/paths" | /usr/bin/grep -q '=false$'; then
  bad "a cargo metadata failure left a job unselected"
else
  echo "  ok: a cargo metadata failure selects every job"
fi

if [ "$fails" -ne 0 ]; then
  echo "ci-changes-selftest.sh: the job selector is not proven." >&2
  exit 1
fi
echo "ci-changes-selftest.sh: all cases behaved as required."

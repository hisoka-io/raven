#!/usr/bin/env bash
#
# Red-proof for check-repo-hygiene.sh: a gate ships with proof it can fail.
#
# The gate carried four checks and no red-proof. One of them - the tracked-file label scan -
# printed its hits and exited 0, because `xargs` returns 123 when any batch's grep matches
# nothing, so testing the pipeline's status passes as soon as the file list needs two
# batches. That failure mode is invisible on a small repository and arrives silently as the
# repository grows, which is why the clean-tree case alone proves nothing.
#
# Runs in a scratch clone so the real tree is never mutated.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/check-repo-hygiene.sh"
failed=0
cases=0

check() {
  local want="$1" got="$2" what="$3"
  cases=$((cases + 1))
  if [[ "$want" == "$got" ]]; then
    echo "  ok    $what (exit $got)"
  else
    echo "  FAIL  $what: expected exit $want, got $got"
    failed=1
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Tracked files at their WORKING-TREE content, not `git archive HEAD`. The gate scans what
# `git ls-files` lists on disk now, so seeding from HEAD gives this proof a DIFFERENT ORACLE
# than the thing it validates: an uncommitted leak reads here as "a clean tree passes" while
# the real gate refuses. Measured before the fix - the gate exited 1 on a working-tree label
# and this file still reported every case green.
( cd "$ROOT" && git ls-files -z | while IFS= read -r -d '' tracked_file; do
    if [[ -e "$tracked_file" || -L "$tracked_file" ]]; then
      printf '%s\0' "$tracked_file"
    fi
  done | tar --null -T - -cf - ) | tar -xf - -C "$work"
git -C "$work" init -q .
git -C "$work" add -A >/dev/null 2>&1
cp "$GATE" "$work/scripts/check-repo-hygiene.sh"

run_gate() { ( cd "$work" && ./scripts/check-repo-hygiene.sh >/dev/null 2>&1; echo $?; ); }
# A plant must be TRACKED to be seen: the scans are driven by `git ls-files`, so writing a
# file without adding it tests nothing.
plant() { printf '%s\n' "$2" >> "$work/$1"; git -C "$work" add "$1" >/dev/null 2>&1; }
# A file that did not exist at HEAD must be removed from the INDEX as well as from disk:
# `git checkout --` restores an added-but-new file from the index and leaves the plant in
# place, which silently poisons every later case.
unplant() {
  if git -C "$work" cat-file -e "HEAD:$1" 2>/dev/null; then
    git -C "$work" checkout -- "$1"
  else
    git -C "$work" rm -f --cached "$1" >/dev/null 2>&1 || true
    rm -f "$work/$1"
  fi
  git -C "$work" add -A >/dev/null 2>&1
}

echo "check-repo-hygiene selftest:"
check 0 "$(run_gate)" "a clean tree passes"

# The label class, in each file type it actually leaked from. Eight of the ten historical
# leaks were .yml, .md and .sh, none of which the adapter's *.rs scan can see.
for f in .github/workflows/ci.yml README.md scripts/bench-gate.sh; do
  plant "$f" "# B-123 leaked into shipped prose"
  check 1 "$(run_gate)" "a ledger label in ${f##*/} is refused"
  unplant "$f"
done

plant crates/core/src/lib.rs "// G-456 in framework source"
check 1 "$(run_gate)" "a ledger label in a .rs file is refused"
unplant crates/core/src/lib.rs

# A NEW tracked file, so the scan is exercised at a file list it did not start with.
plant docs-probe.md "M-789 in a file the gate has never seen"
check 1 "$(run_gate)" "a ledger label in a newly added file is refused"
unplant docs-probe.md

# Negative controls: shapes that must NOT trip the label pattern.
plant README.md "See CVE-2024-1234 and RFC-7539 for details."
check 0 "$(run_gate)" "(control) CVE and RFC identifiers are not ledger labels"
unplant README.md

plant README.md "Tracked as T-4 in the risk register."
check 0 "$(run_gate)" "(control) a single-digit tag is not a ledger label"
unplant README.md

# The security claim, check 3 - the one that works today only because every .md fits one
# xargs batch.
plant README.md "This build provides 128-bit security."
check 1 "$(run_gate)" "a 128-bit security claim is refused"
unplant README.md

# An owned submodule: a checkout of its own, recorded in the parent only as a gitlink. The parent
# `git ls-files` lists that gitlink as a path with no file behind it, and grep handed a directory
# poisons the pipeline's status - the condition that once made the whole-tree scan unable to fire.
# The scratch copy flattens the real submodules into plain files, so this one is built here.
# Its index is enough: nothing here needs a commit, and the truncation check skips a file with no
# HEAD blob.
owned=adapters/probe-owned
mkdir -p "$work/$owned"
git -C "$work/$owned" init -q .
sub_unplant() {
  printf 'pub fn probe() {}\n' > "$work/$owned/lib.rs"
  printf '# probe\n' > "$work/$owned/README.md"
  git -C "$work/$owned" add -A >/dev/null 2>&1
}
sub_plant() { printf '%s\n' "$2" >> "$work/$owned/$1"; git -C "$work/$owned" add "$1" >/dev/null 2>&1; }
sub_unplant
git -C "$work" update-index --add --cacheinfo 160000,0000000000000000000000000000000000000001,"$owned"

check 0 "$(run_gate)" "(control) a clean owned submodule passes"

plant README.md "B-123 with a gitlink in the file list"
check 1 "$(run_gate)" "a label is still caught when a submodule gitlink is listed"
unplant README.md

sub_plant lib.rs "// G-456 in an owned submodule"
check 1 "$(run_gate)" "a ledger label inside an owned submodule is refused"
sub_unplant lib.rs

sub_plant README.md "This build provides 128-bit security."
check 1 "$(run_gate)" "a 128-bit security claim inside an owned submodule is refused"
sub_unplant README.md

mkdir -p "$work/$owned/probe/wal"
printf '{}\n' > "$work/$owned/probe/manifest.json"
check 1 "$(run_gate)" "an untracked runtime data directory inside an owned submodule is refused"
rm -rf "$work/$owned/probe"

# Not checked out: the directory is there and empty of a repository, so a scan of it would find
# nothing and read clean. It must be refused instead.
mv "$work/$owned/.git" "$work/probe-owned.git"
check 1 "$(run_gate)" "an owned submodule that is not checked out is refused"
mv "$work/probe-owned.git" "$work/$owned/.git"
check 0 "$(run_gate)" "(control) checking it out again clears it"

git -C "$work" update-index --force-remove "$owned" >/dev/null 2>&1
rm -rf "${work:?}/$owned"

# The submodule carries its own history and is corrected through a submodule change.
if [[ -d "$work/crates/inspire" ]]; then
  plant crates/inspire/README.md "B-123 and 128-bit security"
  check 0 "$(run_gate)" "(control) the vendored submodule is exempt"
  unplant crates/inspire/README.md
else
  echo "  ok    (skipped) submodule exemption: crates/inspire absent from the archive"
  cases=$((cases + 1))
fi

# The stray-data-dir class is UNTRACKED by nature -- the scan is `git ls-files --others`, so a
# plant that gets `git add`ed proves nothing and `plant()` above cannot be reused. Both
# directions matter: a manifest ALONE is an ordinary package file and firing on it would make
# the gate useless noise, so the negative case is the one that keeps it honest.
probe_dir="$work/adapters/probe-crate"
mkdir -p "$probe_dir"
printf '{}\n' > "$probe_dir/manifest.json"
check 0 "$(run_gate)" "(control) a manifest with no node state beside it is not a data dir"
mkdir -p "$probe_dir/wal"
check 1 "$(run_gate)" "an untracked runtime data directory in a source tree is refused"
rm -rf "$probe_dir"
check 0 "$(run_gate)" "removing the data directory clears it"

# The reach, not the fingerprint. The three-tree pathspec this replaced matched none of these:
# the repo root is where a binary run by hand leaves its data dir, and `tools/` and `benches/`
# are cargo workspaces whose tests can do exactly what the measured instance did.
for where in . tools/probe-crate benches/probe-crate; do
  mkdir -p "$work/$where/wal"
  printf '{}\n' > "$work/$where/manifest.json"
  check 1 "$(run_gate)" "a runtime data directory at ${where} is refused"
  rm -rf "$work/$where/wal" "$work/$where/manifest.json"
done
# `run/` is the deliberate exception and the control for the whole widening: it is gitignored,
# so `git add -A` cannot commit it, which is the harm this gate exists to prevent. The scan is
# `--exclude-standard` for exactly that reason, and this case proves the widening did not lose it.
mkdir -p "$work/run/wal"
printf '{}\n' > "$work/run/manifest.json"
check 0 "$(run_gate)" "(control) an IGNORED runtime data directory under run/ is not refused"
rm -rf "$work/run"
check 0 "$(run_gate)" "removing them all clears it"

if [[ "$failed" -ne 0 ]]; then
  echo "check-repo-hygiene selftest: FAILED" >&2
  exit 1
fi
echo "check-repo-hygiene selftest: all ${cases} cases behaved as specified"

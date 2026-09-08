#!/usr/bin/env bash
# An #[ignore]d test that no CI lane selects runs NOWHERE. 42 of 72 were in that state when this
# gate was written, and nothing in the system was in a position to notice - which is how the
# tree-4 rollover outage stayed invisible for three days: the test that covered the mechanism was
# ignored, and then excluded by name from the one lane that runs ignored tests.
#
# This gate does not demand zero. It FREEZES the existing set in
# scripts/ignore-coverage-allowlist.txt and fails when a NEW uncovered ignore appears. Debt can
# shrink freely - removing a line means the test gained a lane - and cannot silently grow.
set -uo pipefail
cd "$(dirname "$0")/.."

ALLOW=scripts/ignore-coverage-allowlist.txt
[ -f "$ALLOW" ] || { echo "missing ${ALLOW}" >&2; exit 1; }

current=$(python3 - <<'PY'
import re, subprocess, pathlib
def ignores():
    out = []
    for repo, prefix in ((None, ''), ('crates/inspire', 'crates/inspire/')):
        # --untracked: an ignored test MOVED into a new, not-yet-committed file is invisible to a
        # tracked-only census, so the debt figure silently under-reports and a genuinely uncovered
        # ignore escapes. That happened when the client bench moved from tests/ to benches/.
        cmd = ['git'] + (['-C', repo] if repo else []) \
            + ['grep', '--untracked', '-n', '^\\s*#\\[ignore', '--', '*.rs']
        r = subprocess.run(cmd, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            path, ln, _ = line.split(':', 2)
            out.append((prefix + path, int(ln)))
    return out

ci = pathlib.Path('.github/workflows/ci.yml').read_text()
bins, excluded = set(), set()
for m in re.finditer(r'filter: "((?:[^"\\]|\\.)*)"', ci):
    f = m.group(1)
    bins |= set(re.findall(r'binary\(([A-Za-z_0-9]+)\)', f))
    if ' - (' in f:
        excluded |= set(re.findall(r'test\(([A-Za-z_0-9]+)\)', f.split(' - (', 1)[1]))
for m in re.finditer(r"-E '([^']*)'", ci):
    bins |= set(re.findall(r'binary\(([A-Za-z_0-9]+)\)', m.group(1)))

for path, ln in ignores():
    stem = pathlib.Path(path).stem
    lines = pathlib.Path(path).read_text().splitlines()
    fn = ''
    for nxt in lines[ln:ln + 8]:
        fm = re.search(r'\bfn\s+([a-z_0-9]+)', nxt)
        if fm:
            fn = fm.group(1)
            break
    if not (stem in bins and fn not in excluded):
        print(f"{path}::{fn}")
PY
) || { echo "enumeration failed" >&2; exit 1; }

allowed=$(/usr/bin/grep -v '^#' "$ALLOW" | /usr/bin/grep -v '^$' | sort -u)
new=$(comm -23 <(printf '%s\n' "$current" | sort -u) <(printf '%s\n' "$allowed"))

if [ -n "$new" ]; then
  echo "NEW UNCOVERED IGNORE: these #[ignore]d tests run in no CI lane and are not allowlisted:" >&2
  printf '  %s\n' $new >&2
  echo "" >&2
  echo "Either give the test a lane (add its binary to a --run-ignored filter in ci.yml), or" >&2
  echo "add it to ${ALLOW} with a reason in the commit message." >&2
  exit 1
fi

gone=$(comm -13 <(printf '%s\n' "$current" | sort -u) <(printf '%s\n' "$allowed"))
if [ -n "$gone" ]; then
  echo "note: $(printf '%s\n' $gone | wc -l) allowlisted entries are no longer uncovered." >&2
  echo "      Prune them from ${ALLOW} to keep the debt figure honest:" >&2
  printf '  %s\n' $gone >&2
fi

echo "scripts/check-ignore-coverage.sh: clean ($(printf '%s\n' "$current" | /usr/bin/grep -c . ) uncovered, all allowlisted)."

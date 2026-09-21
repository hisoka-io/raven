#!/usr/bin/env bash
# An #[ignore]d test that no CI lane selects runs NOWHERE. 42 of 72 were in that state when this
# gate was written, and nothing in the system was in a position to notice - which is how the
# tree-4 rollover outage stayed invisible for three days: the test that covered the mechanism was
# ignored, and then excluded by name from the one lane that runs ignored tests.
#
# This gate does not demand zero. It FREEZES the existing set in
# scripts/ignore-coverage-allowlist.txt and fails when a NEW uncovered ignore appears, and when a
# listed one gained a lane and was not removed: the figure it prints is only the real debt while
# the list is exactly the uncovered set.
set -uo pipefail
cd "$(dirname "$0")/.."

# the overrides point a red-proof at copies, so it never has to mutate a tracked file
ALLOW="${IGNORE_COVERAGE_ALLOWLIST:-scripts/ignore-coverage-allowlist.txt}"
[ -f "$ALLOW" ] || { echo "missing ${ALLOW}" >&2; exit 1; }

current=$(python3 - <<'PY'
import os, re, subprocess, pathlib, sys
def ignores():
    out = []
    invalid = []
    trigger = re.compile(
        r'(?i)(trigger\s*:|run manually after|run (?:this )?by hand|run with\b|red until|until\b|'
        r'compiles only under|changing\b|when\b|after intentional|un-?ignore|once\b)'
    )
    for repo, prefix in ((None, ''), ('crates/inspire', 'crates/inspire/')):
        # --untracked: an ignored test MOVED into a new, not-yet-committed file is invisible to a
        # tracked-only census, so the debt figure silently under-reports and a genuinely uncovered
        # ignore escapes. That happened when the client bench moved from tests/ to benches/.
        cmd = ['git'] + (['-C', repo] if repo else []) \
            + ['grep', '--untracked', '-n', '^\\s*#\\[ignore', '--', '*.rs']
        r = subprocess.run(cmd, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            path, ln, _ = line.split(':', 2)
            ln = int(ln)
            lines = pathlib.Path(prefix + path).read_text().splitlines()
            raw = '\n'.join(lines[ln - 1:ln + 15])
            attr = re.match(
                r'\s*#\[ignore(?:\s*=\s*"((?:\\.|[^"\\])*)")?\s*\]',
                raw,
                re.DOTALL,
            )
            reason = attr.group(1) if attr else None
            label = f'{prefix}{path}:{ln}'
            if reason is None or not reason.strip():
                invalid.append(f'{label}: bare #[ignore]')
            elif not trigger.search(reason):
                invalid.append(f'{label}: reason has no citable trigger: {reason!r}')
            out.append((prefix + path, ln))
    if invalid:
        print('INVALID IGNORE REASON:', file=sys.stderr)
        for problem in invalid:
            print(f'  {problem}', file=sys.stderr)
        sys.exit(1)
    return out

ci = pathlib.Path(os.environ.get('IGNORE_COVERAGE_WORKFLOW', '.github/workflows/ci.yml')).read_text()
bins, included, excluded = set(), set(), set()
for pattern in (r'filter: "((?:[^"\\]|\\.)*)"', r"-E '([^']*)'"):
    for m in re.finditer(pattern, ci):
        # a test() term on the INCLUSION side selects as surely as a binary() does; reading only
        # the exclusion side reported a running test as debt
        inclusion, _, exclusion = m.group(1).partition(' - (')
        bins |= set(re.findall(r'binary\(([A-Za-z_0-9]+)\)', inclusion))
        included |= set(re.findall(r'test\(([A-Za-z_0-9]+)\)', inclusion))
        excluded |= set(re.findall(r'test\(([A-Za-z_0-9]+)\)', exclusion))
# a `cargo test -- --ignored --exact NAME` step runs the test as surely as a lane does, and the
# submodule workspaces are driven that way rather than through nextest filters
included |= set(re.findall(r'--exact[ \t]+([A-Za-z_0-9]+)', ci))


def names(terms, fn):
    # nextest matches test(NAME) as a substring of the test name
    return any(term in fn for term in terms)


for path, ln in ignores():
    stem = pathlib.Path(path).stem
    lines = pathlib.Path(path).read_text().splitlines()
    fn = ''
    for nxt in lines[ln:ln + 8]:
        fm = re.search(r'\bfn\s+([a-z_0-9]+)', nxt)
        if fm:
            fn = fm.group(1)
            break
    if not ((stem in bins or names(included, fn)) and not names(excluded, fn)):
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
  echo "STALE ALLOWLIST ENTRY: these are covered by a lane and still counted as debt:" >&2
  printf '  %s\n' $gone >&2
  echo "" >&2
  echo "Delete them from ${ALLOW} in the change that gave them a lane. The figure this gate" >&2
  echo "prints is quoted as the repo's test debt, so a stale line makes it a lie." >&2
  exit 1
fi

echo "scripts/check-ignore-coverage.sh: clean ($(printf '%s\n' "$current" | /usr/bin/grep -c . ) uncovered, all allowlisted)."

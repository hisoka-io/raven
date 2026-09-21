#!/usr/bin/env bash
# Every binary()/test() name in a CI nextest filter must resolve to something in the tree.
#
# nextest 0.9.129 fails loudly when a `binary(X)` names a target that does not exist, but a
# `test(Y)` naming a test that does not exist exits 0 and QUIETLY reduces the run. ci.yml carries
# an additive `test(insert_rejects_overflow_past_capacity)` in the engine-ignored lane: rename that
# unit test and the lane keeps passing while no longer running it.
#
# Measured 2026-09-01, which is why this exists as a gate rather than a comment.
#
# The name classes below are [A-Za-z_0-9], not [a-z_0-9]: the first draft used the narrow class
# and its own red-proof passed, because the mutation renamed a term to something containing an
# uppercase letter and the extraction silently skipped it. A gate that cannot see part of its
# own input is worse than no gate.
#
# Two passes, because they cost differently:
#   (no argument)  name resolution against the working tree. No toolchain, so it runs in the
#                  cheap hygiene job - and it reads only plain test(NAME) / binary(NAME) terms in
#                  the workflow. A regex, glob or package() term is invisible to it.
#   --selected     asks nextest what every declared filter selects, so it sees every filter
#                  syntax nextest does. Reads the workflow AND every .config/nextest.toml: an
#                  override whose filter selects nothing configures nothing, silently. Needs the
#                  test binaries built, like scripts/assert-lane-counts.sh.
#
# FILTER_GATE_WORKFLOW and FILTER_GATE_NEXTEST_CONFIGS ("config=manifest ...") point either pass
# at copies, so a red-proof never has to mutate a tracked file.
set -uo pipefail
cd "$(dirname "$0")/.."
CI="${FILTER_GATE_WORKFLOW:-.github/workflows/ci.yml}"
MODE="${1:-names}"
fail=0

[ -f "$CI" ] || { echo "scripts/check-ci-filter-names.sh: workflow ${CI} does not exist." >&2; exit 1; }

if [ "$MODE" = "--selected" ]; then
  if [ -n "${FILTER_GATE_NEXTEST_CONFIGS:-}" ]; then
    config_specs="$FILTER_GATE_NEXTEST_CONFIGS"
  else
    # The disk, not the index, and untracked files count: the same tree nextest answers from.
    config_specs=$(
      { git ls-files -- '.config/nextest.toml' '*/.config/nextest.toml'
        git ls-files --others --exclude-standard -- '.config/nextest.toml' '*/.config/nextest.toml'
      } | sort -u | while IFS= read -r cfg; do
        [ -f "$cfg" ] || continue
        workspace=$(dirname "$(dirname "$cfg")")
        printf '%s=%s\n' "$cfg" "${workspace}/Cargo.toml"
      done
    )
  fi
  # shellcheck disable=SC2086
  exec python3 - "$CI" $config_specs <<'PY'
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib

import yaml

workflow, config_specs = sys.argv[1], sys.argv[2:]
failures = []


def fail(headline, *detail):
    failures.append("\n".join([headline, *("  " + line for line in detail)]))


OPERATOR_WORDS = {"and", "or", "not"}
WORD = re.compile(r"[a-z_]+")


def split_terms(expr):
    """The leaf predicates of a filterset.

    Finds where each term ends and nothing more; nextest decides what a term matches. Every
    character is accounted for, so a construct this does not know raises instead of vanishing.
    """
    terms, i, n = [], 0, len(expr)
    while i < n:
        if expr[i].isspace() or expr[i] in "()&|+-!":
            i += 1
            continue
        word = WORD.match(expr, i)
        if word is None:
            raise ValueError(f"unexpected {expr[i]!r} at offset {i}")
        if word.group(0) in OPERATOR_WORDS:
            i = word.end()
            continue
        k = word.end()
        if k >= n or expr[k] != "(":
            raise ValueError(f"{word.group(0)!r} at offset {i} does not open a predicate")
        k += 1
        if expr[k:].lstrip().startswith("/"):
            # a regex may hold ')' and '|'; it ends at the first unescaped '/'
            k = expr.index("/", k) + 1
            while k < n and expr[k] != "/":
                k += 2 if expr[k] == "\\" else 1
            k += 1
        while k < n and expr[k] != ")":
            k += 2 if expr[k] == "\\" else 1
        if k >= n:
            raise ValueError(f"unterminated {word.group(0)}( at offset {i}")
        terms.append(expr[i : k + 1])
        i = k + 1
    if not terms:
        raise ValueError("no predicate in the expression")
    return terms


evaluations = {}
broken_scopes = {}


def select(scope, expr):
    """(count, None), or (None, reason) when nextest could not answer."""
    key = (tuple(scope), expr)
    if key in evaluations:
        return evaluations[key]
    if tuple(scope) in broken_scopes:
        return None, broken_scopes[tuple(scope)]
    # JSON on stdout, cargo's chatter on stderr: the count never depends on colour or row shape.
    listing = subprocess.run(
        ["cargo", "nextest", "list", "--color", "never", *scope, "-E", expr, "-T", "json"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    if listing.returncode != 0:
        tail = " | ".join(listing.stderr.strip().splitlines()[-4:])
        reason = f"cargo nextest list exited {listing.returncode}: {tail}"
        # 94 is nextest rejecting this expression; anything else sinks the whole scope
        if listing.returncode != 94:
            broken_scopes[tuple(scope)] = reason
        evaluations[key] = (None, reason)
        return evaluations[key]
    try:
        suites = json.loads(listing.stdout)["rust-suites"]
        if not suites:
            raise ValueError("no test binary listed")
        statuses = [
            case["filter-match"]["status"]
            for suite in suites.values()
            for case in suite["testcases"].values()
        ]
        unknown = set(statuses) - {"matches", "mismatch"}
        if unknown:
            raise ValueError(f"unknown filter-match status {sorted(unknown)}")
        evaluations[key] = (statuses.count("matches"), None)
    except (KeyError, TypeError, ValueError) as drift:
        evaluations[key] = (None, f"nextest list JSON is not the shape this gate reads: {drift!r}")
    return evaluations[key]


def check_declaration(where, scope, expr):
    try:
        terms = split_terms(expr)
    except ValueError as unreadable:
        fail(f"FILTER NOT EVALUATED: {where}", f"filter: {expr}", f"cannot split it into terms: {unreadable}")
        return
    count, reason = select(scope, expr)
    if reason:
        fail(f"FILTER NOT EVALUATED: {where}", f"filter: {expr}", reason)
        return
    print(f"{count:6d}  {where}")
    if count == 0:
        fail(
            f"FILTER SELECTS NOTHING: {where}",
            f"filter: {expr}",
            "0 tests selected. Whatever this declaration configures, it configures for no test.",
        )
        return
    if terms == [expr.strip()]:
        return
    for term in terms:
        count, reason = select(scope, term)
        if reason:
            fail(f"FILTER TERM NOT EVALUATED: {where}", f"term: {term}", reason)
        elif count == 0:
            fail(
                f"FILTER TERM SELECTS NOTHING: {where}",
                f"term: {term}",
                "The rest of the filter still matches, so the lane stays green while this term is dead.",
            )


def declared_filters(node, trail):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("filter", "default-filter"):
                yield trail + [key], value, node
            else:
                yield from declared_filters(value, trail + [key])
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from declared_filters(value, trail + [index])


def check_nextest_config(config, manifest):
    try:
        with open(config, "rb") as handle:
            document = tomllib.load(handle)
        with open(manifest, "rb") as handle:
            cargo_profiles = tomllib.load(handle).get("profile") or {}
    except (OSError, tomllib.TOMLDecodeError) as unreadable:
        fail(f"CONFIG NOT READ: {config} (workspace {manifest})", repr(unreadable))
        return
    # the adapter defines ci-test and CI tests it under nothing else; the root workspace has only dev
    cargo_profile = ["--cargo-profile", "ci-test"] if "ci-test" in cargo_profiles else []
    declarations = list(declared_filters(document, []))
    groups = set(document.get("test-groups") or {})
    # so a log shows what discovery reached; a config it never opened would otherwise read as clean
    print(f"        {config}: {len(declarations)} filter declaration(s), {len(groups)} test group(s)")
    for trail, expr, owner in declarations:
        where = f"{config} " + ".".join(str(part) for part in trail)
        if "test-group" in owner:
            where += f" (test-group {owner['test-group']})"
        if not isinstance(expr, str):
            fail(f"FILTER NOT EVALUATED: {where}", f"not a string: {expr!r}")
            continue
        profile = trail[1] if trail[0] == "profile" and len(trail) > 2 else "default"
        # the widest universe nextest can be asked for: dead here is dead in every lane
        scope = ["--manifest-path", manifest, "--config-file", config, "--profile", profile,
                 *cargo_profile, "--all-targets", "--run-ignored", "all"]
        check_declaration(where, scope, expr)
    assigned = {
        override["test-group"]
        for profile in (document.get("profile") or {}).values()
        for override in profile.get("overrides") or []
        if "test-group" in override
    }
    for group in sorted(groups - assigned):
        fail(
            f"TEST GROUP HOLDS NOTHING: {config} test-groups.{group}",
            "No override assigns a test to it, so its limits apply to no test.",
        )


FILTER_FLAGS = {"-E", "--filterset", "--filter-expr"}
SCOPE_VALUE_FLAGS = {"--manifest-path", "-p", "--package", "--features", "--cargo-profile",
                     "--profile", "--run-ignored"}
SCOPE_BARE_FLAGS = {"--all-targets", "--workspace", "--all-features", "--no-default-features"}
RUN_ONLY_VALUE_FLAGS = {"--no-tests"}
RUN_ONLY_BARE_FLAGS = {"--no-fail-fast"}
MATRIX_FIELD = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\s*\}\}")


def lane_scope(arguments):
    """Split a `cargo nextest run` argument list into what scopes a listing and its filters."""
    scope, filters, i = [], [], 0
    while i < len(arguments):
        flag, inline, value = arguments[i].partition("=")
        takes_value = flag in FILTER_FLAGS | SCOPE_VALUE_FLAGS | RUN_ONLY_VALUE_FLAGS
        if takes_value and not inline:
            i += 1
            if i >= len(arguments):
                raise ValueError(f"{flag} has no value")
            value = arguments[i]
        if flag in FILTER_FLAGS:
            filters.append(value)
        elif flag in SCOPE_VALUE_FLAGS:
            scope += [flag, value]
        elif flag in SCOPE_BARE_FLAGS and not inline:
            scope.append(flag)
        elif not (flag in RUN_ONLY_VALUE_FLAGS or (flag in RUN_ONLY_BARE_FLAGS and not inline)):
            raise ValueError(f"argument {arguments[i]!r} is not one this gate knows how to carry into a listing")
        i += 1
    return scope, filters


def workflow_lanes(document):
    """Every filtered nextest command the workflow runs, with its matrix values substituted."""
    for job_name, job in (document.get("jobs") or {}).items():
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        for step in job.get("steps") or []:
            script = (step.get("run") or "").replace("\\\n", " ")
            for line in script.splitlines():
                if "nextest" not in line or line.lstrip().startswith("#"):
                    continue
                axes = {axis for axis, _field in MATRIX_FIELD.findall(line)}
                if len(axes) > 1:
                    raise ValueError(f"{job_name}: a nextest command templated over {sorted(axes)}")
                entries = matrix.get(axes.pop()) if axes else [{}]
                if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
                    raise ValueError(f"{job_name}: matrix axis is not a list of mappings")
                for position, entry in enumerate(entries):
                    concrete = MATRIX_FIELD.sub(lambda m: str(entry[m.group(2)]), line)
                    if "${{" in concrete:
                        raise ValueError(f"{job_name}: unresolved template in {concrete!r}")
                    tokens = shlex.split(concrete, comments=True)
                    if not any(t.partition("=")[0] in FILTER_FLAGS for t in tokens):
                        continue
                    if tokens[:3] != ["cargo", "nextest", "run"]:
                        raise ValueError(f"{job_name}: a filtered command that is not `cargo nextest run`: {concrete!r}")
                    scope, filters = lane_scope(tokens[3:])
                    lane = f"{job_name}/{entry.get('name', step.get('name', position))}"
                    for expr in filters:
                        yield lane, scope, expr


if not config_specs:
    fail("NO NEXTEST CONFIG FOUND", "Discovery returned nothing; both workspaces are known to carry one.")
for spec in config_specs:
    config, separator, manifest = spec.partition("=")
    if not separator or not os.path.isfile(config) or not os.path.isfile(manifest):
        fail(f"CONFIG NOT READ: {spec}", "Expected config=manifest, both existing files.")
        continue
    check_nextest_config(config, manifest)

try:
    with open(workflow, encoding="utf-8") as handle:
        lanes = list(workflow_lanes(yaml.safe_load(handle)))
    if not lanes:
        raise ValueError("no filtered nextest command found; extraction drift?")
except (OSError, KeyError, ValueError, yaml.YAMLError) as unreadable:
    lanes = []
    fail(f"WORKFLOW NOT READ: {workflow}", f"{unreadable}")
for lane, scope, expr in lanes:
    check_declaration(f"{workflow} {lane}", scope, expr)

for failure in failures:
    print(failure, file=sys.stderr)
if failures:
    print(f"scripts/check-ci-filter-names.sh --selected: {len(failures)} failure(s).", file=sys.stderr)
    sys.exit(1)
print(f"scripts/check-ci-filter-names.sh --selected: clean ({len(evaluations)} nextest evaluations).")
PY
fi

if [ "$MODE" != "names" ]; then
  echo "usage: $0 [--selected]" >&2
  exit 2
fi

# `test(...)` names: must appear as a `fn <name>` somewhere in a .rs file ON DISK.
# --untracked, because a lane's brand-new test file is not in the index yet and a gate that
# cannot see it fails on correct work.
while IFS= read -r name; do
  [ -z "$name" ] && continue
  if ! git grep --untracked -qE "fn +${name}\b" -- '*.rs' 2>/dev/null; then
    echo "CI FILTER LEAK: test(${name}) in ${CI} matches no 'fn ${name}' in the tree." >&2
    echo "  A test() term naming a nonexistent test exits 0 and silently shrinks the lane." >&2
    fail=1
  fi
done < <(/usr/bin/grep -oE 'test\([A-Za-z_0-9]+\)' "$CI" | sed -E 's/test\((.*)\)/\1/' | sort -u)

# `binary(...)` names: must match a tests/ or benches/ file that EXISTS ON DISK.
#
# The existence test is `-f`, not `git ls-files | grep -q .`, and that distinction is the whole
# point: `git ls-files` reports the INDEX, so a test file deleted in the working tree and not yet
# committed still resolves. A lane deleted pir_cell_width_law.rs, this gate stayed green, and the
# nightly production-cell lane would have died at exit 94 on a binary() naming nothing. A gate
# that answers from the index while nextest answers from the disk is not checking the same tree.
# Untracked candidates count, so a lane's new test file resolves before it is committed.
while IFS= read -r name; do
  [ -z "$name" ] && continue
  found=0
  while IFS= read -r cand; do
    [ -n "$cand" ] && [ -f "$cand" ] && { found=1; break; }
  done < <(git ls-files "*/tests/${name}.rs" "*/benches/${name}.rs" "*/src/bin/${name}.rs"; \
           git ls-files --others --exclude-standard \
             "*/tests/${name}.rs" "*/benches/${name}.rs" "*/src/bin/${name}.rs")
  if [ "$found" -eq 0 ]; then
    echo "CI FILTER LEAK: binary(${name}) in ${CI} matches no test/bench target on disk." >&2
    echo "  nextest fails the whole lane (exit 94) on a binary() that names nothing." >&2
    fail=1
  fi
done < <(/usr/bin/grep -oE 'binary\([A-Za-z_0-9]+\)' "$CI" | sed -E 's/binary\((.*)\)/\1/' | sort -u)

# Every workspace member must appear in the fmt run block and in a test shard - both are
# enumerated by hand with -p, and a new member is silently uncovered. That already happened once.
members=$(python3 - <<'PY'
import re, pathlib
m = re.search(r'members = \[(.*?)\]', pathlib.Path('adapters/railgun/Cargo.toml').read_text(), re.S)
print('\n'.join('raven-railgun-' + x.strip().strip('"') for x in m.group(1).split(',') if x.strip()))
PY
)

fmt_run=$(awk '
  $0 == "  railgun-static:" { in_job = 1; next }
  in_job && /^  [A-Za-z0-9_-]+:$/ { exit }
  in_job && $0 == "      - name: cargo fmt" { in_step = 1; next }
  in_step && /^      - / { exit }
  in_step && /^        run:/ {
    in_run = 1
    sub(/^        run:[[:space:]]*/, "")
    if ($0 != "|") print
    next
  }
  in_run {
    if ($0 != "" && $0 !~ /^          /) exit
    print
  }
' "$CI")

test_packages=$(awk '
  $0 == "  railgun-tests:" { in_job = 1; next }
  in_job && /^  [A-Za-z0-9_-]+:$/ { exit }
  in_job && /^            packages:/ {
    in_packages = 1
    line = $0
    sub(/^            packages:[[:space:]]*/, "", line)
    print line
    next
  }
  in_packages {
    if ($0 != "" && $0 !~ /^              /) in_packages = 0
    if (in_packages) print
  }
' "$CI")

test_run=$(awk '
  $0 == "  railgun-tests:" { in_job = 1; next }
  in_job && /^  [A-Za-z0-9_-]+:$/ { exit }
  in_job && /^        run:/ {
    in_run = 1
    line = $0
    sub(/^        run:[[:space:]]*/, "", line)
    if (line != "|") print line
    next
  }
  in_run {
    if ($0 != "" && $0 !~ /^          /) in_run = 0
    if (in_run) print
  }
' "$CI")

if [ -z "$fmt_run" ]; then
  echo "CI COVERAGE LEAK: railgun-static has no cargo fmt run block in ${CI}." >&2
  fail=1
fi
if [ -z "$test_packages" ] || ! /usr/bin/grep -Fq '${{ matrix.shard.packages }}' <<< "$test_run"; then
  echo "CI COVERAGE LEAK: railgun-tests does not execute its package shards in ${CI}." >&2
  fail=1
fi

for pkg in $members; do
  if ! /usr/bin/grep -Fq -- "-p ${pkg}" <<< "$fmt_run"; then
    echo "CI COVERAGE LEAK: workspace member ${pkg} is absent from the railgun-static fmt run block." >&2
    fail=1
  fi
  if ! /usr/bin/grep -Fq -- "-p ${pkg}" <<< "$test_packages"; then
    echo "CI COVERAGE LEAK: workspace member ${pkg} is absent from the railgun-tests package shards." >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "scripts/check-ci-filter-names.sh: at least one CI filter or package name does not resolve." >&2
  exit 1
fi
echo "scripts/check-ci-filter-names.sh: clean (plain test()/binary() names and package coverage; --selected asks nextest)."

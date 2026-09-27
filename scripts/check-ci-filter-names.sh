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
#                  override whose filter selects nothing configures nothing, silently. The whole
#                  filter, each term and each top-level alternative of a regex must select a test
#                  in every profile the declaration applies in, over the bare workspace and each
#                  package/feature selection a workflow lane builds. Group membership is what
#                  `nextest show-config test-groups` reports: every declared group holds a test,
#                  a serialising group holds more tests than it admits at once, and every test of
#                  a spawn-and-kill target sits in a max-threads = 1 group. Needs the test
#                  binaries built, like scripts/assert-lane-counts.sh.
#   --spawn-and-kill FILE...
#                  the classifier --selected uses, on its own so a selftest can prove it on
#                  fixtures without a toolchain. A target root, with every file its `mod`s load,
#                  spawns and kills when it names CARGO_BIN_EXE_ or current_exe() and calls kill()
#                  outside comments, strings and `impl Drop`: a Drop reaps at teardown and races
#                  nothing.
#   --show-config-fixture VERSION FILE
#                  the `show-config test-groups` reader --selected uses, on a saved output. That
#                  text is not a stable interface: 0.9.146 added a "(from FILE)" suffix that
#                  0.9.129 does not print, and the gate rejected a healthy tree on it. An unknown
#                  line fails naming the release that printed it, VERSION here.
#
# FILTER_GATE_WORKFLOW and FILTER_GATE_NEXTEST_CONFIGS ("config=manifest ...") point either pass
# at copies, so a red-proof never has to mutate a tracked file.
set -uo pipefail
cd "$(dirname "$0")/.."
CI="${FILTER_GATE_WORKFLOW:-.github/workflows/ci.yml}"
MODE="${1:-names}"
fail=0

[ -f "$CI" ] || { echo "scripts/check-ci-filter-names.sh: workflow ${CI} does not exist." >&2; exit 1; }

if [ "$MODE" = "--selected" ] || [ "$MODE" = "--spawn-and-kill" ] || [ "$MODE" = "--show-config-fixture" ]; then
  shift
  if [ "$MODE" = "--selected" ] && [ -n "${FILTER_GATE_NEXTEST_CONFIGS:-}" ]; then
    # shellcheck disable=SC2086
    set -- $FILTER_GATE_NEXTEST_CONFIGS
  elif [ "$MODE" = "--selected" ]; then
    # The disk, not the index, and untracked files count: the same tree nextest answers from.
    # shellcheck disable=SC2046
    set -- $(
      { git ls-files -- '.config/nextest.toml' '*/.config/nextest.toml'
        git ls-files --others --exclude-standard -- '.config/nextest.toml' '*/.config/nextest.toml'
      } | sort -u | while IFS= read -r cfg; do
        [ -f "$cfg" ] || continue
        workspace=$(dirname "$(dirname "$cfg")")
        printf '%s=%s\n' "$cfg" "${workspace}/Cargo.toml"
      done
    )
  fi
  exec python3 - "$MODE" "$CI" "$@" <<'PY'
import collections
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib

mode, workflow, config_specs = sys.argv[1], sys.argv[2], sys.argv[3:]
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


def regex_alternatives(term):
    """`test(/a|b/)` as `test(/a/)` and `test(/b/)`: one live alternative carries a dead one."""
    head, _, rest = term.partition("(")
    body = rest[:-1].strip()
    if len(body) < 2 or body[0] != "/" or body[-1] != "/":
        return []
    body = body[1:-1]
    alternatives, start, depth, in_class, i = [], 0, 0, False, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch in "()":
            depth += 1 if ch == "(" else -1
        elif ch == "|" and depth == 0:
            alternatives.append(body[start:i])
            start = i + 1
        i += 1
    alternatives.append(body[start:])
    return [f"{head}(/{alt}/)" for alt in alternatives] if len(alternatives) > 1 else []


Listing = collections.namedtuple("Listing", "matched universe suites")
evaluations = {}
broken_scopes = {}


def select(scope, expr):
    """(Listing, None), or (None, reason) when nextest could not answer."""
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
        matched, universe, shapes = set(), set(), {}
        for binary_id, suite in suites.items():
            shapes[binary_id] = (suite["package-name"], suite["binary-name"], suite["kind"])
            for name, case in suite["testcases"].items():
                status = case["filter-match"]["status"]
                if status not in ("matches", "mismatch"):
                    raise ValueError(f"unknown filter-match status {status!r}")
                universe.add((binary_id, name))
                if status == "matches":
                    matched.add((binary_id, name))
        evaluations[key] = (Listing(frozenset(matched), frozenset(universe), shapes), None)
    except (KeyError, TypeError, ValueError) as drift:
        evaluations[key] = (None, f"nextest list JSON is not the shape this gate reads: {drift!r}")
    return evaluations[key]


def selected(scopes, expr):
    """What `expr` selects across every scope, or (None, reason)."""
    matched = set()
    for scope in scopes:
        listing, reason = select(scope, expr)
        if reason:
            return None, reason
        matched |= listing.matched
    return matched, None


DEAD = {
    "FILTER": "0 tests selected. Whatever this declaration configures, it configures for no test.",
    "FILTER TERM": "The rest of the filter still matches, so the lane stays green while this term is dead.",
    "FILTER ALTERNATIVE": "The other alternatives still match, so the regex reads as live while this one is dead.",
}


def check_declaration(where, scopes_by_profile, expr):
    """Every profile the declaration applies in must select a test for it, each of its terms and
    each top-level alternative of a regex term."""
    try:
        terms = split_terms(expr)
    except ValueError as unreadable:
        fail(f"FILTER NOT EVALUATED: {where}", f"filter: {expr}", f"cannot split it into terms: {unreadable}")
        return
    pieces = [("FILTER", expr)]
    if terms != [expr.strip()]:
        pieces += [("FILTER TERM", term) for term in terms]
    pieces += [("FILTER ALTERNATIVE", alt) for term in terms for alt in regex_alternatives(term)]
    for kind, piece in pieces:
        label = kind.split()[-1].lower()
        counts, reason = {}, None
        for profile, scopes in scopes_by_profile.items():
            matched, reason = selected(scopes, piece)
            if reason:
                break
            counts[profile] = len(matched)
        if reason:
            fail(f"{kind} NOT EVALUATED: {where}", f"{label}: {piece}", reason)
            if kind == "FILTER":
                return
            continue
        dead = [profile for profile, count in counts.items() if count == 0]
        if kind == "FILTER":
            print(f"{min(counts.values()):6d}  {where}")
        if dead:
            suffix = f" (profile {', '.join(dead)})" if any(dead) else ""
            fail(f"{kind} SELECTS NOTHING: {where}{suffix}", f"{label}: {piece}", DEAD[kind])
            if kind == "FILTER":
                return


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


SPAWNS = re.compile(r"CARGO_BIN_EXE_|current_exe\(\)")
KILLS = re.compile(r"(?:\.|::)kill\s*\(")
RAW_STRING = re.compile(r'(?<![A-Za-z0-9_])b?r(#*)"')
DROP_IMPL = re.compile(r"\bimpl\b[^{;]*?\bDrop\s+for\b[^{;]*\{")
MOD_DECL = re.compile(r"((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')


def masked(text, strings):
    """Comments blanked, and string and char literals too when `strings`; offsets kept."""
    out, i, n = list(text), 0, len(text)

    def blank(start, end):
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        raw = RAW_STRING.match(text, i) if text[i] in "br" else None
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
        elif text.startswith("/*", i):
            depth, end = 1, i + 2
            while end < n and depth:
                step = text[end : end + 2]
                depth += 1 if step == "/*" else -1 if step == "*/" else 0
                end += 2 if step in ("/*", "*/") else 1
            blank(i, end)
        elif raw:
            close = text.find('"' + raw.group(1), raw.end())
            end = n if close < 0 else close + 1 + len(raw.group(1))
            if strings:
                blank(raw.end(), end)
        elif text[i] == '"':
            end = i + 1
            while end < n and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end += 1
            if strings:
                blank(i + 1, end - 1)
        elif text[i] == "'" and (text[i + 1 : i + 2] == "\\" or text[i + 2 : i + 3] == "'"):
            close = text.find("'", i + 3 if text[i + 1] == "\\" else i + 2)
            end = n if close < 0 else close + 1
            if strings:
                blank(i + 1, end - 1)
        else:
            end = i + 1
        i = end
    return "".join(out)


def without_drop_impls(code):
    """A kill in `impl Drop` reaps a child at teardown; it races nothing."""
    out = list(code)
    for impl in DROP_IMPL.finditer(code):
        depth, end = 1, impl.end()
        while end < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[end], 0)
            end += 1
        out[impl.start() : end] = " " * (end - impl.start())
    return "".join(out)


def source_files(root):
    """A target's root file and every file its `mod` declarations load."""
    files, queue = [], [(root, os.path.dirname(root))]
    while queue:
        path, base = queue.pop()
        if path in files:
            continue
        files.append(path)
        with open(path, encoding="utf-8") as handle:
            code = masked(handle.read(), strings=False)
        for decl in MOD_DECL.finditer(code):
            attr = PATH_ATTR.search(decl.group(1))
            if attr:
                child = os.path.normpath(os.path.join(os.path.dirname(path), attr.group(1)))
                queue.append((child, os.path.dirname(child)))
                continue
            for child, child_base in ((os.path.join(base, decl.group(2) + ".rs"), os.path.join(base, decl.group(2))),
                                      (os.path.join(base, decl.group(2), "mod.rs"), os.path.join(base, decl.group(2)))):
                if os.path.isfile(child):
                    queue.append((child, child_base))
                    break
    return files


def spawns_and_kills(root):
    spawn = kill = False
    for path in source_files(root):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        spawn = spawn or bool(SPAWNS.search(masked(text, strings=False)))
        kill = kill or bool(KILLS.search(without_drop_impls(masked(text, strings=True))))
    return spawn and kill


def spawn_and_kill_targets(manifest):
    """Test and bench targets whose sources run a cargo-built binary and kill it outside a Drop."""
    meta = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--manifest-path", manifest],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    if meta.returncode != 0:
        raise ValueError(f"cargo metadata exited {meta.returncode}: {meta.stderr.strip()[-300:]}")
    for package in json.loads(meta.stdout)["packages"]:
        for target in package["targets"]:
            kind = next((k for k in target["kind"] if k in ("test", "bench")), None)
            if kind is not None and spawns_and_kills(target["src_path"]):
                yield package["name"], target["name"], kind


GROUP_HEADER = re.compile(r"group: (\S+) \(max threads = ([^)]+)\)")
# 0.9.146 appends the declaring file to this line, 0.9.129 does not; both are read
GROUP_OVERRIDE = re.compile(r"  \* override for \S+ profile with filter '.*'(?: \(from .+\))?:")
GROUP_BINARY = re.compile(r" {6}(\S+):")
GROUP_TEST = re.compile(r" {10}(\S+)")
GROUP_EMPTY = "    (no matches)"
_nextest_version = []


def nextest_version():
    """The installed release, for a message that blames a format change on the right tool."""
    if not _nextest_version:
        shown = subprocess.run(["cargo", "nextest", "--version"], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True)
        first = shown.stdout.strip().splitlines()[:1]
        _nextest_version.append(first[0] if shown.returncode == 0 and first else
                                f"cargo-nextest (version unreadable, exit {shown.returncode})")
    return _nextest_version[0]


def parse_show_config(text, version):
    """({group: (max threads, {(binary id, test)})}, None), or (None, reason) on an unknown line."""
    groups, group, binary = {}, None, None
    for line in text.splitlines():
        header, member = GROUP_HEADER.fullmatch(line), GROUP_TEST.fullmatch(line)
        if header:
            group, binary = header.group(1), None
            threads = header.group(2)
            groups[group] = (int(threads) if threads.isdigit() else threads, set())
        elif group and (GROUP_OVERRIDE.fullmatch(line) or line == GROUP_EMPTY):
            binary = None
        elif group and GROUP_BINARY.fullmatch(line):
            binary = GROUP_BINARY.fullmatch(line).group(1)
        elif group and binary and member:
            groups[group][1].add((binary, member.group(1)))
        elif line.strip():
            return None, (f"{version}: its show-config output is not the shape this gate reads: {line!r}. "
                          "CI pins the release in its install steps; teach parse_show_config the new "
                          "shape, with a fixture, before moving that pin.")
    return groups, None


def group_members(scope):
    """({group: (max threads, {(binary id, test)})}, None) as nextest assigns them, or (None, reason)."""
    key = ("show-config", tuple(scope))
    if key in evaluations:
        return evaluations[key]
    shown = subprocess.run(
        ["cargo", "nextest", "show-config", "test-groups", "--color", "never", "--no-pager", *scope],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    if shown.returncode != 0:
        tail = " | ".join(shown.stderr.strip().splitlines()[-4:])
        evaluations[key] = (None, f"cargo nextest show-config test-groups exited {shown.returncode} "
                                  f"({nextest_version()}): {tail}")
        return evaluations[key]
    evaluations[key] = parse_show_config(shown.stdout, nextest_version())
    return evaluations[key]


def check_groups(config, document, scopes_by_profile, manifest):
    """Membership as nextest reports it, in every profile: a declared group holds a test, a
    serialising group holds more tests than it admits at once, and every test of a spawn-and-kill
    target sits in a max-threads = 1 group."""
    declared = sorted(document.get("test-groups") or {})
    try:
        killers = sorted(set(spawn_and_kill_targets(manifest)))
    except (OSError, KeyError, ValueError) as unreadable:
        fail(f"SPAWN AND KILL TARGETS NOT READ: {config} (workspace {manifest})", repr(unreadable))
        return
    if not declared and not killers:
        return
    held, small, loose, listed = set(), collections.defaultdict(list), collections.defaultdict(list), set()
    for profile, scopes in scopes_by_profile.items():
        limit, group_of, universe, shapes = {}, {}, set(), {}
        for scope in scopes:
            if killers:
                listing, reason = select(scope, "all()")
                if reason:
                    fail(f"TEST GROUP NOT EVALUATED: {config} (profile {profile})", reason)
                    return
                universe |= listing.universe
                shapes.update(listing.suites)
            if declared:
                groups, reason = group_members(scope)
                if reason:
                    fail(f"TEST GROUP NOT EVALUATED: {config} (profile {profile})", reason)
                    return
                for group, (threads, members) in groups.items():
                    limit[group] = threads
                    group_of.update(dict.fromkeys(members, group))
        for group in declared:
            size = sum(1 for owner in group_of.values() if owner == group)
            if size:
                held.add(group)
            if isinstance(limit.get(group), int) and 0 < size <= limit[group]:
                small[group].append(f"profile {profile}: {size} test(s) against max-threads = {limit[group]}")
        for target in killers:
            tests = sorted(t for t in universe if shapes[t[0]] == target)
            if tests:
                listed.add(target)
            outside = [t[1] for t in tests if limit.get(group_of.get(t)) != 1]
            if outside:
                loose[target].append(f"profile {profile}: {', '.join(outside)}")
    for group in declared:
        if group not in held:
            fail(f"TEST GROUP HOLDS NOTHING: {config} test-groups.{group}",
                 "nextest assigns it no test in any profile, so its limits apply to no test.")
    for group, detail in sorted(small.items()):
        fail(f"TEST GROUP CONSTRAINS NOTHING: {config} test-groups.{group}", *detail,
             "A group that never holds more tests than it admits at once serialises nothing.")
    for package, name, kind in killers:
        if (package, name, kind) not in listed:
            fail(f"SPAWN AND KILL TARGET NOT LISTED: {config} {package}::{name}",
                 f"{kind} target spawns a cargo-built binary and kills it, and no scope this gate lists holds a test from it.")
        elif (package, name, kind) in loose:
            fail(f"SPAWN AND KILL TEST NOT SERIALISED: {config} {package}::{name}",
                 *loose[(package, name, kind)],
                 "It spawns a cargo-built binary and kills it, outside every max-threads = 1 group.")


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


def feature_variants(manifest, lanes):
    """The package and feature selections the workflow builds this workspace with, plus none."""
    variants = {()}
    for _lane, scope, _expr in lanes:
        flags, lane_manifest, i = [], "Cargo.toml", 0
        while i < len(scope):
            if scope[i] == "--manifest-path":
                lane_manifest = scope[i + 1]
            if scope[i] in ("-p", "--package", "--features"):
                flags += scope[i : i + 2]
            elif scope[i] in ("--all-features", "--no-default-features"):
                flags.append(scope[i])
            i += 2 if scope[i] in SCOPE_VALUE_FLAGS else 1
        if os.path.normpath(lane_manifest) != os.path.normpath(manifest):
            continue
        if {"--features", "--all-features", "--no-default-features"} & set(flags):
            variants.add(tuple(flags))
    return sorted(variants)


def check_nextest_config(config, manifest, lanes):
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
    profiles = ["default", *sorted(set(document.get("profile") or {}) - {"default"})]
    variants = feature_variants(manifest, lanes)
    # the widest universe nextest can be asked for, per profile: dead here is dead in every lane
    scopes_by_profile = {
        profile: [["--manifest-path", manifest, "--config-file", config, "--profile", profile,
                   *cargo_profile, *variant, "--all-targets", "--run-ignored", "all"] for variant in variants]
        for profile in profiles
    }
    # so a log shows what discovery reached; a config it never opened would otherwise read as clean
    print(f"        {config}: {len(declarations)} filter declaration(s), {len(groups)} test group(s), "
          f"profiles {', '.join(profiles)}, {len(variants)} feature scope(s)")
    for trail, expr, owner in declarations:
        where = f"{config} " + ".".join(str(part) for part in trail)
        if "test-group" in owner:
            where += f" (test-group {owner['test-group']})"
        if not isinstance(expr, str):
            fail(f"FILTER NOT EVALUATED: {where}", f"not a string: {expr!r}")
            continue
        owner_profile = trail[1] if trail[0] == "profile" and len(trail) > 2 else "default"
        # the default profile's overrides are nextest's fallback in every other profile
        applies = profiles if owner_profile == "default" else [owner_profile]
        check_declaration(where, {profile: scopes_by_profile[profile] for profile in applies}, expr)
    check_groups(config, document, scopes_by_profile, manifest)


if mode == "--spawn-and-kill":
    for root in config_specs:
        print(f"{'spawns and kills' if spawns_and_kills(root) else 'does not'}: {root}")
    sys.exit(0)

if mode == "--show-config-fixture":
    version, fixture = config_specs
    with open(fixture, encoding="utf-8") as handle:
        groups, reason = parse_show_config(handle.read(), version)
    if reason:
        print(reason, file=sys.stderr)
        sys.exit(1)
    for group, (threads, members) in sorted(groups.items()):
        print(f"group {group} max-threads {threads}: {len(members)} test(s)")
        for binary, test in sorted(members):
            print(f"  {binary} {test}")
    sys.exit(0)

import yaml  # not above: --spawn-and-kill runs in the hygiene job, which needs no PyYAML

try:
    with open(workflow, encoding="utf-8") as handle:
        lanes = list(workflow_lanes(yaml.safe_load(handle)))
    if not lanes:
        raise ValueError("no filtered nextest command found; extraction drift?")
except (OSError, KeyError, ValueError, yaml.YAMLError) as unreadable:
    lanes = []
    fail(f"WORKFLOW NOT READ: {workflow}", f"{unreadable}")

if not config_specs:
    fail("NO NEXTEST CONFIG FOUND", "Discovery returned nothing; both workspaces are known to carry one.")
for spec in config_specs:
    config, separator, manifest = spec.partition("=")
    if not separator or not os.path.isfile(config) or not os.path.isfile(manifest):
        fail(f"CONFIG NOT READ: {spec}", "Expected config=manifest, both existing files.")
        continue
    check_nextest_config(config, manifest, lanes)

for lane, scope, expr in lanes:
    check_declaration(f"{workflow} {lane}", {"": [scope]}, expr)

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

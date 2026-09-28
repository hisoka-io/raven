#!/usr/bin/env bash
# Which CI jobs a change can affect, so a push that touches only docs, only the SDK or one
# workspace runs only the jobs whose inputs it changed.
#
# A job's inputs are the cargo workspaces it builds, closed over their path dependencies with
# `cargo metadata`, plus the few non-Rust paths listed below. A detached workspace counts as its
# whole directory, since its tests read files beside the crates (examples, fixtures, a Dockerfile).
#
# A push is diffed from the last push run of this workflow on its branch that passed, not from the
# push's previous tip, so a run cancelled by a newer push, or one that went red, hides nothing.
#
# It fails OPEN. A schedule or manual run, a branch with no green run, history rewritten since it,
# an unanswered runs API, a metadata error, or a changed path no rule claims all select every job.
# So does a change to the workflow, to scripts/ or to toolchain config: the gates prove themselves
# whenever they move.
# Consumers test `!= 'false'`, so a job whose output never arrived runs rather than skips.
#
# Usage:
#   scripts/ci-changes.sh                 in CI: diff the event's range, write GITHUB_OUTPUT
#   scripts/ci-changes.sh --paths FILE    classify the paths in FILE (one per line), print key=value
#   scripts/ci-changes.sh --keys          the output keys, one per line
#   scripts/ci-changes.sh --explain FILE  as --paths, with the rule that claimed each path
#   scripts/ci-changes.sh --claims FILE   each path in FILE with the keys whose inputs hold it
#   scripts/ci-changes.sh --manifests     each key with the workspace manifests it builds
#   scripts/ci-changes.sh --members       each key with the crates whose tests it builds
#
# CI_CHANGES_CARGO replaces cargo, so the selftest can prove the fail-open path, and
# CI_CHANGES_LAST_GREEN stands in for the runs API (empty: no green run).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
exec python3 - "$@" <<'PY'
import fnmatch
import json
import os
import subprocess
import sys

ROOT = "Cargo.toml"
RAILGUN = "adapters/railgun/Cargo.toml"
CLIENT_WASM = "adapters/railgun/client-wasm/Cargo.toml"

# output key -> (workspaces it builds, extra paths). Which job reads which key lives in ci.yml;
# scripts/ci-changes-selftest.sh holds the two together.
KEYS = {
    "root": ([ROOT, "crates/inspire/Cargo.toml"], []),
    "docs": ([ROOT, RAILGUN], []),
    "wasm": ([ROOT, CLIENT_WASM], []),
    "railgun": ([RAILGUN], []),
    # the full listing: the gates' own configs and pins; ci.yml and scripts/ select it via ALL
    "lane_counts": ([], [".config/nextest.toml", "adapters/railgun/.config/**"]),
    "inspire": (["crates/inspire/Cargo.toml"], []),
    "eth_state": (["adapters/eth-state/Cargo.toml"], []),
    "b1_bench": (["benches/b1-bench/Cargo.toml"], []),
    # tests/tracked_baseline.rs reads the committed baselines
    "bench_compare": (["tools/bench-compare/Cargo.toml"], ["benches/baselines/**"]),
    "bench_gate": (["benches/b1-bench/Cargo.toml", "tools/bench-compare/Cargo.toml"], ["benches/baselines/**"]),
    # the adapter manifest for the four railgun crates the 1.89 job checks by name
    "msrv_1_89": ([ROOT, CLIENT_WASM, "benches/b1-bench/Cargo.toml", "crates/inspire/Cargo.toml",
                   "tools/bench-compare/Cargo.toml", RAILGUN], []),
    "msrv_1_91": (["adapters/eth-state/Cargo.toml", RAILGUN], []),
    # the SDK gates read Rust constants and scripts from across the adapter
    "sdk": ([CLIENT_WASM, RAILGUN], ["adapters/railgun/**"]),
}

# A change here selects every job.
ALL = [".github/**", "scripts/**", "rust-toolchain.toml", "**/rust-toolchain.toml",
       ".cargo/**", "**/.cargo/**", ".gitmodules"]

# Read by no filtered job. Markdown is included by no Rust source (the selftest checks), except
# the SDK README, which ships in its package. No workspace here depends on Howl; its gates belong
# to its own repository.
NO_JOB = ["LICENSE", ".gitignore", ".dockerignore", ".gitleaks.toml", "deny.toml", "adapters/howl"]
NO_JOB_MD_EXCEPT = ["adapters/railgun/sdk/**"]

# Subtrees of a detached workspace directory that its cargo build never reads. The SDK fixtures
# stay in: adapter tests include_str! them.
WORKSPACE_EXCLUDES = {
    "adapters/railgun": [("adapters/railgun/sdk", ["adapters/railgun/sdk/tests/fixtures"]),
                         ("adapters/railgun/scripts", []),
                         ("adapters/railgun/client-wasm", [])],
}

CARGO = os.environ.get("CI_CHANGES_CARGO", "cargo")


class Unreadable(Exception):
    pass


def within(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def glob_match(path, pattern):
    if pattern.endswith("/**"):
        base = pattern[:-3]
        if "*" not in base:
            return within(path, base)
        return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, base)
    return fnmatch.fnmatchcase(path, pattern)


_metadata = {}


def metadata(manifest):
    if manifest not in _metadata:
        run = subprocess.run([CARGO, "metadata", "--no-deps", "--format-version", "1",
                              "--manifest-path", manifest],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True)
        if run.returncode != 0:
            tail = " | ".join(run.stderr.strip().splitlines()[-3:])
            raise Unreadable(f"cargo metadata --manifest-path {manifest} exited {run.returncode}: {tail}")
        try:
            _metadata[manifest] = json.loads(run.stdout)
        except ValueError as bad:
            raise Unreadable(f"cargo metadata --manifest-path {manifest}: not JSON ({bad})")
    return _metadata[manifest]


def rel(path):
    out = os.path.relpath(path, os.getcwd())
    return "." if out == "." else out.replace(os.sep, "/")


def workspace_inputs(manifest):
    """(prefixes with their excluded subtrees, exact files) a build of this workspace reads."""
    meta = metadata(manifest)
    ws = rel(meta["workspace_root"])
    packages = {p["id"]: p for p in meta["packages"]}
    members = [packages[i] for i in meta["workspace_members"]]
    prefixes, files = [], set()
    if ws == ".":
        files |= {"Cargo.toml", "Cargo.lock"}
        prefixes.append((".config", []))
        prefixes += [(rel(os.path.dirname(p["manifest_path"])), []) for p in members]
        scope = [prefix for prefix, _ in prefixes]
    else:
        nested = [(d, []) for d in (manifest_dir(m) for m in known_manifests())
                  if d != ws and within(d, ws)]
        excludes = list(WORKSPACE_EXCLUDES.get(ws, []))
        excludes += [n for n in nested if n[0] not in [e[0] for e in excludes]]
        prefixes.append((ws, excludes))
        scope = [ws]
    # Path dependencies outside this workspace, transitively: the crate's directory, and the
    # manifest of the workspace it inherits fields from. Their tests are not built here.
    queue = [d for p in members for d in p["dependencies"] if d.get("path")]
    seen = set()
    while queue:
        dep = rel(queue.pop()["path"])
        if dep in seen:
            continue
        seen.add(dep)
        if any(within(dep, s) for s in scope):
            continue
        prefixes.append((dep, []))
        dep_meta = metadata(f"{dep}/Cargo.toml")
        files.add(("" if rel(dep_meta["workspace_root"]) == "." else rel(dep_meta["workspace_root"]) + "/") + "Cargo.toml")
        own = [p for p in dep_meta["packages"] if rel(os.path.dirname(p["manifest_path"])) == dep]
        queue += [d for p in own for d in p["dependencies"] if d.get("path")]
    return prefixes, files


def manifest_dir(manifest):
    return os.path.dirname(manifest) or "."


def known_manifests():
    return sorted({m for manifests, _ in KEYS.values() for m in manifests})


def claims(path, prefixes, files, globs):
    if path in files or any(glob_match(path, g) for g in globs):
        return True
    for prefix, excludes in prefixes:
        if not within(path, prefix):
            continue
        if any(within(path, e) and not any(within(path, k) for k in keep) for e, keep in excludes):
            continue
        return True
    return False


def no_job(path):
    if path in NO_JOB:
        return True
    return path.endswith(".md") and not any(glob_match(path, g) for g in NO_JOB_MD_EXCEPT)


def classify(paths):
    """({key: bool}, {key: first path that selected it}, [notes])."""
    selected, why, notes = {k: False for k in KEYS}, {}, []

    def select_all(reason):
        notes.append(f"every job: {reason}")
        return {k: True for k in KEYS}, {k: reason for k in KEYS}, notes

    for path in paths:
        if any(glob_match(path, g) for g in ALL):
            return select_all(f"{path} is CI or toolchain configuration")
    try:
        inputs = {k: workspace_inputs_union(manifests) + (globs,) for k, (manifests, globs) in KEYS.items()}
    except Unreadable as unreadable:
        return select_all(str(unreadable))
    except (KeyError, TypeError, ValueError, OSError) as bug:
        return select_all(f"workspace inputs not computed: {bug!r}")
    for path in paths:
        if no_job(path):
            notes.append(f"no job reads {path}")
            continue
        hit = [k for k, (prefixes, files, globs) in inputs.items() if claims(path, prefixes, files, globs)]
        if not hit:
            return select_all(f"no rule claims {path}")
        for k in hit:
            if not selected[k]:
                selected[k], why[k] = True, path
    return selected, why, notes


def workspace_inputs_union(manifests):
    prefixes, files = [], set()
    for manifest in manifests:
        p, f = workspace_inputs(manifest)
        prefixes += p
        files |= f
    return prefixes, files


def git(*args):
    run = subprocess.run(["git", *args], stdin=subprocess.DEVNULL, capture_output=True, text=True)
    return run.returncode, run.stdout


def last_green(branch):
    """Head of the last push run of this workflow on `branch` that passed, or (None, reason).

    Not the push's previous tip: a newer push cancels the older run, and a push after a red run
    would otherwise skip the jobs that went red. Diffing from the last green run re-selects both.
    """
    pinned = os.environ.get("CI_CHANGES_LAST_GREEN")
    if pinned is not None:
        return (pinned or None), ("no green run given" if not pinned else None)
    repo = os.environ.get("GITHUB_REPOSITORY")
    workflow = os.path.basename((os.environ.get("GITHUB_WORKFLOW_REF") or "").split("@")[0])
    if not repo or not workflow or not os.environ.get("GH_TOKEN"):
        return None, "no repository, workflow or token to find the last green run with"
    run = subprocess.run(["gh", "api", "-X", "GET", f"repos/{repo}/actions/workflows/{workflow}/runs",
                          "-f", f"branch={branch}", "-f", "event=push", "-f", "status=success",
                          "-f", "per_page=1", "--jq", ".workflow_runs[0].head_sha // empty"],
                         stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if run.returncode != 0:
        return None, f"the runs API failed: {' | '.join(run.stderr.strip().splitlines()[-2:])}"
    sha = run.stdout.strip()
    return (sha, None) if sha else (None, f"no green push run on {branch} yet")


def changed_paths():
    """The event's changed paths, or (None, reason) when the range cannot be trusted."""
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    try:
        with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
            payload = json.load(handle)
    except (KeyError, OSError, ValueError) as bad:
        return None, f"event payload unreadable ({bad!r})"
    if event == "push":
        head = payload.get("after") or os.environ.get("GITHUB_SHA", "")
        ref = payload.get("ref") or os.environ.get("GITHUB_REF", "")
        base, reason = last_green(ref.removeprefix("refs/heads/"))
        if base is None:
            return None, reason
        if git("cat-file", "-e", f"{base}^{{commit}}")[0] != 0:
            return None, f"last green commit {base} is not in the clone"
        if git("merge-base", "--is-ancestor", base, head)[0] != 0:
            return None, f"history was rewritten: last green {base} is not an ancestor of {head}"
        spec = [base, head]
    elif event == "pull_request":
        pr = payload.get("pull_request") or {}
        base, head = (pr.get("base") or {}).get("sha"), (pr.get("head") or {}).get("sha")
        if not base or not head:
            return None, "pull request payload has no base or head sha"
        # the whole pull request against its merge base, so a cancelled run hides nothing
        spec = [f"{base}...{head}"]
    else:
        return None, f"a {event or 'unknown'} run tests everything"
    rc, out = git("diff", "--name-only", "--no-renames", *spec)
    if rc != 0:
        return None, f"git diff {' '.join(spec)} failed"
    return [line for line in out.splitlines() if line], None


def emit(selected, why, notes, paths):
    lines = [f"{k}={'true' if v else 'false'}" for k, v in selected.items()]
    print("\n".join(lines))
    for note in notes:
        print(f"  {note}", file=sys.stderr)
    for k, v in selected.items():
        if v:
            print(f"  {k}: {why.get(k, '')}", file=sys.stderr)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### Jobs this change selects\n\n| key | runs | first path |\n|---|---|---|\n")
            for k, v in selected.items():
                handle.write(f"| {k} | {'yes' if v else 'no'} | {why.get(k, '')} |\n")
            if notes:
                handle.write("\n" + "\n".join(f"- {n}" for n in notes) + "\n")
            if paths is not None:
                handle.write(f"\n{len(paths)} changed path(s).\n")


args = sys.argv[1:]
if args == ["--keys"]:
    print("\n".join(KEYS))
    sys.exit(0)
if args == ["--manifests"]:
    for k, (manifests, _globs) in KEYS.items():
        print(f"{k}\t{' '.join(manifests)}")
    sys.exit(0)
if args == ["--members"]:
    for k, (manifests, _globs) in KEYS.items():
        crates = set()
        for manifest in manifests:
            meta = metadata(manifest)
            packages = {p["id"]: p for p in meta["packages"]}
            crates |= {rel(os.path.dirname(packages[i]["manifest_path"])) for i in meta["workspace_members"]}
        print(f"{k}\t{' '.join(sorted(crates))}")
    sys.exit(0)
if len(args) == 2 and args[0] == "--claims":
    with open(args[1], encoding="utf-8") as handle:
        paths = [line.strip() for line in handle if line.strip()]
    inputs = {k: workspace_inputs_union(manifests) + (globs,) for k, (manifests, globs) in KEYS.items()}
    for path in paths:
        keys = [] if no_job(path) else [k for k, i in inputs.items() if claims(path, *i)]
        print(f"{path}\t{','.join(keys)}")
    sys.exit(0)
if len(args) == 2 and args[0] in ("--paths", "--explain"):
    with open(args[1], encoding="utf-8") as handle:
        paths = [line.strip() for line in handle if line.strip()]
    selected, why, notes = classify(paths)
    for k, v in selected.items():
        print(f"{k}={'true' if v else 'false'}")
    if args[0] == "--explain":
        for note in notes:
            print(f"  {note}")
        for k, v in selected.items():
            if v:
                print(f"  {k}: {why.get(k, '')}")
    sys.exit(0)
if args:
    print("usage: scripts/ci-changes.sh [--paths FILE | --explain FILE | --claims FILE | --keys | --manifests"
          " | --members]",
          file=sys.stderr)
    sys.exit(2)

paths, reason = changed_paths()
if paths is None:
    emit({k: True for k in KEYS}, {k: reason for k in KEYS}, [f"every job: {reason}"], None)
else:
    print(f"{len(paths)} changed path(s)", file=sys.stderr)
    emit(*classify(paths), paths)
PY

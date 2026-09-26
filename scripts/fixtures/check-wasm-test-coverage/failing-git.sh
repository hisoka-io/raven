#!/usr/bin/env bash
# Installed as `git` ahead of the real one: `grep` exits 128 when it would run in the directory
# FAIL_GREP_IN names, and every other call is REAL_GIT.
dir=.
args=("$@")
while [ "$#" -ge 2 ] && [ "$1" = -C ]; do dir=$2; shift 2; done
if [ "${1:-}" = grep ] && [ "$(cd "$dir" && pwd -P)" = "$FAIL_GREP_IN" ]; then
  echo "fatal: injected git grep failure" >&2
  exit 128
fi
exec "$REAL_GIT" "${args[@]}"

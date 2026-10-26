#!/usr/bin/env bash
# The image entrypoint's checks, run without the image: the arguments it renders from the
# variables, each variable it refuses, and the flags it keeps for the variables alone.
# `--red-proof` runs the same cases against copies with one check removed each, and passes only
# if every copy fails them.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
entry=${ENTRYPOINT:-$here/entrypoint.sh}

if [ "${1:-}" = --red-proof ]; then
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  status=0
  for plant in 's/--listen | --listen=\*) die/--never) die/' \
               's/--data-dir | --data-dir=\*) die/--never) die/' \
               's/^  1 | 2) ;;$/  *) ;;/' \
               's/^\[ -n "\${HOWL_NODE_RPC_URL:-}" \] || /true || /' \
               's/--listen "0.0.0.0:\$port"/--listen "0.0.0.0:8645"/'; do
    sed "$plant" "$here/entrypoint.sh" > "$scratch/entrypoint.sh"
    if cmp -s "$here/entrypoint.sh" "$scratch/entrypoint.sh"; then
      echo "red-proof: plant did not apply: $plant"; status=1; continue
    fi
    if ENTRYPOINT=$scratch/entrypoint.sh "$0" >/dev/null 2>&1; then
      echo "red-proof: the checks passed a copy planted with: $plant"; status=1
    else
      echo "red-proof: caught: $plant"
    fi
  done
  exit $status
fi

failed=0
data=$(mktemp -d)
trap 'rm -rf "$data"' EXIT
pool=0x6DABb5682A62b3827eE7e0E02F1DACE896AD457a
# A copy whose node binary is never there, so a check that let a bad value through ends in a
# failed exec (127), not in a node that happens to be installed.
sed 's|^node=.*$|node=/nonexistent/howl-node|' "$entry" > "$data/entrypoint.sh"
grep -q '^node=/nonexistent/howl-node$' "$data/entrypoint.sh" || { echo "check-entrypoint: no node= line"; exit 1; }

run() {  # run <env assignments...> -- <args...>: the entrypoint under exactly those variables
  local vars=()
  while [ "$1" != -- ]; do vars+=("$1"); shift; done
  shift
  env -i PATH="$PATH" "${vars[@]}" sh "$data/entrypoint.sh" "$@"
}

base=(HOWL_CHAIN_ID=421614 HOWL_POOL=$pool HOWL_DEPLOYMENT_BLOCK=312414608 HOWL_DATA_DIR=$data)

renders() {  # renders <expected> <env...> -- <args...>
  local want=$1; shift
  local got
  got=$(run "$@" 2>&1)
  [ "$got" = "$want" ] || { echo "check-entrypoint: rendered '$got', wanted '$want'"; failed=1; }
}

refuses() {  # refuses <message part> <env...> -- <args...>
  local part=$1; shift
  local out rc
  out=$(run "$@" 2>&1); rc=$?
  if [ "$rc" != 1 ] || ! grep -qF -- "$part" <<<"$out"; then
    echo "check-entrypoint: wanted exit 1 naming '$part', got $rc: $out"; failed=1
  fi
}

renders "--data-dir $data --chain-id 421614 --pool $pool --deployment-block 312414608 --param-set 1 --listen 0.0.0.0:8645" \
  "${base[@]}" -- --print-args
renders "--data-dir $data --chain-id 421614 --pool $pool --deployment-block 312414608 --param-set 2 --listen 0.0.0.0:9100 --rate 7" \
  "${base[@]}" HOWL_PARAM_SET=2 PORT=9100 -- --print-args --rate 7
renders "--data-dir /data --chain-id 421614 --pool $pool --deployment-block 312414608 --param-set 1 --listen 0.0.0.0:8645" \
  HOWL_CHAIN_ID=421614 HOWL_POOL=$pool HOWL_DEPLOYMENT_BLOCK=312414608 -- --print-args

# --print-args skips the endpoint check, so this one runs as a start would.
refuses HOWL_NODE_RPC_URL "${base[@]}" --
refuses HOWL_POOL HOWL_CHAIN_ID=1 HOWL_DEPLOYMENT_BLOCK=1 HOWL_DATA_DIR=$data -- --print-args
refuses HOWL_POOL "${base[@]}" HOWL_POOL=0x12 -- --print-args
refuses HOWL_POOL "${base[@]}" HOWL_POOL=0xZZABb5682A62b3827eE7e0E02F1DACE896AD457a -- --print-args
refuses HOWL_CHAIN_ID "${base[@]}" HOWL_CHAIN_ID=x1 -- --print-args
refuses HOWL_DEPLOYMENT_BLOCK "${base[@]}" HOWL_DEPLOYMENT_BLOCK= -- --print-args
refuses HOWL_PARAM_SET "${base[@]}" HOWL_PARAM_SET=3 -- --print-args
refuses PORT "${base[@]}" PORT=80a -- --print-args
refuses HOWL_DATA_DIR "${base[@]}" HOWL_DATA_DIR=data -- --print-args
refuses HOWL_DATA_DIR "${base[@]}" "HOWL_DATA_DIR=/da ta" -- --print-args
for flag in --listen --listen=127.0.0.1:1 --data-dir --chain-id --pool --deployment-block --param-set; do
  refuses "not $flag" "${base[@]}" -- --print-args "$flag" x
done

[ "$failed" = 0 ] && echo "check-entrypoint: ok"
exit "$failed"

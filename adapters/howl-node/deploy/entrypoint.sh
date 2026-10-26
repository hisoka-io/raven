#!/bin/sh
# Builds the node's arguments from the container's variables, hands the data directory to the
# node's user, and execs the node as that user. Arguments given to the container are passed on
# after these, so any other flag of the binary can be added there. The flags set here come only
# from the variables, so the health check probes the port the node binds and the volume holds
# its data.
#
#   HOWL_NODE_RPC_URL         JSON-RPC endpoint; read by the node itself, so a key in it stays out
#                             of the process list. It must take a block hash as the block of
#                             eth_call (EIP-1898). A pruned endpoint serves, provided it keeps
#                             the full log history and the state of the newest blocks within
#                             the walk depth (--walk-blocks, 64)
#   HOWL_CHAIN_ID             chain id
#   HOWL_POOL                 the pool's address, 0x-prefixed
#   HOWL_DEPLOYMENT_BLOCK     the block the pool was deployed in
#   HOWL_PARAM_SET            1 or 2 (default 1)
#   HOWL_DATA_DIR             the table and key material (default: RAILWAY_VOLUME_MOUNT_PATH when
#                             set, else /data, the image's volume)
#   PORT                      the node binds 0.0.0.0:$PORT (default 8645)
#   HOWL_NODE_OPERATOR_TOKEN  bearer token of /howl/v1/status, 16 bytes or more, generated at
#                             random (openssl rand -hex 32); read by the node itself. Unset, the
#                             route stays closed
#
# `entrypoint.sh --print-args [args]` prints the node's arguments and exits.
set -eu

HOWL_UID=1500
node=/usr/local/bin/howl-node

die() { echo "howl-node: $*" >&2; exit 1; }

whole() {  # name value
  case $2 in
    '' | *[!0-9]*) die "$1 '$2' is not a whole number" ;;
  esac
}

if [ "${1:-}" = --print-args ]; then
  shift
  print=1
else
  print=0
fi

[ -n "${HOWL_NODE_RPC_URL:-}" ] || [ "$print" = 1 ] || die "HOWL_NODE_RPC_URL is not set"
whole HOWL_CHAIN_ID "${HOWL_CHAIN_ID:-}"
whole HOWL_DEPLOYMENT_BLOCK "${HOWL_DEPLOYMENT_BLOCK:-}"
pool=${HOWL_POOL:-}
case $pool in
  0x????????????????????????????????????????) ;;
  *) die "HOWL_POOL '$pool' is not a 0x-prefixed 20-byte address" ;;
esac
case ${pool#0x} in
  *[!0-9a-fA-F]*) die "HOWL_POOL '$pool' is not hex" ;;
esac
param_set=${HOWL_PARAM_SET:-1}
case $param_set in
  1 | 2) ;;
  *) die "HOWL_PARAM_SET must be 1 or 2, not '$param_set'" ;;
esac
port=${PORT:-8645}
whole PORT "$port"
data=${HOWL_DATA_DIR:-${RAILWAY_VOLUME_MOUNT_PATH:-/data}}
case $data in
  /*) data=${data%/} ;;
  *) die "HOWL_DATA_DIR '$data' is not an absolute path" ;;
esac
case $data in
  '' | *[!A-Za-z0-9/._-]*) die "HOWL_DATA_DIR '$data' is not a plain path" ;;
esac

for arg in "$@"; do
  case $arg in
    --data-dir | --data-dir=*) die "set HOWL_DATA_DIR, not $arg" ;;
    --chain-id | --chain-id=*) die "set HOWL_CHAIN_ID, not $arg" ;;
    --pool | --pool=*) die "set HOWL_POOL, not $arg" ;;
    --deployment-block | --deployment-block=*) die "set HOWL_DEPLOYMENT_BLOCK, not $arg" ;;
    --param-set | --param-set=*) die "set HOWL_PARAM_SET, not $arg" ;;
    --listen | --listen=*) die "set PORT, not $arg" ;;
  esac
done

set -- --data-dir "$data" --chain-id "$HOWL_CHAIN_ID" --pool "$pool" \
  --deployment-block "$HOWL_DEPLOYMENT_BLOCK" --param-set "$param_set" \
  --listen "0.0.0.0:$port" "$@"

if [ "$print" = 1 ]; then
  printf '%s\n' "$*"
  exit 0
fi

mkdir -p "$data"
if [ "$(id -u)" = 0 ]; then
  # A platform volume is mounted root-owned.
  find "$data" -xdev ! -user "$HOWL_UID" -exec chown -h "$HOWL_UID:$HOWL_UID" {} +
  exec setpriv --reuid="$HOWL_UID" --regid="$HOWL_UID" --clear-groups --no-new-privs "$node" "$@"
fi
exec "$node" "$@"

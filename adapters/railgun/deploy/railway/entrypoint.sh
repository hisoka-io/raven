#!/bin/sh
# Renders the node's config from a shipped template and Railway's variables, hands the volume to
# the node's user, and execs the node as that user.
#
#   RAVEN_NETWORK              mainnet or sepolia: the template, examples/<network>-ppoi.toml
#   RAILWAY_VOLUME_MOUNT_PATH  set by Railway when a volume is attached; every data_dir moves
#                              under it. Required, so a node never syncs onto a disk a redeploy
#                              discards
#   PORT                       set by Railway; the node binds 0.0.0.0:$PORT (8080 when unset)
#   RAVEN_BEARER_TOKEN         read by the node itself for /metrics, never written to disk
#   RAVEN_MAX_SESSIONS         packing-key seats per instance (default 32)
#   RAVEN_MIRROR_ENDPOINT      the upstream aggregator (default: the template's)
#
# The template's trust_proxy_header = false stays: Railway's edge passes a client's
# cf-connecting-ip through, and the node takes that header as the client address from any
# trusted peer. The per-IP rate limit keys on the edge's address instead.
#
# `entrypoint.sh --print-config` prints the rendered config and exits.
set -eu

RAVEN_UID=1500
templates=${RAVEN_TEMPLATE_DIR:-/etc/raven-railgun}
config=/run/raven-railgun/config.toml

die() { echo "raven-railway: $*" >&2; exit 1; }

# Replace exactly one line matching the ERE, or fail: a template that changed shape must stop the
# boot rather than serve a half-edited config.
replace_one() {  # file pattern replacement
  n=$(grep -cE "$2" "$1" || true)
  [ "$n" = 1 ] || die "template: expected one line matching /$2/, found $n"
  awk -v pat="$2" -v rep="$3" '$0 ~ pat { print rep; next } { print }' "$1" >"$1.new"
  mv "$1.new" "$1"
}

render() {  # out
  out=$1
  case ${RAVEN_NETWORK:-} in
    mainnet | sepolia) ;;
    *) die "RAVEN_NETWORK must be mainnet or sepolia, not '${RAVEN_NETWORK:-}'" ;;
  esac
  volume=${RAILWAY_VOLUME_MOUNT_PATH:-}
  case $volume in
    /*) volume=${volume%/} ;;
    *) die "RAILWAY_VOLUME_MOUNT_PATH is not set: attach a volume to this service" ;;
  esac
  case $volume in
    *[!A-Za-z0-9/._-]* | '') die "RAILWAY_VOLUME_MOUNT_PATH '$volume' is not a plain path" ;;
  esac
  port=${PORT:-8080}
  case $port in
    '' | *[!0-9]*) die "PORT '$port' is not a number" ;;
  esac
  seats=${RAVEN_MAX_SESSIONS:-32}
  case $seats in
    '' | 0* | *[!0-9]*) die "RAVEN_MAX_SESSIONS '$seats' is not a whole number from 1" ;;
  esac

  cp "$templates/$RAVEN_NETWORK-ppoi.toml" "$out"
  replace_one "$out" '^bind = "[^"]*"$' "bind = \"0.0.0.0:$port\""
  # The node takes RAVEN_BEARER_TOKEN from its environment; a second source is a boot error.
  replace_one "$out" '^token = "REPLACE_ME"$' ""
  replace_one "$out" '^[[]global[]]$' "[global]
max_sessions_per_instance = $seats"
  if [ -n "${RAVEN_MIRROR_ENDPOINT:-}" ]; then
    case $RAVEN_MIRROR_ENDPOINT in
      *[\"\\]*) die "RAVEN_MIRROR_ENDPOINT holds a quote or backslash" ;;
    esac
    replace_one "$out" '^mirror_endpoint = "[^"]*"$' "mirror_endpoint = \"$RAVEN_MIRROR_ENDPOINT\""
  fi

  instances=$(grep -cE '^[[][[]instance[]][]]$' "$out" || true)
  dirs=$(grep -cE '^data_dir = "/srv/raven/data/[^"]+"$' "$out" || true)
  [ "$instances" -ge 1 ] && [ "$dirs" = "$instances" ] \
    || die "template: $instances instances but $dirs data_dir lines under /srv/raven/data"
  sed -e "s|^data_dir = \"/srv/raven/data/|data_dir = \"$volume/|" "$out" >"$out.new"
  mv "$out.new" "$out"
}

if [ "${1:-}" = --print-config ]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp" "$tmp.new"' EXIT
  render "$tmp"
  cat "$tmp"
  exit 0
fi

mkdir -p "${config%/*}"
render "$config"
chmod 0644 "$config"
node=/usr/local/bin/raven-railgun
if [ "$(id -u)" = 0 ]; then
  # Railway mounts a new volume root-owned.
  find "$volume" -xdev ! -user "$RAVEN_UID" -exec chown -h "$RAVEN_UID:$RAVEN_UID" {} +
  exec setpriv --reuid="$RAVEN_UID" --regid="$RAVEN_UID" --clear-groups --no-new-privs \
    "$node" serve-production --config "$config"
fi
exec "$node" serve-production --config "$config"

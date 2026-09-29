# Shared by deploy.sh and backup.sh; sourced, never run.
# shellcheck shell=bash disable=SC2034  # the constants are read by the scripts that source this

# The image runs as this user, and its volumes are created owned by it.
RAVEN_UID=1500
# Container paths fixed by the image.
DATA_DIR=/srv/raven/data
SECRETS_DIR=/srv/raven/secrets
CONFIG_PATH=$SECRETS_DIR/mainnet.toml
TOKEN_PATH=$SECRETS_DIR/bearer-token
TEMPLATE_PATH=/etc/raven-railgun/mainnet-ppoi.toml
# Above the node's own 8 s stop budget, so docker never kills a final commit.
STOP_TIMEOUT=30
# Debug switches in the respond path: never on a served node.
FORBIDDEN_ENV=(RAVEN_FORCE_PACKING_ONLINE RAVEN_PROFILE_RESPOND)

die() { echo "error: $*" >&2; exit 1; }
say() { echo "== $*"; }

# A tag can be moved to other bytes; a digest cannot.
require_pinned_image() {
  local ref=$1
  [[ $ref =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ || $ref =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "image '$ref' is not pinned: pass repo@sha256:<digest>, or sha256:<id> for an image loaded with docker load"
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    [[ $ref == *@sha256:* ]] || die "image $ref is not loaded on this host"
    docker pull "$ref" >/dev/null || die "cannot pull $ref"
  fi
  local env
  env=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ref")
  for var in "${FORBIDDEN_ENV[@]}"; do
    ! grep -q "^$var=" <<<"$env" || die "image $ref sets $var; refusing to run it"
  done
}

# Refuse a running container that carries a debug switch, whoever started it.
require_clean_container_env() {
  local name=$1 env
  env=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$name")
  for var in "${FORBIDDEN_ENV[@]}"; do
    ! grep -q "^$var=" <<<"$env" || die "container $name has $var set"
  done
}

# A helper container from the node image; its own user unless a -u is passed first.
helper() {
  docker run --rm -i --network none --entrypoint sh "$@"
}

volume_is_empty() {  # volume image
  helper -v "$1:$DATA_DIR:ro" "$2" -c "[ -z \"\$(ls -A $DATA_DIR)\" ]"
}

# Replace exactly one line matching `pattern` (an ERE anchored by the caller), or fail: a
# template that changed shape must stop the deploy rather than ship a half-edited config.
replace_one() {  # text pattern replacement
  local count
  count=$(grep -cE "$2" <<<"$1" || true)
  [[ $count == 1 ]] || die "config template: expected one line matching /$2/, found $count"
  awk -v pat="$2" -v rep="$3" '$0 ~ pat { print rep; next } { print }' <<<"$1"
}

# The image's template with the token read from a file, the mirror endpoint and proxy trust set.
# Every step returns on failure: errexit does not reach inside the command substitution callers
# run this in, and a half-edited config must never be written.
render_config() {  # image mirror_endpoint(empty keeps the template's) trusted_cidr(empty: trust none)
  local image=$1 endpoint=$2 trusted=$3 cfg
  cfg=$(docker run --rm --network none --entrypoint cat "$image" "$TEMPLATE_PATH") \
    || { echo "error: cannot read $TEMPLATE_PATH from $image" >&2; return 1; }
  cfg=$(replace_one "$cfg" '^token = "REPLACE_ME"$' "token_file = \"$TOKEN_PATH\"") || return 1
  if [[ -n $endpoint ]]; then
    cfg=$(replace_one "$cfg" '^mirror_endpoint = "[^"]*"$' "mirror_endpoint = \"$endpoint\"") || return 1
  fi
  if [[ -n $trusted ]]; then
    cfg=$(replace_one "$cfg" '^trust_proxy_header = false$' \
      "trust_proxy_header = true
trusted_proxy_cidrs = [\"$trusted\"]") || return 1
  fi
  printf '%s\n' "$cfg"
}

# Write the config (stdin) into a secrets volume, and mint the token if the volume has none.
# The token is written by the container and never passes through this shell.
install_secrets() {  # volume image
  helper -u "$RAVEN_UID:$RAVEN_UID" -v "$1:$SECRETS_DIR" "$2" -c "
    set -e
    umask 077
    cat > $CONFIG_PATH.new
    mv $CONFIG_PATH.new $CONFIG_PATH
    if [ ! -s $TOKEN_PATH ]; then
      head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > $TOKEN_PATH.new
      mv $TOKEN_PATH.new $TOKEN_PATH
    fi
    chmod 600 $CONFIG_PATH $TOKEN_PATH"
}

# An archive backup.sh wrote after a clean stop, unchanged since: its record says so.
check_archive() {  # tar
  local tar=$1 record=$1.clean-stop want got
  [[ -f $tar ]] || die "$tar not found"
  [[ -f $record ]] || die "$record not found: only an archive backup.sh took after a clean stop is installed"
  want=$(awk '$1 == "sha256" { print $2 }' "$record")
  got=$(sha256sum "$tar" | awk '{ print $1 }')
  [[ -n $want && $want == "$got" ]] || die "$tar does not match the checksum in $record"
}

# Unpack a backup.sh archive into an empty data volume, as the node's user.
restore_volume() {  # tar volume image
  local tar=$1 volume=$2 image=$3
  check_archive "$tar"
  # Mounted at the image's own path, so a new volume takes that directory's owner (the node's user).
  docker volume create "$volume" >/dev/null
  volume_is_empty "$volume" "$image" || die "volume $volume is not empty"
  # Root reads the archive whatever its mode, and everything unpacked is handed to the node's user.
  helper -u 0:0 -v "$volume:$DATA_DIR" -v "$(cd "$(dirname "$tar")" && pwd):/in:ro" "$image" \
    -c "tar -xf '/in/${tar##*/}' -C $DATA_DIR && chown -R $RAVEN_UID:$RAVEN_UID $DATA_DIR" \
    || die "unpacking $tar into $volume failed"
}

# One line per mirrored list: state rows_held upstream_rows consecutive_failures. Empty when the
# node does not answer.
feed_lines() {  # port
  curl -s -m 5 "http://127.0.0.1:$1/v1/health/ready" | python3 -c '
import json, sys
try:
    body = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
for f in body.get("mirror_feeds", []):
    print(f["state"], f["rows_held"], f["upstream_rows"], f["consecutive_failures"])
' 2>/dev/null || true
}

# Wait until every list is caught up, or `secs` pass. Fails at once if the container stops.
wait_caught_up() {  # container port secs
  local name=$1 port=$2 secs=$3 start lines
  start=$SECONDS
  while :; do
    if [[ $(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null) != true ]]; then
      echo "container $name stopped; its last log lines:" >&2
      docker logs --tail 20 "$name" >&2 2>&1 || true
      return 2
    fi
    lines=$(feed_lines "$port")
    if [[ -n $lines ]] && ! grep -qv '^caught_up ' <<<"$lines"; then
      echo "caught_up after $((SECONDS - start)) s: $lines"
      return 0
    fi
    if ((SECONDS - start >= secs)); then
      echo "not caught up after $secs s: ${lines:-no answer}"
      return 1
    fi
    sleep 1
  done
}

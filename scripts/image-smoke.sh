#!/usr/bin/env bash
# Runs a built node image once with no network and checks that it starts, serves and stops.
#
#   scripts/image-smoke.sh howl-node IMAGE      the Howl node (adapters/howl-node/deploy/Dockerfile)
#   scripts/image-smoke.sh railgun-node IMAGE   the Railgun node for Railway
#                                               (adapters/railgun/deploy/railway/Dockerfile)
#   scripts/image-smoke.sh --stub PORT_FILE     the stand-in PPOI upstream the Railgun run uses
#
# The node runs in a network namespace that holds only loopback, on a new volume mounted
# root-owned as a platform mounts one. The Howl node follows an endpoint nothing answers and
# still serves. The Railgun node refuses to boot with no rows and no upstream, so a stub that
# answers every request with an empty list, as the in-tree boot tests' upstream does, listens in
# that namespace. Checks: the liveness route answers from inside the container, and so does the
# image's HEALTHCHECK when it has one; the node runs as uid and gid 1500 with no supplementary
# groups and no_new_privs; everything on the volume belongs to 1500; `docker stop` ends it with
# exit code 0. Needs a Docker engine, and sudo for nsenter on the Railgun run.
set -uo pipefail

if [[ ${1:-} == --stub ]]; then
  exec python3 -I - "$2" <<'PY'
import http.server, json, pathlib, sys

class Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["content-length"])))
        body = json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": []}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

server = http.server.HTTPServer(("127.0.0.1", 0), Upstream)
pathlib.Path(sys.argv[1]).write_text(str(server.server_port))
server.serve_forever()
PY
fi

kind=${1:-} image=${2:-}
[[ -n $image ]] || { echo "usage: scripts/image-smoke.sh howl-node|railgun-node IMAGE" >&2; exit 2; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
name=smoke-$kind
holder=smoke-$kind-net
volume=smoke-$kind-data
# nocopy keeps the image's own /data out, so the volume stays as new and root-owned.
mount=type=volume,src=$volume,dst=/data,volume-nocopy
scratch=$(mktemp -d)
stub_pid=""
fails=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fails=$((fails + 1)); }
check() {  # label command...
  local label=$1
  shift
  if "$@"; then ok "$label"; else bad "$label"; fi
}
cleanup() {
  [[ -z $stub_pid ]] || sudo kill "$stub_pid" 2>/dev/null
  docker rm -f "$name" "$holder" >/dev/null 2>&1
  docker volume rm -f "$volume" >/dev/null 2>&1
  rm -rf "$scratch"
}
trap cleanup EXIT

case $kind in
  howl-node)
    comm=howl-node
    live=http://127.0.0.1:8645/howl/v1/health
    ;;
  railgun-node)
    comm=raven-railgun
    live=http://127.0.0.1:8080/v1/health/live
    ;;
  *)
    echo "unknown image kind '$kind': howl-node or railgun-node" >&2
    exit 2
    ;;
esac

docker volume create "$volume" >/dev/null || { echo "FAIL  docker volume create"; exit 1; }
owner=$(docker run --rm --network none --mount "$mount" --entrypoint stat "$image" -c %u:%g /data)
check "the new volume is mounted root-owned (got $owner)" test "$owner" = 0:0

# The namespace outlives the node, so a stub can listen in it before the node starts.
docker run -d --name "$holder" --network none --no-healthcheck --entrypoint sleep "$image" infinity >/dev/null \
  || { echo "FAIL  cannot start a container from $image"; exit 1; }

case $kind in
  howl-node)
    env=(-e HOWL_NODE_RPC_URL=http://127.0.0.1:9 -e HOWL_CHAIN_ID=421614
      -e HOWL_POOL=0x6DABb5682A62b3827eE7e0E02F1DACE896AD457a -e HOWL_DEPLOYMENT_BLOCK=312414608)
    ;;
  railgun-node)
    pid=$(docker inspect -f '{{.State.Pid}}' "$holder")
    sudo nsenter --target "$pid" --net "$here/image-smoke.sh" --stub "$scratch/port" &
    stub_pid=$!
    for _ in $(seq 100); do [[ -s $scratch/port ]] && break; sleep 0.1; done
    [[ -s $scratch/port ]] || { echo "FAIL  the stub upstream did not start"; exit 1; }
    # A fresh token per run: the node refuses to boot without one, and nothing reads it here.
    env=(-e RAVEN_NETWORK=mainnet -e RAILWAY_VOLUME_MOUNT_PATH=/data
      -e "RAVEN_MIRROR_ENDPOINT=http://127.0.0.1:$(cat "$scratch/port")"
      -e "RAVEN_BEARER_TOKEN=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')")
    ;;
esac

docker run -d --name "$name" --network "container:$holder" --mount "$mount" "${env[@]}" "$image" >/dev/null \
  || { echo "FAIL  docker run"; exit 1; }

running() { [[ $(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null) == true ]]; }
answered=""
for _ in $(seq 300); do
  if answered=$(docker exec "$name" curl -fsS -m 2 "$live" 2>/dev/null); then break; fi
  answered=""
  running || break
  sleep 1
done
if [[ -n $answered ]]; then ok "$live answers: $answered"; else bad "$live never answered"; fi

if [[ -n $(docker inspect -f '{{if .Config.Healthcheck}}yes{{end}}' "$image") ]]; then
  health=""
  for _ in $(seq 120); do
    health=$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null)
    if [[ $health != starting ]] || ! running; then break; fi
    sleep 1
  done
  check "docker reports the image's HEALTHCHECK healthy (got ${health:-none})" test "$health" = healthy
fi

ids=$(docker exec "$name" sh -c "for p in /proc/[0-9]*; do
    [ \"\$(cat \$p/comm 2>/dev/null)\" = $comm ] && grep -E '^(Uid|Gid|Groups|NoNewPrivs):' \$p/status; done")
has() { grep -qE "$1" <<<"$ids"; }
check "the node runs as uid 1500" has '^Uid:\s+1500\s+1500\s+1500\s+1500$'
check "the node runs as gid 1500" has '^Gid:\s+1500\s+1500\s+1500\s+1500$'
check "no supplementary groups" has '^Groups:\s*$'
check "no_new_privs is set" has '^NoNewPrivs:\s+1$'
[[ -n $ids ]] || echo "no $comm process found"
if owners=$(docker exec "$name" find /data -xdev ! -user 1500); then
  check "everything on /data belongs to 1500" test -z "$owners"
  [[ -z $owners ]] || echo "not owned by 1500: $owners"
else
  bad "cannot list /data in the container"
fi

docker stop -t 30 "$name" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
check "docker stop ends it with exit code 0 (got $code)" test "$code" = 0

if ((fails)); then
  echo "--- node log"
  docker logs "$name" 2>&1 | tail -n 60
  echo "image-smoke: $fails check(s) failed for $kind"
  exit 1
fi
echo "image-smoke: $kind started, served and stopped cleanly"

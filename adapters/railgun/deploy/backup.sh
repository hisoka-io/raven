#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=adapters/railgun/deploy/lib.sh
. "$here/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  backup.sh backup --out DIR [--name NAME] [--port PORT] [--wait SECS]
  backup.sh restore --from TAR --volume VOLUME [--image IMAGE]
  backup.sh verify --from TAR [--image IMAGE] [--name NAME] [--port PORT] [--plant-dir DIR] [--keep]

backup   Copies the data volume of the node deploy.sh runs (NAME-node, default raven-node) to
         DIR/NAME-data-<UTC time>.tar, with a .clean-stop record beside it (checksum, image,
         stop time and exit code, rows held). A data dir is consistent only while no process
         writes it: a copy of a running node can pair a snapshot with a write-ahead log from
         another moment. So it waits until every list is caught up (up to --wait SECS, default
         300, else it stops nothing and fails), stops the node, copies, and starts it again: a
         few seconds of downtime (the stop takes at most about 8 s, a warm boot about 4 s).
         A stop that exits non-zero, or whose log says the stop budget ran out, is not clean:
         the node is started again and no copy is kept. The archive is what deploy.sh
         --data-from installs as an instant-boot data dir.
restore  Unpacks an archive into VOLUME, which must be new or empty, owned by the node's user.
         IMAGE defaults to the one the record names.
verify   Proves an archive boots and that a mismatched dir is refused:
         1. restores it into a new volume NAME-verify-data and boots it as NAME-verify-node on
            127.0.0.1:PORT (default 18080), with an unreachable upstream so it touches no
            aggregator. It must answer ready with the rows the record names, then stop with
            exit code 0.
         2. boots the same dirs under the config for another list key: it must refuse to start.
         3. with --plant-dir DIR: puts DIR (an instance data dir another sync built) in place of
            the first instance's dir: it must refuse to start.
         Removes what it created unless --keep.
EOF
}

cmd=${1:-}
[[ -n $cmd ]] || { usage; exit 1; }
shift
out="" from="" volume="" image="" name=raven port="" wait_secs=300 plant_dir="" keep=0
while (($#)); do
  case $1 in
    --out) out=$2; shift ;;
    --from) from=$2; shift ;;
    --volume) volume=$2; shift ;;
    --image) image=$2; shift ;;
    --name) name=$2; shift ;;
    --port) port=$2; shift ;;
    --wait) wait_secs=$2; shift ;;
    --plant-dir) plant_dir=$2; shift ;;
    --keep) keep=1 ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
  shift
done

record_image() { awk '$1 == "image" { print $2 }' "$1.clean-stop"; }

backup() {
  local node=$name-node data=$name-data copy=$name-backup-copy stamp tar started_at t0 stop_s exit_code oom feeds logs
  [[ -n $out ]] || die "--out is required"
  port=${port:-8080}
  [[ $(docker inspect -f '{{.State.Running}}' "$node" 2>/dev/null) == true ]] || die "$node is not running"
  image=$(docker inspect -f '{{.Image}}' "$node")
  say "waiting up to $wait_secs s for every list to be caught up"
  wait_caught_up "$node" "$port" "$wait_secs" || die "not caught up; nothing was stopped"
  feeds=$(feed_lines "$port")
  started_at=$(docker inspect -f '{{.State.StartedAt}}' "$node")
  say "stopping $node"
  t0=$(date +%s.%N)
  docker stop "$node" >/dev/null
  stop_s=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')
  exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$node")
  oom=$(docker inspect -f '{{.State.OOMKilled}}' "$node")
  # Captured first: a grep that quits at its first match would fail the pipe under pipefail.
  logs=$(docker logs --since "$started_at" "$node" 2>&1)
  if [[ $exit_code != 0 || $oom != false ]] || grep -q 'stop budget' <<<"$logs"; then
    docker start "$node" >/dev/null
    die "the stop was not clean (exit $exit_code, oom $oom); $node is started again and no copy was made"
  fi
  mkdir -p "$out"
  out=$(cd "$out" && pwd)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  tar=$out/$name-data-$stamp.tar
  # Volume to volume while the node is down, which is quick; the archive is written from that
  # copy after the node is back.
  say "copying $data to $copy"
  docker volume rm "$copy" >/dev/null 2>&1 || true
  if ! helper -u 0:0 -v "$data:/from:ro" -v "$copy:/to" "$image" -c "cp -a /from/. /to/"; then
    docker start "$node" >/dev/null
    docker volume rm "$copy" >/dev/null 2>&1 || true
    die "copy failed; $node is started again"
  fi
  docker start "$node" >/dev/null
  echo "stop ${stop_s} s, exit code 0; node down for $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }') s"
  say "writing $tar"
  helper -u 0:0 -v "$copy:/from:ro" -v "$out:/out" "$image" \
    -c "tar -cf '/out/${tar##*/}' -C /from . && chown $(id -u):$(id -g) '/out/${tar##*/}'" \
    || { rm -f "$tar"; docker volume rm "$copy" >/dev/null; die "writing $tar failed"; }
  docker volume rm "$copy" >/dev/null
  {
    echo "sha256 $(sha256sum "$tar" | awk '{ print $1 }')"
    echo "image $image"
    echo "stopped_at $stamp"
    echo "stop_seconds $stop_s"
    echo "exit_code $exit_code"
    while read -r line; do echo "feed $line"; done <<<"$feeds"
  } >"$tar.clean-stop"
  echo "$tar ($(du -h "$tar" | cut -f1))"
}

# Poll a container until it exits; prints its exit code, or fails if it is still up after `secs`.
wait_exit() {  # container secs
  local start=$SECONDS
  while [[ $(docker inspect -f '{{.State.Running}}' "$1") == true ]]; do
    ((SECONDS - start < $2)) || return 1
    sleep 1
  done
  docker inspect -f '{{.State.ExitCode}}' "$1"
}

verify() {
  local ctr=$name-verify-node vol=$name-verify-data sec=$name-verify-secrets cfg key other
  local want got start t0 code line logs
  [[ -n $from ]] || die "--from is required"
  port=${port:-18080}
  check_archive "$from"
  image=${image:-$(record_image "$from")}
  require_pinned_image "$image"
  want=$(awk '$1 == "feed" { print $3 }' "$from.clean-stop" | sort | paste -sd ' ')
  [[ -n $want ]] || die "$from.clean-stop names no rows held"

  docker rm -f "$ctr" >/dev/null 2>&1 || true
  docker volume rm "$vol" "$sec" >/dev/null 2>&1 || true
  say "restoring into $vol"
  restore_volume "$from" "$vol" "$image"
  # Port 9 on the container's own loopback: nothing answers, so the copy serves what it holds.
  cfg=$(render_config "$image" "http://127.0.0.1:9" "") || die "cannot render the verify config"
  docker volume create "$sec" >/dev/null
  install_secrets "$sec" "$image" <<<"$cfg"

  run_verify_node() {
    docker rm -f "$ctr" >/dev/null 2>&1 || true
    docker run -d --name "$ctr" --user "$RAVEN_UID:$RAVEN_UID" \
      --publish "127.0.0.1:$port:8080" \
      --volume "$vol:$DATA_DIR" --volume "$sec:$SECRETS_DIR" \
      --read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges \
      --stop-signal SIGTERM --stop-timeout "$STOP_TIMEOUT" \
      "$image" serve-production --config "$CONFIG_PATH" >/dev/null
  }

  say "1. booting the restored copy on 127.0.0.1:$port"
  run_verify_node
  start=$SECONDS
  while :; do
    got=$(feed_lines "$port" | awk '{ print $2 }' | sort | paste -sd ' ')
    [[ $got != "$want" ]] || break
    [[ $(docker inspect -f '{{.State.Running}}' "$ctr") == true ]] \
      || { docker logs --tail 20 "$ctr" >&2; die "the restored copy did not boot"; }
    ((SECONDS - start < 120)) || die "the restored copy holds '$got' rows, the record says '$want'"
    sleep 0.5
  done
  echo "PASS restored copy ready in $((SECONDS - start)) s holding rows $got, as recorded"
  t0=$(date +%s.%N)
  docker stop "$ctr" >/dev/null
  code=$(docker inspect -f '{{.State.ExitCode}}' "$ctr")
  [[ $code == 0 ]] || die "the restored copy stopped with exit code $code"
  echo "PASS stop in $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }') s, exit code 0"

  say "2. the same dirs under the config for another list key"
  key=$(grep -oE '^list_key = "[0-9a-f]{64}"' <<<"$cfg" | head -1 | grep -oE '[0-9a-f]{64}')
  [[ -n $key ]] || die "the config names no list_key"
  other=${key%?}$([[ ${key: -1} == 0 ]] && echo 1 || echo 0)
  install_secrets "$sec" "$image" <<<"${cfg//$key/$other}"
  run_verify_node
  code=$(wait_exit "$ctr" 120) || die "the node served dirs built for another list"
  logs=$(docker logs "$ctr" 2>&1)
  line=$(grep -m1 'holds rows of a list other than the configured list' <<<"$logs") \
    || { tail -20 <<<"$logs" >&2; die "the node exited $code without the list refusal"; }
  echo "PASS refused, exit code $code: ${line:0:240}"

  if [[ -n $plant_dir ]]; then
    say "3. $plant_dir planted as the first instance's dir"
    [[ -d $plant_dir ]] || die "$plant_dir is not a directory"
    install_secrets "$sec" "$image" <<<"$cfg"
    local first
    first=$(grep -oE "^data_dir = \"$DATA_DIR/[^\"]+\"" <<<"$cfg" | head -1 | cut -d'"' -f2)
    helper -u 0:0 -v "$vol:$DATA_DIR" -v "$(cd "$plant_dir" && pwd):/plant:ro" "$image" \
      -c "rm -rf '$first' && cp -a /plant '$first' && chown -R $RAVEN_UID:$RAVEN_UID '$first'"
    run_verify_node
    code=$(wait_exit "$ctr" 120) || die "the node served a planted dir"
    logs=$(docker logs "$ctr" 2>&1)
    line=$(grep -m1 'Operator:' <<<"$logs") \
      || { tail -20 <<<"$logs" >&2; die "the node exited $code without naming the fix"; }
    echo "PASS refused, exit code $code: ${line:0:240}"
  fi

  if ((keep == 0)); then
    docker rm -f "$ctr" >/dev/null
    docker volume rm "$vol" "$sec" >/dev/null
  fi
}

case $cmd in
  backup) backup ;;
  restore)
    [[ -n $from && -n $volume ]] || die "restore needs --from and --volume"
    image=${image:-$(record_image "$from")}
    require_pinned_image "$image"
    restore_volume "$from" "$volume" "$image"
    echo "restored $from into $volume"
    ;;
  verify) verify ;;
  -h | --help) usage ;;
  *) die "unknown command $cmd (see --help)" ;;
esac

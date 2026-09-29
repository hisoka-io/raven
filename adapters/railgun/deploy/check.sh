#!/usr/bin/env bash
set -uo pipefail

usage() {
  cat <<'EOF'
Usage: check.sh [--help]

One check of a node deploy.sh installed. deploy.sh runs it every minute from a systemd timer.
It alerts when:
  readiness  /v1/health/ready does not answer 200 (the node is down, starting a cold sync
             with no rows yet, or a list feed has stopped)
  behind     a list has not been caught up with upstream for more than RAVEN_BEHIND_SECS, or
             upstream last answered its feed more than RAVEN_BEHIND_SECS ago (a caught-up feed
             asks every 30 s). This catches a cold sync that runs long, a feed held at a row it
             cannot take, and a feed that stopped asking
  lag        a list holds more than RAVEN_MAX_LAG_ROWS fewer rows than upstream's latest answers
             show it has (upstream_rows_seen - rows_held), in any state; the behind clock above
             still catches a feed that stops answering
  failures   upstream has failed more than RAVEN_MAX_FAILURES requests in a row (30 s apart)
  disk       the data volume has less than RAVEN_MIN_FREE_MB free
  rss        the node process holds more than RAVEN_MAX_RSS_MB resident

An alert is sent when the set of alerts changes (a clear is sent as "resolved"), and again every
RAVEN_ALERT_REPEAT_SECS while it lasts. It is printed, which the timer's unit writes to the
journal, and posted as JSON {"text": ...} to RAVEN_ALERT_WEBHOOK when that is set. A post the
webhook does not answer with 2xx is sent again on the next run.
Exits 1 while any alert holds.

Environment (defaults in brackets):
  RAVEN_NAME [raven]  RAVEN_PORT [8080]  RAVEN_ALERT_WEBHOOK []
  RAVEN_BEHIND_SECS [900]  RAVEN_MAX_LAG_ROWS [500]  RAVEN_MAX_FAILURES [5]
  RAVEN_MIN_FREE_MB [2048]
  RAVEN_MAX_RSS_MB [3072] (three quarters of deploy.sh's default 4g cap)
  RAVEN_ALERT_REPEAT_SECS [3600]  RAVEN_ALERT_STATE [a file under /var/lib/raven, or
  ~/.local/state/raven when not root; the behind check keeps its clock beside it]
EOF
}
[[ ${1:-} != -h && ${1:-} != --help ]] || { usage; exit 0; }

name=${RAVEN_NAME:-raven}
port=${RAVEN_PORT:-8080}
node=$name-node
behind_secs=${RAVEN_BEHIND_SECS:-900}
max_lag=${RAVEN_MAX_LAG_ROWS:-500}
max_failures=${RAVEN_MAX_FAILURES:-5}
min_free_mb=${RAVEN_MIN_FREE_MB:-2048}
max_rss_mb=${RAVEN_MAX_RSS_MB:-3072}
repeat=${RAVEN_ALERT_REPEAT_SECS:-3600}
if ((EUID == 0)); then state_dir=/var/lib/raven; else state_dir=${XDG_STATE_HOME:-$HOME/.local/state}/raven; fi
state=${RAVEN_ALERT_STATE:-$state_dir/$name-alerts}
behind_state=$state.behind
now=$(date +%s)

alerts=()
add() { alerts+=("$1: $2"); }

reply=$(curl -s -m 5 -w '\n%{http_code}' "http://127.0.0.1:$port/v1/health/ready")
code=${reply##*$'\n'}
body=${reply%$'\n'*}
if [[ $code != 200 ]]; then
  status=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} oom={{.State.OOMKilled}}' "$node" 2>/dev/null || echo "no container $node")
  add readiness "HTTP ${code/#000/no answer}; container $status"
fi

# When each list was first seen short of caught_up, carried from run to run.
declare -A since=() behind=()
if [[ -f $behind_state ]]; then
  while read -r k t; do [[ -n $k && $t =~ ^[0-9]+$ ]] && since[$k]=$t; done <"$behind_state"
fi
feeds_seen=0
# One line per list: key state rows_held upstream_rows_seen seconds_since_answer failures
# last_failure.
while read -r key feed_state held seen answered failures last_failure; do
  [[ -n $key ]] || continue
  feeds_seen=1
  if [[ $feed_state != caught_up ]]; then
    behind[$key]=${since[$key]:-$now}
    if ((now - behind[$key] > behind_secs)); then
      add behind "list $key $feed_state for $((now - behind[$key])) s, holding $held rows"
    fi
  fi
  if [[ $seen =~ ^[0-9]+$ ]] && ((seen - held > max_lag)); then
    add lag "list $key holds $held rows, $((seen - held)) behind the $seen upstream has shown"
  fi
  if [[ $answered =~ ^[0-9]+$ ]] && ((answered > behind_secs)); then
    add behind "list $key: upstream last answered $answered s ago"
  fi
  if ((failures > max_failures)); then
    add failures "list $key: $failures upstream requests failed in a row, last $last_failure"
  fi
done < <(python3 -c '
import json, sys
try:
    feeds = json.loads(sys.argv[1]).get("mirror_feeds", [])
except ValueError:
    feeds = []
for f in feeds:
    print(f["list_key"][:16], f["state"], f["rows_held"], f.get("upstream_rows_seen"),
          f["seconds_since_answer"], f["consecutive_failures"], f["last_failure"])
' "$body")
# A node that did not answer keeps the clock running rather than restarting it.
if ((feeds_seen)); then
  mkdir -p "$(dirname "$behind_state")"
  for k in "${!behind[@]}"; do echo "$k ${behind[$k]}"; done >"$behind_state"
fi

if [[ $(docker inspect -f '{{.State.Running}}' "$node" 2>/dev/null) == true ]]; then
  free_kb=$(docker exec "$node" df -Pk /srv/raven/data | awk 'NR == 2 { print $4 }')
  if [[ $free_kb =~ ^[0-9]+$ ]] && ((free_kb / 1024 < min_free_mb)); then
    add disk "$((free_kb / 1024)) MB free on the data volume"
  fi
  # The process under tini, by name: PID 1 is tini.
  rss_kb=$(docker exec "$node" sh -c 'for p in /proc/[0-9]*; do
      [ "$(cat "$p/comm" 2>/dev/null)" = raven-railgun ] && sed -n "s/^VmRSS:[[:space:]]*\([0-9]*\).*/\1/p" "$p/status"
    done')
  if [[ $rss_kb =~ ^[0-9]+$ ]] && ((rss_kb / 1024 > max_rss_mb)); then
    add rss "node holds $((rss_kb / 1024)) MB resident"
  fi
fi

keys=$(for a in "${alerts[@]}"; do echo "${a%%:*}"; done | sort -u | paste -sd ' ')
last_sent=0 last_keys=""
if [[ -f $state ]]; then read -r last_sent last_keys <"$state" || true; fi
last_keys=${last_keys:-}
message=""
if ((${#alerts[@]})); then
  if [[ $keys != "$last_keys" ]] || ((now - last_sent >= repeat)); then
    message="ALERT $name on $(hostname): $(printf '%s\n' "${alerts[@]}" | paste -sd ';' | sed 's/;/; /g')"
  fi
elif [[ -n $last_keys ]]; then
  message="RESOLVED $name on $(hostname): $last_keys"
fi

for a in "${alerts[@]}"; do echo "alert $a"; done
if [[ -n $message ]]; then
  echo "$message"
  delivered=1
  if [[ -n ${RAVEN_ALERT_WEBHOOK:-} ]]; then
    python3 -c 'import json, sys; print(json.dumps({"text": sys.argv[1]}))' "$message" \
      | curl -fsS -m 10 -o /dev/null -H 'content-type: application/json' --data-binary @- "$RAVEN_ALERT_WEBHOOK" \
      || { delivered=0; echo "webhook post failed; sending it again on the next run"; }
  fi
  # Recorded as sent only once delivered, so a failed post is retried rather than held back.
  if ((delivered)); then
    mkdir -p "$(dirname "$state")"
    echo "$now $keys" >"$state"
  fi
fi
((${#alerts[@]} == 0))

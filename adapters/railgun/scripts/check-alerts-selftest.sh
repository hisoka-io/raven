#!/usr/bin/env bash
# Red-proof for deploy/check.sh: each case serves a canned /v1/health/ready and webhook from a
# local stub, with a stub docker on PATH, and asserts which alerts check.sh raises and posts.
# CHECK_SH points it at another copy of check.sh.
# shellcheck disable=SC2016,SC2329  # expect evals its condition, which is where posts runs
set -uo pipefail

adapter=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
check=${CHECK_SH:-$adapter/deploy/check.sh}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/check-alerts-selftest.XXXXXX")
stub_pid=""
trap '[[ -z $stub_pid ]] || kill "$stub_pid" 2>/dev/null; rm -rf "$scratch"' EXIT
failed=0
fake=$scratch/fake
mkdir -p "$fake" "$scratch/bin"

cat >"$scratch/bin/docker" <<'EOF'
#!/bin/sh
case "$1 $3" in
  "inspect {{.State.Running}}") echo true ;;
  inspect*) echo "running exit=0 restarts=0 oom=false" ;;
  "exec df") printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 1 1 %s 1%% /srv\n' "$(cat "$FAKE/free_kb")" ;;
  "exec sh") cat "$FAKE/rss_kb" ;;
esac
EOF
chmod +x "$scratch/bin/docker"

python3 - "$fake" <<'EOF' &
import http.server, pathlib, sys
fake = pathlib.Path(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self.reply(int((fake / "code").read_text()), (fake / "body").read_text().encode())
    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        with open(fake / "posts", "ab") as f:
            f.write(body + b"\n")
        self.reply(int((fake / "hook_code").read_text()))
s = http.server.HTTPServer(("127.0.0.1", 0), H)
(fake / "port").write_text(str(s.server_port))
s.serve_forever()
EOF
stub_pid=$!
for _ in $(seq 200); do [[ -s $fake/port ]] && break; sleep 0.1; done
[[ -s $fake/port ]] || { echo "FAIL the stub server did not start"; exit 1; }
port=$(cat "$fake/port")

# serve <http code> <state> <rows_held> <seconds_since_answer|null> <failures>
serve() {
  echo "$1" >"$fake/code"
  printf '{"mirror_feeds":[{"list_key":"%s","state":"%s","rows_held":%s,"upstream_rows":null,"consecutive_failures":%s,"last_failure":null,"seconds_since_answer":%s}]}' \
    "$(printf 'ab%.0s' $(seq 32))" "$2" "$3" "$5" "$4" >"$fake/body"
}
reset() {
  serve 200 caught_up 363278 3 0
  echo 200 >"$fake/hook_code"
  echo 99999999 >"$fake/free_kb"
  echo 1000000 >"$fake/rss_kb"
  : >"$fake/posts"
  state=$scratch/state-$1
  rm -f "$state" "$state.behind"
}
out=""
run() {  # env assignments for check.sh
  out=$(env PATH="$scratch/bin:$PATH" FAKE="$fake" RAVEN_PORT="$port" RAVEN_ALERT_STATE="$state" \
    RAVEN_ALERT_WEBHOOK= "$@" "$check" 2>&1)
}
posts() { grep -c . "$fake/posts"; }
expect() {  # label condition
  if eval "$2"; then echo "ok   $1"; else echo "FAIL $1: $out"; failed=1; fi
}

reset healthy
run
expect "a caught-up node raises nothing" '[[ -z $out ]]'

reset behind
serve 200 syncing 206559 0 0
run RAVEN_BEHIND_SECS=1
expect "a feed just seen syncing raises nothing yet" '[[ $out != *behind* ]]'
sleep 2
run RAVEN_BEHIND_SECS=1
expect "a feed syncing past RAVEN_BEHIND_SECS raises behind" '[[ $out == *"alert behind: list abababababababab syncing for"* ]]'
serve 200 caught_up 363278 0 0
run RAVEN_BEHIND_SECS=1
expect "catching up resolves behind" '[[ $out == *"RESOLVED"*behind* && ! -s $state.behind ]]'

reset unanswered
serve 200 syncing 206559 0 0
run RAVEN_BEHIND_SECS=1
serve 503 syncing 206559 0 0
echo "" >"$fake/body"
sleep 2
run RAVEN_BEHIND_SECS=1
serve 200 syncing 206559 0 0
run RAVEN_BEHIND_SECS=1
expect "a run the node does not answer keeps the behind clock" '[[ $out == *"alert behind: "*syncing* ]]'

reset silent
serve 200 caught_up 363278 5000 0
run
expect "an upstream silent past RAVEN_BEHIND_SECS raises behind" '[[ $out == *"upstream last answered 5000 s ago"* ]]'

reset failures
serve 200 upstream_refusing 363000 20 9
run
expect "failures past RAVEN_MAX_FAILURES raise failures" '[[ $out == *"alert failures: "* ]]'

reset readiness
serve 503 never_fed 0 null 0
run
expect "readiness red raises readiness" '[[ $out == *"alert readiness: HTTP 503"* ]]'

reset resources
echo 1024 >"$fake/free_kb"
echo 4000000 >"$fake/rss_kb"
run
expect "low disk and high RSS raise disk and rss" '[[ $out == *"alert disk: 1 MB free"* && $out == *"alert rss: node holds 3906 MB"* ]]'

reset hook-ok
serve 503 never_fed 0 null 0
run RAVEN_ALERT_WEBHOOK="http://127.0.0.1:$port/hook"
run RAVEN_ALERT_WEBHOOK="http://127.0.0.1:$port/hook"
expect "a delivered alert is posted once, not every run" '[[ $(posts) == 1 ]]'

reset hook-5xx
echo 500 >"$fake/hook_code"
serve 503 never_fed 0 null 0
run RAVEN_ALERT_WEBHOOK="http://127.0.0.1:$port/hook"
expect "a webhook answering 500 is reported as failed" '[[ $out == *"webhook post failed"* ]]'
run RAVEN_ALERT_WEBHOOK="http://127.0.0.1:$port/hook"
expect "an alert the webhook refused is posted again next run" '[[ $(posts) == 2 ]]'

reset hook-down
serve 503 never_fed 0 null 0
run RAVEN_ALERT_WEBHOOK="http://127.0.0.1:1/hook"
run RAVEN_ALERT_WEBHOOK="http://127.0.0.1:1/hook"
expect "an unreachable webhook is retried every run" '[[ $out == *"webhook post failed"* && ! -f $state ]]'

exit $failed

#!/usr/bin/env bash
# The deploy files' claims about the code they run, checked against the code:
#   1. every cargo build in an adapter Dockerfile passes --locked, so an image is built from the
#      committed Cargo.lock and never a fresh resolve;
#   2. the operator image declares STOPSIGNAL SIGTERM, the signal the node's shutdown handles;
#   3. the Dockerfile's stated stop budget is the node's STOP_BUDGET, and deploy.sh's stop timeout
#      is at least twice it, so docker never kills a final commit;
#   4. the Caddyfile drops a client's cf-connecting-ip, which the node takes as the client
#      address from a trusted proxy;
#   5. deploy.sh publishes the node's port on 127.0.0.1 only;
#   6. the Caddyfile binds IPv4 only (tcp4), since a bare address opens a dual-stack socket.
# DEPLOY_CHECK_ROOT points it at a copy of the adapter directory (its selftest does).
set -uo pipefail

root=${DEPLOY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
failed=0
fail() { echo "check-deploy: $1"; failed=1; }

for dockerfile in "$root"/Dockerfile*; do
  # A RUN continued over several lines is one command; join them before looking for the flag.
  while IFS= read -r run; do
    [[ $run == *--locked* ]] || fail "${dockerfile##*/}: cargo build without --locked: $run"
  done < <(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$dockerfile" | grep -E '^RUN .*cargo (build|install)')
done

grep -qx 'STOPSIGNAL SIGTERM' "$root/Dockerfile" || fail "Dockerfile: no STOPSIGNAL SIGTERM"

budget=$(grep -oE 'const STOP_BUDGET: std::time::Duration = std::time::Duration::from_secs\([0-9]+\)' \
  "$root/cli/src/serve_production_multi.rs" | grep -oE '[0-9]+\)$' | tr -d ')')
timeout=$(grep -oE '^STOP_TIMEOUT=[0-9]+$' "$root/deploy/lib.sh" | cut -d= -f2)
stated=$(grep -oE "^# SIGTERM starts the node's [0-9]+ s stop budget" "$root/Dockerfile" | grep -oE '[0-9]+')
if [[ -z $budget || -z $timeout || -z $stated ]]; then
  fail "could not read STOP_BUDGET (${budget:-none}), STOP_TIMEOUT (${timeout:-none}) or the Dockerfile's stop budget (${stated:-none})"
else
  [[ $stated == "$budget" ]] || fail "Dockerfile states a $stated s stop budget; STOP_BUDGET is $budget s"
  ((timeout >= 2 * budget)) || fail "deploy/lib.sh STOP_TIMEOUT=$timeout is under twice STOP_BUDGET ($budget s)"
fi

grep -qE '^[[:space:]]*header_up -Cf-Connecting-Ip$' "$root/deploy/Caddyfile" \
  || fail "deploy/Caddyfile does not drop a client's cf-connecting-ip"

grep -qE '^[[:space:]]*default_bind tcp4/[^[:space:]]+$' "$root/deploy/Caddyfile" \
  || fail "deploy/Caddyfile does not bind IPv4 only (default_bind tcp4/...)"

publishes=$(grep -oE -- '--publish "[^"]*"' "$root/deploy/deploy.sh")
[[ -n $publishes ]] || fail "deploy/deploy.sh publishes no port"
while IFS= read -r p; do
  [[ -z $p || $p == '--publish "127.0.0.1:'* ]] || fail "deploy/deploy.sh publishes beyond loopback: $p"
done <<<"$publishes"

((failed == 0)) && echo "check-deploy: ok"
exit $failed

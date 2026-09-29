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
#   6. the Caddyfile binds IPv4 only (tcp4), since a bare address opens a dual-stack socket;
#   7. deploy.sh's default --memory holds its default worst case for the image template's
#      instances, worst_case_mib in deploy/lib.sh, and --help states that figure; the seat size
#      there is for the template's 512 B rows;
#   8. the Railway image builds the binary exactly as the operator image does (the same build
#      stage) and declares no VOLUME, since Railway attaches its own;
#   9. the Railway service settings (deploy/railway/configure.sh) give the node at least twice
#      STOP_BUDGET between SIGTERM and SIGKILL, and health-check a route the node serves;
#  10. the Railway entrypoint renders both shipped templates to bind 0.0.0.0:$PORT, carry no token
#      source beside RAVEN_BEARER_TOKEN, trust no forwarding header (Railway's edge passes a
#      client's cf-connecting-ip through), and keep every instance's data under the volume.
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

template=$root/examples/mainnet-ppoi.toml
memory=$(grep -oE '^image=.* memory=[0-9]+[a-z]*$' "$root/deploy/deploy.sh" | grep -oE '[0-9]+[a-z]*$')
seats=$(grep -oE '^max_sessions=[0-9]+ ' "$root/deploy/deploy.sh" | grep -oE '[0-9]+')
instances=$(grep -cE '^[[][[]instance[]][]]$' "$template")
grep -qx 'record_size = 512' "$template" \
  || fail "examples/mainnet-ppoi.toml: record_size is not 512, the row size deploy/lib.sh SEAT_MIB is for"
if [[ -z $memory || -z $seats || $instances == 0 ]]; then
  fail "could not read deploy.sh's default memory (${memory:-none}) or seats (${seats:-none}), or the template's instances ($instances)"
else
  (
    # shellcheck source=adapters/railgun/deploy/lib.sh
    . "$root/deploy/lib.sh"
    die() { echo "check-deploy: $*"; exit 1; }
    cap=$(memory_mib "$memory") || die "deploy.sh's default memory $memory does not parse"
    worst=$(worst_case_mib "$seats" "$instances")
    ((worst <= cap)) || die "deploy.sh defaults do not fit: $seats seats x $instances instances need $worst MiB, over the $memory cap"
    grep -qF "The defaults need $worst MiB for the template's $instances instances" "$root/deploy/deploy.sh" \
      || die "deploy.sh --help does not state the defaults' $worst MiB for $instances instances"
  ) || failed=1
fi

railway=$root/deploy/railway
build_stage() { awk '/^FROM /{n++} n==1' "$1"; }
[[ -n $(build_stage "$railway/Dockerfile") && $(build_stage "$root/Dockerfile") == "$(build_stage "$railway/Dockerfile")" ]] \
  || fail "deploy/railway/Dockerfile: its build stage is not the operator Dockerfile's"
! grep -qE '^VOLUME' "$railway/Dockerfile" || fail "deploy/railway/Dockerfile declares a VOLUME"

draining=$(grep -oE '^ +drainingSeconds: [0-9]+,?$' "$railway/configure.sh" | grep -oE '[0-9]+')
if [[ -z $draining || -z $budget ]]; then
  fail "could not read configure.sh drainingSeconds (${draining:-none}) or STOP_BUDGET (${budget:-none})"
else
  ((draining >= 2 * budget)) || fail "configure.sh drainingSeconds=$draining is under twice STOP_BUDGET ($budget s)"
fi
health=$(grep -oE '^ +healthcheckPath: "[^"]+",?$' "$railway/configure.sh" | cut -d'"' -f2)
if [[ -z $health ]] || ! grep -qF ".route(\"$health\"" "$root/http/src/lib.rs"; then
  fail "configure.sh healthcheckPath '${health:-none}' is not a route the node serves"
fi

# The token must not be readable back from Railway, where the account's other members can see it.
sets=$(grep -cE "token_patch '[{]value: " "$railway/configure.sh" || true)
sealed=$(grep -cE "token_patch '[{]value: input, isSealed: true[}]'" "$railway/configure.sh" || true)
if [[ $sets == 0 || $sealed != "$sets" ]] || grep -qE 'name: "RAVEN_BEARER_TOKEN"|RAVEN_BEARER_TOKEN: [$]' "$railway/configure.sh"; then
  fail "configure.sh sets RAVEN_BEARER_TOKEN without sealing it"
fi

for net in mainnet sepolia; do
  if ! out=$(RAVEN_TEMPLATE_DIR=$root/examples RAVEN_NETWORK=$net RAILWAY_VOLUME_MOUNT_PATH=/vol \
    PORT=4321 sh "$railway/entrypoint.sh" --print-config 2>&1); then
    fail "deploy/railway/entrypoint.sh cannot render $net: $out"
    continue
  fi
  [[ $(grep -cx 'bind = "0.0.0.0:4321"' <<<"$out") == 1 ]] \
    || fail "the rendered $net config does not bind 0.0.0.0:\$PORT"
  ! grep -qE '^(token|token_file) = ' <<<"$out" \
    || fail "the rendered $net config carries a token source beside RAVEN_BEARER_TOKEN"
  if [[ $(grep -cE '^trust_proxy_header = ' <<<"$out") != 1 ]] || ! grep -qx 'trust_proxy_header = false' <<<"$out"; then
    fail "the rendered $net config trusts forwarding headers"
  fi
  want=$(grep -cE '^[[][[]instance[]][]]$' "$root/examples/$net-ppoi.toml")
  got=$(grep -cE '^data_dir = "/vol/[^"]+"$' <<<"$out")
  [[ $want -ge 1 && $got == "$want" && $(grep -cE '^data_dir = ' <<<"$out") == "$want" ]] \
    || fail "the rendered $net config keeps $got of $want instances' data under the volume"
done

((failed == 0)) && echo "check-deploy: ok"
exit $failed

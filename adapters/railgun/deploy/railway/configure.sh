#!/usr/bin/env bash
# Applies a Railway service's settings for one node. Railway reads no railway.toml for a service
# created now, so the settings live on the service and this script is their record; running it
# again changes nothing. RAILWAY_API_TOKEN is an account or workspace token from Railway.
#   configure.sh --project ID --environment ID --service ID --network mainnet|sepolia
#                [--mint-token | --token-stdin]
# RAVEN_BEARER_TOKEN, which opens /metrics, is always sealed: deployments receive it, and once the
# service has deployed with it Railway's API and CLI no longer return it. So whoever
# scrapes /metrics must hold the token before it is set:
#   --token-stdin  sets it to the line on stdin (a pipe from a secret store; 32 characters or more)
#   --mint-token   sets it to 32 random bytes in hex that nobody holds, closing /metrics
# Either replaces a token already set, and neither passes it through a file, an argument list or
# the terminal. Without them the service must already have a token, which is sealed if it is not.
# Nothing here deploys: the next up.sh or `railway redeploy` applies the settings.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

project="" environment="" service="" network="" token_src=""
while (($#)); do
  case $1 in
    --project) project=$2; shift ;;
    --environment) environment=$2; shift ;;
    --service) service=$2; shift ;;
    --network) network=$2; shift ;;
    --mint-token) token_src=mint ;;
    --token-stdin) token_src=stdin ;;
    *) die "unknown option $1" ;;
  esac
  shift
done
[[ -n $project && -n $environment && -n $service ]] || die "--project, --environment and --service are required"
[[ -n ${RAILWAY_API_TOKEN:-} ]] || die "RAILWAY_API_TOKEN is not set"
if [[ $token_src == stdin ]]; then
  [[ ! -t 0 ]] || die "--token-stdin reads a pipe, not a terminal"
  IFS= read -r token || [[ -n ${token:-} ]] || die "--token-stdin: stdin is empty"
  [[ ${#token} -ge 32 && $token != *[[:space:]]* ]] || die "--token-stdin: need 32 or more characters, no spaces"
fi
# The node's worst case at 32 seats (deploy/lib.sh worst_case_mib) is 8,243 MiB for mainnet's
# seven instances and 4,403 MiB for Sepolia's two; each limit leaves room above it.
case $network in
  mainnet) memory_gb=10 vcpus=8 ;;
  sepolia) memory_gb=6 vcpus=4 ;;
  *) die "--network must be mainnet or sepolia" ;;
esac

# Body on stdin; the token goes in a header read from a pipe, never an argument.
gql() {
  local out
  out=$(curl -sS --fail-with-body https://backboard.railway.com/graphql/v2 \
    -H @<(printf 'Authorization: Bearer %s\n' "$RAILWAY_API_TOKEN") \
    -H 'Content-Type: application/json' --data-binary @-) || die "Railway API: $out"
  jq -e 'has("errors") | not' <<<"$out" >/dev/null || die "Railway API: $(jq -c .errors <<<"$out")"
  printf '%s\n' "$out"
}

ids=$(jq -n --arg p "$project" --arg e "$environment" --arg s "$service" \
  '{projectId: $p, environmentId: $e, serviceId: $s}')

# Live, not ready: ready is 503 while a mirrored list holds no row, as at the start of every cold
# sync. SIGTERM to SIGKILL is twice the node's 15 s stop budget.
jq -n --argjson ids "$ids" '{
  query: "mutation($s: String!, $e: String!, $i: ServiceInstanceUpdateInput!) { serviceInstanceUpdate(serviceId: $s, environmentId: $e, input: $i) }",
  variables: {s: $ids.serviceId, e: $ids.environmentId, i: {
    dockerfilePath: "adapters/railgun/deploy/railway/Dockerfile",
    healthcheckPath: "/v1/health/live",
    healthcheckTimeout: 300,
    drainingSeconds: 30,
    restartPolicyType: "ON_FAILURE",
    restartPolicyMaxRetries: 5
  }}}' | gql >/dev/null

jq -n --argjson ids "$ids" --argjson m "$memory_gb" --argjson c "$vcpus" '{
  query: "mutation($i: ServiceInstanceLimitsUpdateInput!) { serviceInstanceLimitsUpdate(input: $i) }",
  variables: {i: {serviceId: $ids.serviceId, environmentId: $ids.environmentId, memoryGB: $m, vCPUs: $c}}}' | gql >/dev/null

# PORT is pinned so the domain's target port and the node's bind cannot drift apart.
port=8080
# shellcheck disable=SC2016  # GraphQL variables, not shell
jq -n --argjson ids "$ids" --arg n "$network" --arg p "$port" '{
  query: "mutation($i: VariableCollectionUpsertInput!) { variableCollectionUpsert(input: $i) }",
  variables: {i: ($ids + {variables: {RAVEN_NETWORK: $n, PORT: $p}, skipDeploys: true})}}' | gql >/dev/null

# shellcheck disable=SC2016
domains=$(jq -n --argjson ids "$ids" '{
  query: "query($p: String!, $e: String!, $s: String!) { domains(projectId: $p, environmentId: $e, serviceId: $s) { serviceDomains { id domain } } }",
  variables: {p: $ids.projectId, e: $ids.environmentId, s: $ids.serviceId}}' | gql | jq -c '.data.domains.serviceDomains')
if [[ $domains == '[]' ]]; then
  # shellcheck disable=SC2016
  jq -n --argjson ids "$ids" --argjson p "$port" '{
    query: "mutation($i: ServiceDomainCreateInput!) { serviceDomainCreate(input: $i) { domain } }",
    variables: {i: {environmentId: $ids.environmentId, serviceId: $ids.serviceId, targetPort: $p}}}' | gql >/dev/null
else
  jq -c '.[]' <<<"$domains" | while read -r d; do
    # shellcheck disable=SC2016
    jq -n --argjson ids "$ids" --argjson d "$d" --argjson p "$port" '{
      query: "mutation($i: ServiceDomainUpdateInput!) { serviceDomainUpdate(input: $i) }",
      variables: {i: {environmentId: $ids.environmentId, serviceId: $ids.serviceId,
        serviceDomainId: $d.id, domain: $d.domain, targetPort: $p}}}' | gql >/dev/null
  done
fi

# A patch, not variableUpsert: only the environment config can seal a variable.
# shellcheck disable=SC2016
patch='mutation($e: String!, $p: EnvironmentConfig!) { environmentPatchCommit(environmentId: $e, patch: $p, skipDeploys: true) }'
token_patch() {  # jq filter for the variable's entry; `input` is stdin's line
  jq -nR --argjson ids "$ids" --arg q "$patch" "{query: \$q, variables: {e: \$ids.environmentId,
    p: {services: {(\$ids.serviceId): {variables: {RAVEN_BEARER_TOKEN: ($1)}}}}}}" | gql >/dev/null
}
if [[ $token_src == mint ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | token_patch '{value: input, isSealed: true}'
elif [[ $token_src == stdin ]]; then
  printf '%s\n' "$token" | token_patch '{value: input, isSealed: true}'
  unset token
else
  # shellcheck disable=SC2016
  sealed=$(jq -n --argjson ids "$ids" '{
    query: "query($e: String!) { environment(id: $e) { variables { edges { node { name serviceId isSealed } } } } }",
    variables: {e: $ids.environmentId}}' | gql | jq -r --arg s "$service" \
    '[.data.environment.variables.edges[].node | select(.serviceId == $s and .name == "RAVEN_BEARER_TOKEN")
      | .isSealed] | if length == 0 then "absent" else (.[0] | tostring) end')
  case $sealed in
    absent) die "the service has no RAVEN_BEARER_TOKEN: run again with --token-stdin or --mint-token" ;;
    false) token_patch '{isSealed: true}' </dev/null ;;
  esac
fi
echo "configured $service: $network, ${memory_gb} GB, $vcpus vCPU, port $port, token sealed"

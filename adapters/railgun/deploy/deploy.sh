#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=adapters/railgun/deploy/lib.sh
. "$here/lib.sh"

CADDY_IMAGE_DEFAULT=caddy:2.11.4@sha256:0c994536bddb66445885237f1a5dcc1916bccea922661c76b4e9fc24061f9b52

usage() {
  cat <<EOF
Usage:
  deploy.sh --image IMAGE --hostname HOST [options]    install, or upgrade in place
  deploy.sh --print-sg --admin-cidr CIDR [--vpc-id ID] [--instance-id ID] [--name NAME]
  deploy.sh --help

Runs one Raven PPOI node from the raven-railgun image behind Caddy on a Docker host. Run it
again with a new image to upgrade: the data and secrets volumes and the token are kept, the
config is written again from the new image's template, and the node is stopped and started.

Node       container NAME-node as uid 1500, read-only root, volumes NAME-data (instance data)
           and NAME-secrets (config and token), port 127.0.0.1:PORT only, memory capped at
           --memory with no swap, restart on-failure:5, SIGTERM with a ${STOP_TIMEOUT} s stop timeout (the
           node's stop budget is 15 s, past Docker's default 10 s).
           Its HEALTHCHECK can be red while a cold sync runs, so nothing restarts the node on it.
Proxy      container NAME-caddy on the host network. It serves HTTPS for HOST (a Let's Encrypt
           certificate, which needs HOST's A record pointing here and port 80 reachable) and
           proxies to 127.0.0.1:PORT. It drops any client cf-connecting-ip header. The node
           trusts forwarding headers only from the address Caddy reaches it from (the host
           side of network NAME-net).
IPv6       Caddy listens on IPv4 only and --print-sg opens no IPv6 port: the node's rate limit
           keys an IPv6 client per /128 address, and one client can hold a whole /64. Publish
           only an A record for HOST. The script says so when this host has a global IPv6
           address.
Token      minted on the first install into NAME-secrets/bearer-token (mode 600, uid 1500) and
           never printed; it opens /metrics. Read it on the box with
             docker run --rm -v NAME-secrets:/s:ro --entrypoint cat IMAGE /s/bearer-token
Alerts     check.sh every minute from a systemd timer; see check.sh --help. The webhook URL
           and thresholds go in NAME-alert.env, written once with no webhook set.
Boot       systemd unit NAME-containers starts both containers at boot, since docker does not
           restart an on-failure container that stopped cleanly.
Units and files go to /etc/systemd/system and /etc/raven when run as root, else to the
user's systemd and ~/.config/raven.

Options:
  --image REF             node image pinned by digest: repo@sha256:<64 hex>, or
                          sha256:<64 hex> for an image loaded with docker load
  --hostname HOST         the public DNS name Caddy serves
  --data-from TAR         install an instant-boot data dir: an archive backup.sh wrote after a
                          clean stop, with its .clean-stop record beside it. Goes only into an
                          empty NAME-data; add --replace-data to discard the current data
  --replace-data          with --data-from: delete NAME-data first
  --mirror-endpoint URL   upstream PPOI aggregator (default: the template's, the Railgun
                          aggregator https://ppoi.fdi.network)
  --name NAME             prefix of containers, volumes, network and units (default raven)
  --port PORT             node port on 127.0.0.1 (default 8080)
  --memory SIZE           node memory cap (default 10g). The deploy refuses a cap below the
                          node's worst case, in MiB:
                            $NODE_PEAK_MIB + SEATS x INSTANCES x $SEAT_MIB + $HEADROOM_MIB
                          the warm-boot peak (1.8 GiB in rehearsal, settling at 1.2 GiB), every
                          packing-key seat full ($SEAT_MIB MiB each at a 512 B row), and headroom
                          for queries. The defaults need 8243 MiB for the template's 7 instances.
  --max-sessions N        packing-key seats per instance (default 32), written to the config
                          as max_sessions_per_instance. A full instance refuses new sessions
                          until one expires
  --wait SECS             how long to wait for every list to be caught up (default 120). A cold
                          sync asks upstream for pages of up to 501 rows at least 1 s apart,
                          so the 363,278-row mainnet list takes at least 726 pages and 12
                          minutes. --data-from skips it
  --caddy-image REF       default $CADDY_IMAGE_DEFAULT
  --bind-address ADDR     Caddy's listen address (default 0.0.0.0)
  --http-port N           Caddy's HTTP port (default 80)
  --https-port N          Caddy's HTTPS port (default 443)
  --no-caddy              leave the proxy out (the node stays on 127.0.0.1)
  --no-units              install no systemd units (no alerts timer, no start at boot)
  --admin-cidr CIDR       with --print-sg: the IPv4 range SSH is opened to
  --vpc-id ID             with --print-sg: the VPC to create the group in
  --instance-id ID        with --print-sg: also print the command that attaches the group
EOF
}

image="" hostname="" data_from="" replace_data=0 endpoint="" name=raven port=8080 memory=10g
max_sessions=32 wait_secs=120 caddy_image=$CADDY_IMAGE_DEFAULT bind_address=0.0.0.0 http_port=80 https_port=443
with_caddy=1 with_units=1 print_sg=0 admin_cidr="" vpc_id="" instance_id=""
while (($#)); do
  case $1 in
    --image) image=$2; shift ;;
    --hostname) hostname=$2; shift ;;
    --data-from) data_from=$2; shift ;;
    --replace-data) replace_data=1 ;;
    --mirror-endpoint) endpoint=$2; shift ;;
    --name) name=$2; shift ;;
    --port) port=$2; shift ;;
    --memory) memory=$2; shift ;;
    --max-sessions) max_sessions=$2; shift ;;
    --wait) wait_secs=$2; shift ;;
    --caddy-image) caddy_image=$2; shift ;;
    --bind-address) bind_address=$2; shift ;;
    --http-port) http_port=$2; shift ;;
    --https-port) https_port=$2; shift ;;
    --no-caddy) with_caddy=0 ;;
    --no-units) with_units=0 ;;
    --print-sg) print_sg=1 ;;
    --admin-cidr) admin_cidr=$2; shift ;;
    --vpc-id) vpc_id=$2; shift ;;
    --instance-id) instance_id=$2; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
  shift
done
[[ $name =~ ^[a-z][a-z0-9-]*$ ]] || die "--name must be lowercase letters, digits and dashes"
[[ $max_sessions =~ ^[1-9][0-9]{0,5}$ ]] || die "--max-sessions must be a whole number from 1"
memory_cap_mib=$(memory_mib "$memory") || die "--memory $memory is not a size such as 10g or 8192m"

print_sg() {
  [[ $admin_cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] \
    || die "--admin-cidr must be an IPv4 CIDR such as 203.0.113.7/32"
  [[ $admin_cidr != */0 ]] || die "--admin-cidr must not open SSH to every address"
  cat <<EOF
# Ingress: 443 and 80 from any IPv4 address, 22 from $admin_cidr only. No rule for the node's
# port: it listens on 127.0.0.1. No IPv6 rule (see deploy.sh --help). Egress keeps the default
# allow-all: the node reaches the aggregator, Caddy reaches Let's Encrypt, docker its registry.
SG_ID=\$(aws ec2 create-security-group --group-name $name-node \\
  --description "Raven node: https, acme and admin ssh" --vpc-id ${vpc_id:-"\$VPC_ID"} \\
  --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "\$SG_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id "\$SG_ID" --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id "\$SG_ID" --protocol tcp --port 22 --cidr $admin_cidr
EOF
  if [[ -n $instance_id ]]; then
    echo "# Replaces every group on the instance with this one."
    echo "aws ec2 modify-instance-attribute --instance-id $instance_id --groups \"\$SG_ID\""
  fi
}

if ((print_sg)); then print_sg; exit 0; fi

[[ -n $image ]] || die "--image is required (see --help)"
((with_caddy == 0)) || [[ -n $hostname ]] || die "--hostname is required unless --no-caddy"
((replace_data == 0)) || [[ -n $data_from ]] || die "--replace-data needs --data-from"
for tool in docker curl python3 sha256sum; do
  command -v "$tool" >/dev/null || die "$tool is not installed"
done
for var in "${FORBIDDEN_ENV[@]}"; do
  [[ -z ${!var:-} ]] || die "$var is set in this shell; unset it"
done
require_pinned_image "$image"
((with_caddy == 0)) || require_pinned_image "$caddy_image"

node=$name-node caddy=$name-caddy net=$name-net data=$name-data secrets=$name-secrets
if ((EUID == 0)); then
  etc=/etc/raven unit_dir=/etc/systemd/system systemctl=(systemctl) wanted_by=multi-user.target
else
  etc=${XDG_CONFIG_HOME:-$HOME/.config}/raven unit_dir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
  systemctl=(systemctl --user) wanted_by=default.target
fi
alert_env=$etc/$name-alert.env

if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
  echo "note: this host has a global IPv6 address. Caddy listens on IPv4 only; publish only an A record for ${hostname:-the node}."
fi

if [[ -n $data_from ]]; then
  check_archive "$data_from"
  if ((replace_data == 0)) && docker volume inspect "$data" >/dev/null 2>&1; then
    volume_is_empty "$data" "$image" || die "volume $data holds data; add --replace-data to discard it"
  fi
fi

say "network $net"
docker network inspect "$net" >/dev/null 2>&1 || docker network create "$net" >/dev/null
gateway=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$net")
[[ $gateway =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "network $net has no IPv4 gateway"
trusted=""
((with_caddy == 0)) || trusted=$gateway/32

say "config and token in volume $secrets"
config=$(render_config "$image" "$endpoint" "$trusted" "$max_sessions") \
  || die "no config written; the running node is untouched"
instances=$(grep -cE '^[[][[]instance[]][]]$' <<<"$config" || true)
worst=$(worst_case_mib "$max_sessions" "$instances")
((worst <= memory_cap_mib)) || die "the node needs up to $worst MiB ($NODE_PEAK_MIB boot peak + \
$max_sessions seats x $instances instances x $SEAT_MIB MiB + $HEADROOM_MIB headroom), over --memory \
$memory; raise --memory or lower --max-sessions. The running node is untouched"
docker volume create "$secrets" >/dev/null
install_secrets "$secrets" "$image" <<<"$config"

say "stopping $node if it runs"
if docker inspect "$node" >/dev/null 2>&1; then
  docker stop "$node" >/dev/null
  docker rm "$node" >/dev/null
fi

if [[ -n $data_from ]]; then
  say "instant-boot data from $data_from"
  if ((replace_data)); then docker volume rm "$data" >/dev/null 2>&1 || true; fi
  restore_volume "$data_from" "$data" "$image"
fi

say "starting $node"
started=$SECONDS
docker run -d --name "$node" \
  --user "$RAVEN_UID:$RAVEN_UID" \
  --network "$net" \
  --publish "127.0.0.1:$port:8080" \
  --volume "$data:$DATA_DIR" \
  --volume "$secrets:$SECRETS_DIR" \
  --read-only --tmpfs /tmp:size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory "$memory" --memory-swap "$memory" \
  --restart on-failure:5 \
  --stop-signal SIGTERM --stop-timeout "$STOP_TIMEOUT" \
  --log-opt max-size=50m --log-opt max-file=5 \
  "$image" serve-production --config "$CONFIG_PATH" >/dev/null
require_clean_container_env "$node"

if ((with_caddy)); then
  say "starting $caddy for $hostname"
  mkdir -p "$etc"
  install -m 0644 "$here/Caddyfile" "$etc/$name-Caddyfile"
  if docker inspect "$caddy" >/dev/null 2>&1; then docker rm -f "$caddy" >/dev/null; fi
  docker run -d --name "$caddy" \
    --network host \
    --volume "$name-caddy-data:/data" --volume "$name-caddy-config:/config" \
    --volume "$etc/$name-Caddyfile:/etc/caddy/Caddyfile:ro" \
    --env "RAVEN_HOSTNAME=$hostname" --env "RAVEN_PORT=$port" \
    --env "RAVEN_BIND_ADDRESS=$bind_address" \
    --env "RAVEN_HTTP_PORT=$http_port" --env "RAVEN_HTTPS_PORT=$https_port" \
    --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges \
    --restart on-failure:5 \
    --log-opt max-size=10m --log-opt max-file=3 \
    "$caddy_image" >/dev/null
fi

if ((with_units)); then
  say "systemd units in $unit_dir"
  mkdir -p "$etc" "$unit_dir"
  install -m 0755 "$here/check.sh" "$etc/$name-check.sh"
  if [[ ! -f $alert_env ]]; then
    (umask 077; cat >"$alert_env" <<EOF
# Read by $name-check.sh; see its --help for the thresholds. With no webhook, alerts go to the
# journal only.
RAVEN_ALERT_WEBHOOK=
EOF
    )
  fi
  containers=$node
  ((with_caddy == 0)) || containers="$node $caddy"
  docker_unit=""
  ((EUID != 0)) || docker_unit=$'After=docker.service\nWants=docker.service'
  cat >"$unit_dir/$name-containers.service" <<EOF
[Unit]
Description=Start the $name node containers at boot
$docker_unit

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v docker) start $containers

[Install]
WantedBy=$wanted_by
EOF
  cat >"$unit_dir/$name-check.service" <<EOF
[Unit]
Description=Check the $name node and send alerts

[Service]
Type=oneshot
Environment=RAVEN_NAME=$name RAVEN_PORT=$port
EnvironmentFile=$alert_env
ExecStart=$etc/$name-check.sh
EOF
  cat >"$unit_dir/$name-check.timer" <<EOF
[Unit]
Description=Check the $name node every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF
  "${systemctl[@]}" daemon-reload
  "${systemctl[@]}" enable "$name-containers.service" >/dev/null 2>&1
  "${systemctl[@]}" enable --now "$name-check.timer" >/dev/null 2>&1
fi

say "waiting for $node"
if wait_caught_up "$node" "$port" "$wait_secs"; then
  echo "ready $((SECONDS - started)) s after start"
else
  rc=$?
  ((rc != 2)) || die "$node did not start"
  echo "still syncing; follow it with: curl -s http://127.0.0.1:$port/v1/health/ready"
fi

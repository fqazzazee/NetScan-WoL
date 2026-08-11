#!/usr/bin/env bash
#
# Create a Proxmox LXC container running a NetScan-WoL agent.
#
# Run this on the Proxmox host, not inside a container.
#
#   ./create-agent-lxc.sh --hub https://hub.example.com:8443 \
#       --token <64-hex-token> --ca-pin sha256:<fingerprint>
#
# Why an unprivileged container works here:
#
# ARP scanning needs CAP_NET_RAW. An unprivileged LXC container does hold
# CAP_NET_RAW inside its own user namespace, and because the container's veth
# is bridged onto a real Proxmox bridge (vmbr0 by default), that namespace is
# attached to the physical broadcast domain. So the agent can scan the LAN
# without the container being privileged — which is the configuration you want.
#
# What does NOT work: an unprivileged container on an isolated or NAT bridge.
# The agent would only see the container network. Bridge to the segment you
# actually want to scan.

set -euo pipefail

# ---- defaults -------------------------------------------------------------

CTID=""
HOSTNAME="nswagent"
BRIDGE="vmbr0"
STORAGE="local-lvm"
TEMPLATE_STORAGE="local"
DISK_GB=2
MEMORY_MB=256
CORES=1
IPCONFIG="dhcp"
VLAN=""
AGENT_VERSION="2.0.0"
AGENT_URL=""
HUB_URL=""
TOKEN=""
CA_PIN=""
AGENT_NAME=""
START_AFTER_CREATE=1

usage() {
  cat <<'EOF'
Create a Proxmox LXC container running a NetScan-WoL agent.

Required:
  --hub URL             Command hub URL, e.g. https://hub.example.com:8443
  --token HEX           64-character enrollment token from the hub UI

Strongly recommended:
  --ca-pin sha256:...   Hub CA fingerprint. Without it the agent accepts
                        whatever certificate answers on first contact.

Optional:
  --ctid N              Container ID (default: next free)
  --hostname NAME       Container hostname (default: nswagent)
  --agent-name NAME     Display name in the hub (default: the hostname)
  --bridge BR           Proxmox bridge (default: vmbr0)
  --vlan TAG            VLAN tag for the container's interface
  --ip CIDR,gw=GW       Static address instead of DHCP,
                        e.g. --ip 10.0.50.9/24,gw=10.0.50.1
  --storage NAME        Container storage (default: local-lvm)
  --disk GB             Disk size in GB (default: 2)
  --memory MB           Memory in MB (default: 256)
  --cores N             CPU cores (default: 1)
  --agent-url URL       Where to fetch the nswagent binary
  --no-start            Create the container but do not start it
  -h, --help            This message

The container is unprivileged, which is sufficient: CAP_NET_RAW inside its own
user namespace plus a bridged interface is all an ARP scan needs.
EOF
}

# ---- argument parsing -----------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ctid)       CTID="$2"; shift 2 ;;
    --hostname)   HOSTNAME="$2"; shift 2 ;;
    --agent-name) AGENT_NAME="$2"; shift 2 ;;
    --bridge)     BRIDGE="$2"; shift 2 ;;
    --vlan)       VLAN="$2"; shift 2 ;;
    --ip)         IPCONFIG="$2"; shift 2 ;;
    --storage)    STORAGE="$2"; shift 2 ;;
    --disk)       DISK_GB="$2"; shift 2 ;;
    --memory)     MEMORY_MB="$2"; shift 2 ;;
    --cores)      CORES="$2"; shift 2 ;;
    --hub)        HUB_URL="$2"; shift 2 ;;
    --token)      TOKEN="$2"; shift 2 ;;
    --ca-pin)     CA_PIN="$2"; shift 2 ;;
    --agent-url)  AGENT_URL="$2"; shift 2 ;;
    --no-start)   START_AFTER_CREATE=0; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

command -v pct >/dev/null || die "pct not found — run this on the Proxmox host"
[[ $EUID -eq 0 ]] || die "must be run as root"
[[ -n "$HUB_URL" ]] || die "--hub is required"
[[ -n "$TOKEN"   ]] || die "--token is required"

[[ ${#TOKEN} -eq 64 ]] || die "the token must be 64 hex characters (got ${#TOKEN})"

if [[ -z "$CA_PIN" ]]; then
  cat >&2 <<'EOF'
warning: no --ca-pin given.

The agent will accept whatever certificate the hub presents on first contact,
without verifying it. Anyone able to intercept that first connection could
impersonate the hub and capture the enrollment token. The hub UI shows the pin
next to every token it issues; pass it with --ca-pin.

EOF
  read -r -p "Continue without pinning? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || exit 1
fi

[[ -n "$AGENT_NAME" ]] || AGENT_NAME="$HOSTNAME"
[[ -n "$CTID" ]] || CTID=$(pvesh get /cluster/nextid)

if [[ -z "$AGENT_URL" ]]; then
  AGENT_URL="https://github.com/fqazzazee/NetScan-WoL/releases/download/v${AGENT_VERSION}/nswagent-linux-amd64"
fi

# ---- template -------------------------------------------------------------

TEMPLATE="debian-12-standard_12.7-1_amd64.tar.zst"
TEMPLATE_REF="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}"

if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -q "$TEMPLATE"; then
  echo "==> Downloading the container template"
  pveam update >/dev/null
  # Pick whatever current Debian 12 template the mirror actually offers rather
  # than pinning a point release that may have been superseded.
  TEMPLATE=$(pveam available --section system | awk '/debian-12-standard/ {print $2}' | sort -V | tail -1)
  [[ -n "$TEMPLATE" ]] || die "no Debian 12 template is available"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
  TEMPLATE_REF="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}"
fi

# ---- create ---------------------------------------------------------------

NET="name=eth0,bridge=${BRIDGE},firewall=1"
[[ -n "$VLAN" ]] && NET="${NET},tag=${VLAN}"
if [[ "$IPCONFIG" == "dhcp" ]]; then
  NET="${NET},ip=dhcp"
else
  NET="${NET},ip=${IPCONFIG}"
fi

echo "==> Creating container ${CTID} (${HOSTNAME}) on ${BRIDGE}"
pct create "$CTID" "$TEMPLATE_REF" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" \
  --memory "$MEMORY_MB" \
  --swap 0 \
  --rootfs "${STORAGE}:${DISK_GB}" \
  --net0 "$NET" \
  --unprivileged 1 \
  --features nesting=0 \
  --onboot 1 \
  --description "NetScan-WoL agent — reports to ${HUB_URL}"

echo "==> Starting container"
pct start "$CTID"

# Wait for the network to come up before trying to download anything.
for _ in $(seq 1 30); do
  if pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1; then break; fi
  sleep 2
done

# ---- install --------------------------------------------------------------

echo "==> Installing the agent"
pct exec "$CTID" -- bash -eu -c "
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates >/dev/null

  curl -fsSL '${AGENT_URL}' -o /usr/local/bin/nswagent
  chmod 0755 /usr/local/bin/nswagent

  # A dedicated account. The agent needs one capability, not root.
  id nswagent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin nswagent
  install -d -o nswagent -g nswagent -m 0700 /var/lib/netscan-wol/agent

  # CAP_NET_RAW on the binary rather than running as root. Inside an
  # unprivileged container this is namespaced, so it grants packet access to
  # this container's network and nothing beyond it.
  setcap cap_net_raw+ep /usr/local/bin/nswagent
"

echo "==> Enrolling with the hub"
pct exec "$CTID" -- runuser -u nswagent -- \
  /usr/local/bin/nswagent enroll \
    --hub "$HUB_URL" \
    --token "$TOKEN" \
    ${CA_PIN:+--ca-pin "$CA_PIN"} \
    --name "$AGENT_NAME" \
    --state /var/lib/netscan-wol/agent

echo "==> Installing the service"
pct exec "$CTID" -- bash -eu -c "cat > /etc/systemd/system/nswagent.service <<'UNIT'
[Unit]
Description=NetScan-WoL Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/nswagent run --state /var/lib/netscan-wol/agent
Restart=always
RestartSec=10s
User=nswagent
Group=nswagent
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
StateDirectory=netscan-wol/agent

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now nswagent.service
"

sleep 2
echo
echo "==> Done."
pct exec "$CTID" -- systemctl is-active nswagent.service || true
pct exec "$CTID" -- /usr/local/bin/nswagent status --state /var/lib/netscan-wol/agent || true

cat <<EOF

Container ${CTID} (${HOSTNAME}) is running the agent.

  Logs:     pct exec ${CTID} -- journalctl -u nswagent -f
  Shell:    pct enter ${CTID}
  Networks: pct exec ${CTID} -- nswagent interfaces

The agent should now appear in the hub UI under Agents.
EOF

[[ $START_AFTER_CREATE -eq 1 ]] || pct stop "$CTID"

#!/usr/bin/env bash
#
# NetScan-WoL v2 installer.
#
#   Hub:    sudo ./install.sh hub
#   Agent:  sudo ./install.sh agent --hub https://hub.example.com:8443 \
#                                   --token <64-hex> --ca-pin sha256:<fingerprint>
#
# Installs the requested component, creates its service account, sets up a
# systemd unit, and — for an agent given a token — enrolls it with the hub.
#
# Binaries come from the GitHub release for the running platform. With --source,
# or on a platform with no published build, it compiles from the working tree
# instead; that needs Go 1.24+ and nothing else.

set -euo pipefail

readonly VERSION_DEFAULT="2.0.0"
readonly REPO="fqazzazee/NetScan-WoL"

# ---- settings, overridable by flag ----------------------------------------

COMPONENT=""
VERSION="$VERSION_DEFAULT"
PREFIX="/usr/local"
HUB_URL=""
TOKEN=""
TOKEN_FILE=""
CA_PIN=""
AGENT_NAME=""
AGENT_LABELS=""
HUB_NAMES=""
HUB_LISTEN=":8443"
FROM_SOURCE=0
INSTALL_SERVICE=1
START_SERVICE=1
UNINSTALL=0
FORCE=0
RUN_CHECK=0
REMOVE_V1=0
KEEP_V1=0

# ---- output ---------------------------------------------------------------

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
fi

step()  { printf '%s==>%s %s\n' "$C_BOLD" "$C_RESET" "$*"; }
info()  { printf '    %s\n' "$*"; }
warn()  { printf '%swarning:%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()   { printf '%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
ok()    { printf '%s  ✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }

usage() {
  cat <<'EOF'
NetScan-WoL v2 installer

Usage:
  install.sh [component] [options]

Run with no component for an interactive menu.

Components:
  hub            The dashboard hub: web interface, agent API, certificate authority
  agent          A remote agent: ARP scanning and Wake-on-LAN on its own network
  both           Hub and agent together on this server (the v1 single-box setup)
  check          Check prerequisites and report; install nothing
  remove-v1      Remove a NetScan-WoL v1 installation and nothing else

Common options:
  --check            Run the prerequisite check first, then install
  --remove-v1        Remove the v1 web service if one is found, without asking
  --keep-v1          Leave any v1 installation alone, without asking
  --version VER      Release to install (default: 2.0.0)
  --source           Build from this working tree instead of downloading
  --prefix DIR       Install prefix (default: /usr/local)
  --no-service       Install binaries only; do not create systemd units
  --no-start         Create the units but do not start them
  --force            Reinstall over an existing installation
  --uninstall        Remove the named component
  -h, --help         This message

Hub options:
  --names LIST       Comma-separated DNS names and IPs for the TLS certificate.
                     Every address a browser or agent will use must be listed.
  --listen ADDR      Listen address (default: :8443)

Agent options:
  --hub URL          Hub URL, e.g. https://hub.example.com:8443
  --token HEX        64-character enrollment token from the hub UI
  --token-file PATH  Read the token from a file (keeps it out of the process list)
  --ca-pin PIN       Hub CA fingerprint, sha256:...  Strongly recommended.
  --name NAME        Display name in the hub (default: this hostname)
  --labels K=V,K=V   Tags shown in the hub UI, e.g. site=hq,rack=3

Examples:
  # Interactive
  sudo ./install.sh

  # See what is and is not ready, without changing anything
  ./install.sh check

  # Hub, reachable at https://hub.example.com:8443
  sudo ./install.sh hub --names hub.example.com

  # Agent, joined to that hub
  sudo ./install.sh agent \
    --hub https://hub.example.com:8443 \
    --token 8f3c... --ca-pin sha256:1a2b...

  # Everything on one machine
  sudo ./install.sh both --names $(hostname)

  # Install the agent now, enroll by hand later
  sudo ./install.sh agent --no-start

  # Retire an old v1 install (its saved hosts and history are left in place)
  sudo ./install.sh remove-v1
EOF
}

# ---- component selection --------------------------------------------------

# choose_component asks what to install when nothing was named on the command
# line. Only offered on a terminal: piping this script into a shell must never
# block waiting for input that will never come.
choose_component() {
  cat >&2 <<EOF

${C_BOLD}NetScan-WoL v2${C_RESET}

  What should this server run?

    ${C_BOLD}1${C_RESET}) Dashboard hub    the web interface and certificate authority.
                        Other machines join it as agents.
    ${C_BOLD}2${C_RESET}) Agent            scans and wakes machines on this network,
                        reporting to a hub elsewhere.
    ${C_BOLD}3${C_RESET}) Both             hub and agent on this one server.
    ${C_BOLD}4${C_RESET}) Check only       report what is ready and what is missing,
                        change nothing.
    ${C_BOLD}5${C_RESET}) Remove v1        take out an old v1 web service, keeping
                        its saved hosts and scan history.

EOF
  local reply
  while true; do
    read -r -p "  Choose [1-5], or q to quit: " reply || { echo >&2; exit 1; }
    case "$reply" in
      1) COMPONENT="hub";   return ;;
      2) COMPONENT="agent"; return ;;
      3) COMPONENT="both";  return ;;
      4) COMPONENT="check"; return ;;
      5) COMPONENT="remove-v1"; return ;;
      q|Q) exit 0 ;;
      *) printf '  %sPlease enter 1, 2, 3, 4, 5 or q.%s\n' "$C_DIM" "$C_RESET" >&2 ;;
    esac
  done
}

# ---- argument parsing -----------------------------------------------------

case "${1:-}" in
  hub|agent|both|check|remove-v1) COMPONENT="$1"; shift ;;
  -h|--help)            usage; exit 0 ;;
  "")
    if [[ -t 0 && -t 1 ]]; then
      choose_component
    else
      usage
      exit 1
    fi
    ;;
  -*) die "a component must come first: hub, agent, both, check or remove-v1" ;;
  *)  die "unknown component '${1}' (expected hub, agent, both, check or remove-v1)" ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)     VERSION="$2"; shift 2 ;;
    --prefix)      PREFIX="$2"; shift 2 ;;
    --source)      FROM_SOURCE=1; shift ;;
    --no-service)  INSTALL_SERVICE=0; shift ;;
    --no-start)    START_SERVICE=0; shift ;;
    --force)       FORCE=1; shift ;;
    --check)       RUN_CHECK=1; shift ;;
    --uninstall)   UNINSTALL=1; shift ;;
    --remove-v1)   REMOVE_V1=1; shift ;;
    --keep-v1)     KEEP_V1=1; shift ;;
    --hub)         HUB_URL="$2"; shift 2 ;;
    --token)       TOKEN="$2"; shift 2 ;;
    --token-file)  TOKEN_FILE="$2"; shift 2 ;;
    --ca-pin)      CA_PIN="$2"; shift 2 ;;
    --name)        AGENT_NAME="$2"; shift 2 ;;
    --labels)      AGENT_LABELS="$2"; shift 2 ;;
    --names)       HUB_NAMES="$2"; shift 2 ;;
    --listen)      HUB_LISTEN="$2"; shift 2 ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "unknown option '$1' (see --help)" ;;
  esac
done

[[ $REMOVE_V1 -eq 1 && $KEEP_V1 -eq 1 ]] && die "--remove-v1 and --keep-v1 contradict each other"

readonly BINDIR="$PREFIX/bin"
readonly STATE_ROOT="/var/lib/netscan-wol"
readonly UNIT_DIR="/etc/systemd/system"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- platform detection ---------------------------------------------------

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in
    x86_64|amd64)   arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
    armv7l|armv6l)  arch="arm" ;;
    *) die "unsupported architecture $(uname -m); build from source with --source" ;;
  esac
  printf '%s %s' "$os" "$arch"
}

read -r PLATFORM_OS PLATFORM_ARCH <<<"$(detect_platform)"

# ---- v1 detection and removal ---------------------------------------------

# v1 was a bash script with an optional Flask web UI. Its --web-install copied
# the server to /opt/netscan-wol and wrote a unit called netscan-wol-web. None
# of that collides with v2 by name or by port, so a forgotten v1 keeps running:
# scanning the same network, holding its own port, and showing a second,
# diverging list of hosts. Detecting it is worth doing on every install.

readonly V1_SERVICE="netscan-wol-web"
readonly V1_UNIT_PATH="/etc/systemd/system/netscan-wol-web.service"
readonly V1_APP_DIR="/opt/netscan-wol"

V1_HAS_UNIT=0
V1_ACTIVE=0
V1_ENABLED=0
V1_HAS_APP=0
V1_DATA_DIRS=()

# detect_v1 fills in the V1_* globals and returns 0 when there is something of
# v1's left on this machine. Data directories alone do not count: they are the
# part worth keeping, and their presence is no reason to prompt anyone.
detect_v1() {
  V1_HAS_UNIT=0; V1_ACTIVE=0; V1_ENABLED=0; V1_HAS_APP=0; V1_DATA_DIRS=()

  if [[ -f "$V1_UNIT_PATH" ]]; then
    V1_HAS_UNIT=1
  elif [[ $HAS_SYSTEMD -eq 1 ]] && systemctl cat "${V1_SERVICE}.service" >/dev/null 2>&1; then
    V1_HAS_UNIT=1
  fi

  if [[ $V1_HAS_UNIT -eq 1 && $HAS_SYSTEMD -eq 1 ]]; then
    systemctl is-active  --quiet "${V1_SERVICE}.service" 2>/dev/null && V1_ACTIVE=1
    systemctl is-enabled --quiet "${V1_SERVICE}.service" 2>/dev/null && V1_ENABLED=1
  fi

  [[ -d "$V1_APP_DIR" ]] && V1_HAS_APP=1

  local d
  for d in /root/.netscan-wol /home/*/.netscan-wol; do
    [[ -d "$d" ]] && V1_DATA_DIRS+=("$d")
  done

  [[ $V1_HAS_UNIT -eq 1 || $V1_HAS_APP -eq 1 ]]
}

v1_state_word() {
  if   [[ $V1_ACTIVE  -eq 1 ]]; then printf 'running'
  elif [[ $V1_ENABLED -eq 1 ]]; then printf 'enabled, not running'
  else                               printf 'installed, stopped'
  fi
}

report_v1() {
  [[ $V1_HAS_UNIT -eq 1 ]] && info "service  ${V1_SERVICE}.service — $(v1_state_word)"
  [[ $V1_HAS_APP  -eq 1 ]] && info "files    ${V1_APP_DIR}"
  if [[ ${#V1_DATA_DIRS[@]} -gt 0 ]]; then
    info "data     ${V1_DATA_DIRS[*]}"
  fi
}

remove_v1() {
  if [[ $V1_HAS_UNIT -eq 1 ]]; then
    if [[ $HAS_SYSTEMD -eq 1 ]]; then
      systemctl disable --now "${V1_SERVICE}.service" >/dev/null 2>&1 || true
      systemctl reset-failed "${V1_SERVICE}.service" >/dev/null 2>&1 || true
    fi
    rm -f "$V1_UNIT_PATH"
    if [[ $HAS_SYSTEMD -eq 1 ]]; then
      systemctl daemon-reload
    fi
    ok "removed the ${V1_SERVICE} service"
  fi

  if [[ $V1_HAS_APP -eq 1 ]]; then
    rm -rf "$V1_APP_DIR"
    ok "removed ${V1_APP_DIR}"
  fi

  # Saved hosts and scan history are the only part of a v1 install worth
  # anything, and v2 cannot read them. Removing the service must not take them
  # with it, so they are reported and left exactly where they are.
  if [[ ${#V1_DATA_DIRS[@]} -gt 0 ]]; then
    info "kept ${V1_DATA_DIRS[*]} — v1's saved hosts and history, untouched"
  fi
}

# handle_v1 runs before an install. It removes v1, keeps it, or asks, depending
# on the flags and on whether there is anyone at the terminal to ask.
handle_v1() {
  detect_v1 || return 0

  step "Found a NetScan-WoL v1 installation"
  report_v1

  if [[ $KEEP_V1 -eq 1 ]]; then
    info "leaving it in place (--keep-v1)"
    return 0
  fi

  if [[ $REMOVE_V1 -eq 1 ]]; then
    remove_v1
    return 0
  fi

  if [[ -t 0 && -t 1 ]]; then
    local reply
    read -r -p "  Remove it? Saved hosts and history are kept. [y/N]: " reply || reply="n"
    case "$reply" in
      y|Y|yes|YES) remove_v1 ;;
      *) info "leaving it in place" ;;
    esac
    return 0
  fi

  warn "v1 is still installed and will keep scanning alongside v2."
  warn "Remove it with: sudo $0 remove-v1"
}

# ---- prerequisite check ---------------------------------------------------

CHECK_FAIL=0
CHECK_WARN=0

pass_() { printf '  %s✓%s %-30s %s\n' "$C_GREEN" "$C_RESET" "$1" "${2:-}"; }
warn_() { printf '  %s!%s %-30s %s\n' "$C_YELLOW" "$C_RESET" "$1" "${2:-}"; CHECK_WARN=$((CHECK_WARN + 1)); }
fail_() { printf '  %s✗%s %-30s %s\n' "$C_RED" "$C_RESET" "$1" "${2:-}"; CHECK_FAIL=$((CHECK_FAIL + 1)); }

# port_busy reports whether something is already listening on a TCP port,
# using whichever tool the system happens to have.
port_busy() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"
  else
    return 1   # cannot tell; not a failure
  fi
}

free_mb() {
  df -Pm "$1" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0
}

check_prereqs() {
  local want="$1"    # hub, agent or both

  printf '\n%sPrerequisite check%s  (%s)\n\n' "$C_BOLD" "$C_RESET" "$want"

  printf '%s System%s\n' "$C_DIM" "$C_RESET"
  if [[ $EUID -eq 0 ]]; then
    pass_ "root privileges" "installing is possible"
  else
    warn_ "root privileges" "not root; the check runs but installing needs sudo"
  fi

  case "$PLATFORM_OS" in
    linux) pass_ "operating system" "linux/${PLATFORM_ARCH}" ;;
    *)     warn_ "operating system" "${PLATFORM_OS}/${PLATFORM_ARCH} — the agent's native ARP scanning is Linux-only" ;;
  esac

  if [[ $HAS_SYSTEMD -eq 1 ]]; then
    pass_ "systemd" "services can be installed"
  else
    warn_ "systemd" "not running; binaries install but no service is created"
  fi

  local root_mb; root_mb="$(free_mb "$PREFIX" 2>/dev/null || echo 0)"
  if [[ "${root_mb:-0}" -ge 64 ]]; then
    pass_ "disk space" "${root_mb} MB free at ${PREFIX}"
  else
    fail_ "disk space" "only ${root_mb} MB free at ${PREFIX}; needs about 25 MB"
  fi

  printf '\n%s Obtaining binaries%s\n' "$C_DIM" "$C_RESET"
  local can_download=0 can_build=0
  if command -v curl >/dev/null 2>&1; then
    can_download=1
    pass_ "curl" "release downloads possible"
  else
    warn_ "curl" "not installed; a release cannot be downloaded"
  fi

  if command -v go >/dev/null 2>&1; then
    local gv; gv="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
    local major minor; major="${gv%%.*}"; minor="$(printf '%s' "$gv" | cut -d. -f2)"
    if [[ "${major:-0}" -gt 1 ]] || { [[ "${major:-0}" -eq 1 ]] && [[ "${minor:-0}" -ge 24 ]]; }; then
      can_build=1
      pass_ "go toolchain" "go${gv} — can build from source"
    else
      warn_ "go toolchain" "go${gv} is below the 1.24 minimum"
    fi
  else
    printf '  %s·%s %-30s %s\n' "$C_DIM" "$C_RESET" "go toolchain" "not installed (only needed for --source)"
  fi

  if [[ -f "${SCRIPT_DIR}/go.mod" ]]; then
    pass_ "source checkout" "present, so a source build is possible"
  else
    printf '  %s·%s %-30s %s\n' "$C_DIM" "$C_RESET" "source checkout" "not a repository checkout"
  fi

  if [[ $can_download -eq 0 && $can_build -eq 0 ]]; then
    fail_ "binaries" "no way to obtain them: install curl, or Go 1.24+ for a source build"
  fi

  # ---- hub-specific ----
  if [[ "$want" == "hub" || "$want" == "both" ]]; then
    printf '\n%s Hub%s\n' "$C_DIM" "$C_RESET"

    local port="${HUB_LISTEN##*:}"
    if port_busy "$port"; then
      fail_ "port ${port}" "already in use; choose another with --listen"
    else
      pass_ "port ${port}" "free"
    fi

    if [[ -n "$HUB_NAMES" ]]; then
      pass_ "certificate names" "$HUB_NAMES"
    else
      warn_ "certificate names" "no --names; the certificate will cover only this host, localhost and 127.0.0.1"
    fi

    if [[ -e "${STATE_ROOT}/hub/pki/ca.key" ]]; then
      warn_ "existing hub state" "${STATE_ROOT}/hub — the existing CA will be reused"
    else
      pass_ "hub state" "will be created at ${STATE_ROOT}/hub"
    fi

    if [[ -x "${BINDIR}/nswhub" ]] && [[ $FORCE -eq 0 ]]; then
      warn_ "existing install" "${BINDIR}/nswhub will be replaced"
    fi
  fi

  # ---- agent-specific ----
  if [[ "$want" == "agent" || "$want" == "both" ]]; then
    printf '\n%s Agent%s\n' "$C_DIM" "$C_RESET"

    if command -v setcap >/dev/null 2>&1; then
      pass_ "setcap" "CAP_NET_RAW can be granted"
    else
      warn_ "setcap" "not found; install libcap2-bin (Debian) or libcap (RHEL) for full ARP scanning"
    fi

    # An interface that can carry an ARP scan needs to be up, non-loopback and
    # hold an IPv4 address. Without one the agent installs but finds nothing.
    local eligible=""
    if command -v ip >/dev/null 2>&1; then
      eligible="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2}' | sort -u | tr '\n' ' ')"
    fi
    if [[ -n "${eligible// /}" ]]; then
      pass_ "scannable interfaces" "$eligible"
    else
      warn_ "scannable interfaces" "none found with a global IPv4 address; scans will return nothing"
    fi

    if [[ -n "$HUB_URL" ]]; then
      # The hub uses its own CA, so this deliberately does not verify the
      # certificate: the question is only whether the address answers at all.
      if command -v curl >/dev/null 2>&1 && \
         curl -sk --max-time 8 -o /dev/null "${HUB_URL%/}/healthz" 2>/dev/null; then
        pass_ "hub reachable" "$HUB_URL"
      else
        fail_ "hub reachable" "cannot reach ${HUB_URL} — check the URL, routing and firewall"
      fi
    else
      printf '  %s·%s %-30s %s\n' "$C_DIM" "$C_RESET" "hub URL" "not given; pass --hub to test reachability"
    fi

    local secret="${TOKEN}"
    [[ -z "$secret" && -n "$TOKEN_FILE" && -r "$TOKEN_FILE" ]] && secret="$(tr -d '[:space:]' < "$TOKEN_FILE")"
    [[ -z "$secret" ]] && secret="${NSWAGENT_TOKEN:-}"
    if [[ -n "$secret" ]]; then
      if [[ ${#secret} -eq 64 ]]; then
        pass_ "enrollment token" "64 characters, well formed"
      else
        fail_ "enrollment token" "${#secret} characters; it must be exactly 64"
      fi
      if [[ -n "$CA_PIN" ]]; then
        pass_ "CA pin" "supplied — the hub will be verified before the token is sent"
      else
        warn_ "CA pin" "not supplied; enrollment falls back to trust-on-first-use"
      fi
    else
      printf '  %s·%s %-30s %s\n' "$C_DIM" "$C_RESET" "enrollment token" "not given; the agent installs unenrolled"
    fi

    if [[ -f "${STATE_ROOT}/agent/agent.json" ]] && [[ $FORCE -eq 0 ]]; then
      warn_ "existing enrollment" "${STATE_ROOT}/agent — kept unless you pass --force"
    fi
  fi

  # ---- v1 leftovers ----
  if detect_v1; then
    printf '\n%s Version 1%s\n' "$C_DIM" "$C_RESET"
    if [[ $V1_ACTIVE -eq 1 ]]; then
      warn_ "v1 web service" "${V1_SERVICE}.service is running; it will scan alongside v2"
    elif [[ $V1_HAS_UNIT -eq 1 ]]; then
      warn_ "v1 web service" "${V1_SERVICE}.service is installed ($(v1_state_word))"
    else
      warn_ "v1 files" "${V1_APP_DIR} left behind"
    fi
    info "remove it with: sudo $0 remove-v1"
  fi

  # ---- verdict ----
  echo
  if [[ $CHECK_FAIL -gt 0 ]]; then
    printf '%s%d blocking problem(s)%s and %d warning(s).\n' "$C_RED" "$CHECK_FAIL" "$C_RESET" "$CHECK_WARN"
    return 1
  elif [[ $CHECK_WARN -gt 0 ]]; then
    printf '%sReady%s, with %d warning(s) — installing will work but read them first.\n' \
      "$C_GREEN" "$C_RESET" "$CHECK_WARN"
  else
    printf '%sReady.%s Everything this needs is in place.\n' "$C_GREEN" "$C_RESET"
  fi
  return 0
}

# ---- preflight ------------------------------------------------------------

HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  HAS_SYSTEMD=1
fi

# Check-only mode needs no privileges and changes nothing, so it runs before
# the root requirement and exits with a status that reflects the verdict.
if [[ "$COMPONENT" == "check" ]]; then
  check_prereqs "both"
  exit $?
fi

if [[ $RUN_CHECK -eq 1 && $UNINSTALL -eq 0 ]]; then
  if ! check_prereqs "$COMPONENT"; then
    die "prerequisites are not met; fix the items marked ✗ or re-run without --check to proceed anyway"
  fi
  echo
fi

[[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0 ${COMPONENT} ...)"

# ---- remove v1 only -------------------------------------------------------

if [[ "$COMPONENT" == "remove-v1" ]]; then
  step "Looking for a NetScan-WoL v1 installation"
  if detect_v1; then
    report_v1
    echo
    if [[ $REMOVE_V1 -eq 0 && -t 0 && -t 1 ]]; then
      read -r -p "  Remove it? Saved hosts and history are kept. [y/N]: " reply || reply="n"
      case "$reply" in
        y|Y|yes|YES) ;;
        *) info "nothing removed"; exit 0 ;;
      esac
    fi
    remove_v1
  else
    ok "no v1 installation found"
    if [[ ${#V1_DATA_DIRS[@]} -gt 0 ]]; then
      info "v1 data is still at ${V1_DATA_DIRS[*]}; delete it by hand if you mean to"
    fi
  fi
  exit 0
fi

if [[ $HAS_SYSTEMD -eq 0 && $INSTALL_SERVICE -eq 1 ]]; then
  warn "systemd is not running here; installing binaries only"
  INSTALL_SERVICE=0
fi

if [[ "$PLATFORM_OS" != "linux" ]]; then
  warn "native ARP scanning is Linux-only; on ${PLATFORM_OS} the agent falls back to arp-scan or the neighbour table"
fi

# ---- uninstall ------------------------------------------------------------

uninstall_one() {
  local name="$1"          # nswhub or nswagent
  local statedir="$2"

  if [[ $HAS_SYSTEMD -eq 1 ]] && systemctl list-unit-files "${name}.service" >/dev/null 2>&1; then
    systemctl disable --now "${name}.service" 2>/dev/null || true
    rm -f "${UNIT_DIR}/${name}.service"
    systemctl daemon-reload
    ok "removed the ${name} service"
  fi
  rm -f "${BINDIR}/${name}"
  ok "removed ${BINDIR}/${name}"

  # State is deliberately left in place. For the hub it holds the certificate
  # authority; deleting it would invalidate every enrolled agent, which is not
  # something an uninstall should do silently.
  if [[ -d "$statedir" ]]; then
    info "state kept at ${statedir} (delete it by hand if you mean to)"
  fi
}

if [[ $UNINSTALL -eq 1 ]]; then
  step "Uninstalling"
  [[ "$COMPONENT" == "hub"   || "$COMPONENT" == "both" ]] && uninstall_one nswhub   "${STATE_ROOT}/hub"
  [[ "$COMPONENT" == "agent" || "$COMPONENT" == "both" ]] && uninstall_one nswagent "${STATE_ROOT}/agent"
  exit 0
fi

# Deal with any v1 before fetching anything, so the question is answered while
# the operator is still watching rather than after a download.
handle_v1

# ---- obtaining binaries ---------------------------------------------------

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

build_from_source() {
  command -v go >/dev/null 2>&1 || die "--source needs a Go toolchain (1.24 or newer)"
  [[ -f "${SCRIPT_DIR}/go.mod" ]] || die "--source must be run from a checkout of the repository"

  local goversion
  goversion="$(go env GOVERSION 2>/dev/null || echo unknown)"
  info "building with ${goversion}"

  # No modules to download, so this works with no network access at all.
  ( cd "$SCRIPT_DIR" && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
      -o "${WORKDIR}/nswhub" ./cmd/nswhub && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
      -o "${WORKDIR}/nswagent" ./cmd/nswagent ) \
    || die "build failed"
  ok "built from source"
}

download_release() {
  command -v curl >/dev/null 2>&1 || die "curl is required to download a release (or use --source)"

  local base="https://github.com/${REPO}/releases/download/v${VERSION}"
  local name
  for name in nswhub nswagent; do
    local url="${base}/${name}-${PLATFORM_OS}-${PLATFORM_ARCH}"
    info "fetching ${name} ${VERSION} (${PLATFORM_OS}/${PLATFORM_ARCH})"
    # Errors are reported by the caller with context, so curl's own message is
    # suppressed rather than printed alongside it.
    if ! curl -fsL --retry 3 -o "${WORKDIR}/${name}" "$url" 2>/dev/null; then
      warn "no published build at ${url}"
      return 1
    fi
  done

  # Verify against the release checksums when they are published. A failed
  # checksum aborts; a missing checksum file is only a warning, so an
  # unsigned pre-release still installs.
  if curl -fsSL --retry 2 -o "${WORKDIR}/SHA256SUMS" "${base}/SHA256SUMS" 2>/dev/null; then
    ( cd "$WORKDIR" && \
      grep -E "(nswhub|nswagent)-${PLATFORM_OS}-${PLATFORM_ARCH}$" SHA256SUMS \
        | sed -E "s/(nswhub|nswagent)-${PLATFORM_OS}-${PLATFORM_ARCH}\$/\1/" \
        | sha256sum --check --status ) \
      || die "checksum verification failed — do not use these binaries"
    ok "checksums verified"
  else
    warn "no SHA256SUMS published for v${VERSION}; skipping checksum verification"
  fi
  return 0
}

step "Obtaining NetScan-WoL ${VERSION}"
if [[ $FROM_SOURCE -eq 1 ]]; then
  build_from_source
elif ! download_release; then
  if [[ -f "${SCRIPT_DIR}/go.mod" ]] && command -v go >/dev/null 2>&1; then
    warn "falling back to building from this checkout"
    build_from_source
  else
    die "could not download release v${VERSION} and cannot build from source here"
  fi
fi

# ---- installation ---------------------------------------------------------

install_binary() {
  local name="$1"
  if [[ -x "${BINDIR}/${name}" && $FORCE -eq 0 ]]; then
    info "replacing the existing ${BINDIR}/${name}"
  fi
  install -Dm0755 "${WORKDIR}/${name}" "${BINDIR}/${name}"
  ok "installed ${BINDIR}/${name}"
}

ensure_user() {
  local user="$1"
  if ! id "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user" 2>/dev/null \
      || useradd --system --no-create-home --shell /sbin/nologin "$user"
    ok "created the ${user} service account"
  fi
}

install_unit() {
  local name="$1" src="$2"
  if [[ -f "$src" ]]; then
    install -Dm0644 "$src" "${UNIT_DIR}/${name}.service"
  else
    return 1   # caller writes an inline unit instead
  fi
  return 0
}

# ---- hub ------------------------------------------------------------------

install_hub() {
  step "Installing the command hub"
  install_binary nswhub

  local statedir="${STATE_ROOT}/hub"
  install -d -m0700 "$statedir"

  [[ -n "$HUB_NAMES" ]] || {
    HUB_NAMES="$(hostname -f 2>/dev/null || hostname)"
    warn "no --names given; the TLS certificate will cover only '${HUB_NAMES}', localhost and 127.0.0.1"
    warn "browsers and agents reaching the hub by any other name will reject it"
  }

  [[ $INSTALL_SERVICE -eq 1 ]] || { info "skipping the service (--no-service)"; return; }

  # DynamicUser gives the hub a transient account and its own state directory.
  # It needs no capabilities at all: it does no raw networking.
  cat > "${UNIT_DIR}/nswhub.service" <<UNIT
[Unit]
Description=NetScan-WoL Command Hub
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=${BINDIR}/nswhub --data ${statedir} --listen ${HUB_LISTEN} --names ${HUB_NAMES}
Restart=on-failure
RestartSec=5s

DynamicUser=yes
StateDirectory=netscan-wol/hub
StateDirectoryMode=0700

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
NoNewPrivileges=yes
RemoveIPC=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
  ok "installed the nswhub service"

  systemctl daemon-reload
  if [[ $START_SERVICE -eq 1 ]]; then
    systemctl enable --now nswhub.service
    sleep 2
    if systemctl is-active --quiet nswhub.service; then
      ok "the hub is running"
    else
      warn "the hub did not start; check: journalctl -u nswhub -n 40"
    fi
  fi
}

# ---- agent ----------------------------------------------------------------

install_agent() {
  step "Installing the agent"
  install_binary nswagent

  # CAP_NET_RAW on the binary, rather than running the agent as root. It is the
  # only privilege ARP scanning needs.
  #
  # Setting file capabilities makes an exec behave like a setuid one, and in
  # some environments — a user namespace, or a filesystem mounted nosuid — the
  # result is a binary the kernel then refuses to run at all. That is worse
  # than no capability, so the grant is verified and rolled back if it broke
  # execution.
  grant_net_raw() {
    command -v setcap >/dev/null 2>&1 || {
      warn "setcap not found (install libcap2-bin or libcap); ARP scanning will be degraded"
      return 1
    }
    setcap cap_net_raw+ep "${BINDIR}/nswagent" 2>/dev/null || {
      warn "could not set CAP_NET_RAW on ${BINDIR}/nswagent"
      return 1
    }
    if ! "${BINDIR}/nswagent" version >/dev/null 2>&1; then
      setcap -r "${BINDIR}/nswagent" 2>/dev/null || true
      warn "the binary would not execute with file capabilities set, so they were removed."
      warn "This happens on nosuid mounts and inside some user namespaces."
      warn "Run the agent as root, or grant the capability through the service"
      warn "manager instead (the systemd unit below already uses AmbientCapabilities)."
      return 1
    fi
    ok "granted CAP_NET_RAW to nswagent"
    return 0
  }

  if grant_net_raw; then
    HAVE_NET_RAW=1
  else
    HAVE_NET_RAW=0
    info "ARP scanning will fall back to arp-scan or the kernel neighbour table"
  fi

  ensure_user nswagent
  local statedir="${STATE_ROOT}/agent"
  install -d -o nswagent -g nswagent -m0700 "$statedir"

  # ---- enrollment ----

  local secret=""
  if [[ -n "$TOKEN_FILE" ]]; then
    [[ -r "$TOKEN_FILE" ]] || die "cannot read the token file ${TOKEN_FILE}"
    secret="$(tr -d '[:space:]' < "$TOKEN_FILE")"
  elif [[ -n "$TOKEN" ]]; then
    secret="$TOKEN"
  elif [[ -n "${NSWAGENT_TOKEN:-}" ]]; then
    secret="$NSWAGENT_TOKEN"
  fi

  if [[ -n "$secret" && -n "$HUB_URL" ]]; then
    [[ ${#secret} -eq 64 ]] || die "the enrollment token must be 64 hex characters (got ${#secret})"

    if [[ -z "$CA_PIN" ]]; then
      warn "no --ca-pin given: the hub's certificate will be accepted on first"
      warn "contact without verification. Anyone able to intercept that"
      warn "connection could impersonate the hub and capture the token."
      warn "The hub UI shows the pin beside every token it issues."
    fi

    if [[ -f "${statedir}/agent.json" && $FORCE -eq 0 ]]; then
      info "already enrolled; pass --force to replace that identity"
    else
      step "Enrolling with ${HUB_URL}"
      local args=(enroll --hub "$HUB_URL" --token "$secret" --state "$statedir")
      [[ -n "$CA_PIN"       ]] && args+=(--ca-pin "$CA_PIN")
      [[ -n "$AGENT_NAME"   ]] && args+=(--name "$AGENT_NAME")
      [[ -n "$AGENT_LABELS" ]] && args+=(--labels "$AGENT_LABELS")
      [[ $FORCE -eq 1       ]] && args+=(--force)

      # Enroll as the service account so the key and certificate are written
      # with the ownership the service will run under. runuser is util-linux
      # and not everywhere, so fall back to su.
      if command -v runuser >/dev/null 2>&1; then
        runuser -u nswagent -- "${BINDIR}/nswagent" "${args[@]}" \
          || die "enrollment failed; the agent is installed but not joined"
      else
        su -s /bin/sh nswagent -c "$(printf '%q ' "${BINDIR}/nswagent" "${args[@]}")" \
          || die "enrollment failed; the agent is installed but not joined"
      fi
      ok "enrolled"
    fi
  else
    info "no hub or token given; enroll later with:"
    info "  sudo -u nswagent ${BINDIR}/nswagent enroll \\"
    info "    --hub https://HUB:8443 --token <64-hex> --ca-pin sha256:... \\"
    info "    --state ${statedir}"
    START_SERVICE=0
  fi

  [[ $INSTALL_SERVICE -eq 1 ]] || { info "skipping the service (--no-service)"; return; }

  cat > "${UNIT_DIR}/nswagent.service" <<UNIT
[Unit]
Description=NetScan-WoL Agent
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=${BINDIR}/nswagent run --state ${statedir}
Restart=always
RestartSec=10s

User=nswagent
Group=nswagent
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
NoNewPrivileges=yes
ReadWritePaths=${statedir}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
  ok "installed the nswagent service"

  systemctl daemon-reload
  if [[ $START_SERVICE -eq 1 ]]; then
    systemctl enable --now nswagent.service
    sleep 2
    if systemctl is-active --quiet nswagent.service; then
      ok "the agent is running"
    else
      warn "the agent did not start; check: journalctl -u nswagent -n 40"
    fi
  else
    systemctl enable nswagent.service >/dev/null 2>&1 || true
    info "the agent service is enabled but not started"
  fi
}

# ---- run ------------------------------------------------------------------

[[ "$COMPONENT" == "hub"   || "$COMPONENT" == "both" ]] && install_hub
[[ "$COMPONENT" == "agent" || "$COMPONENT" == "both" ]] && install_agent

# ---- what to do next ------------------------------------------------------

echo
step "Done"

if [[ "$COMPONENT" == "hub" || "$COMPONENT" == "both" ]]; then
  hub_port="${HUB_LISTEN##*:}"
  first_name="${HUB_NAMES%%,*}"
  cat <<EOF

  Command hub
    URL       https://${first_name}:${hub_port}
    State     ${STATE_ROOT}/hub
    Logs      journalctl -u nswhub -f

  The first-start username and password were printed to the hub's log:

    journalctl -u nswhub | grep -A3 'first start'

  Sign in, change the password, then open Enrollment to generate an agent
  token. Note the CA pin shown beside it — agents need it to verify this hub.

    ${BINDIR}/nswhub --data ${STATE_ROOT}/hub --print-pin
EOF
fi

if [[ "$COMPONENT" == "agent" || "$COMPONENT" == "both" ]]; then
  cat <<EOF

  Agent
    State     ${STATE_ROOT}/agent
    Logs      journalctl -u nswagent -f
    Identity  ${BINDIR}/nswagent status --state ${STATE_ROOT}/agent
    Networks  ${BINDIR}/nswagent interfaces

  If scans come back nearly empty, the agent is probably missing CAP_NET_RAW
  or is not attached to the segment you meant. Both show up in its startup log.
EOF
fi

echo

# NetScan-WoL v2

**Distributed network discovery and Wake-on-LAN. One command hub, agents
wherever your networks are.**

NetScan-WoL discovers every host on a broadcast domain using ARP — including
the machines that drop pings — and sends Wake-on-LAN magic packets to bring
them back. Version 2 splits the tool into a **hub** with a web interface and
**agents** that run on each network you want to reach, connected by mutual TLS.

Agents dial out to the hub, so a remote site needs no inbound firewall rule, no
port forward, and no static address.

```
                         ┌────────────────────┐
                         │    Command Hub     │
      browser ──TLS────▶ │  web UI · CA ·     │
                         │  agent API         │
                         └─────────▲──────────┘
                                   │ mutual TLS, agents dial out
              ┌────────────────────┼────────────────────┐
              │                    │                    │
        ┌─────┴─────┐        ┌─────┴─────┐        ┌─────┴─────┐
        │  agent    │        │  agent    │        │  agent    │
        │ office LAN│        │ k8s node  │        │ Proxmox   │
        └─────┬─────┘        └─────┬─────┘        └─────┬─────┘
          ARP · WoL             ARP · WoL            ARP · WoL
```

---

## What's new in v2

| | v1 | v2 |
|---|---|---|
| Shape | One bash script on one machine | Hub plus distributed agents |
| Reach | The network you ran it on | Every network with an agent |
| Transport | — | Mutual TLS, per-agent certificates |
| Joining agents | — | 256-bit single-use enrollment tokens |
| Interface | Dark-only desktop dashboard | Responsive, light/dark/system |
| Mobile | Not usable | Built mobile-first, works from 320px |
| ARP scanning | Shelled out to `arp-scan` | Native raw sockets, three fallbacks |
| Deployment | systemd service | systemd, Docker, Podman, Kubernetes, LXC |
| Dependencies | arp-scan, wakeonlan, Python, Flask | None — one static binary each |
| Auditing | Log file | Append-only audit log of every action |

---

## Features

**Command Hub**
- Responsive web interface, usable one-handed on a phone and dense on a desktop
- Light, dark, and match-device themes
- Live agent roster with platform, capabilities, reachable subnets, last contact
- Saved hosts keyed by MAC, so a DHCP change never loses a machine
- Scan history, per-agent, with the method used for each segment
- Append-only audit log of sign-ins, enrollments, agent changes, and every wake

**Agents**
- Native ARP scanning over raw sockets — no `arp-scan` package required
- Automatic fallback to `arp-scan`, then the kernel neighbour table, when raw
  sockets are unavailable, with a clear explanation of what was used
- Auto-discovery of every scannable interface, and a reason for each one skipped
- Hostname resolution via reverse DNS and a built-in mDNS client
- Vendor identification, including flagging virtual and locally administered MACs
- Wake-on-LAN with directed broadcast, SecureOn, custom ports and repeat counts
- Liveness checks over ARP, ICMP, then TCP, with MAC confirmation
- Runs on a host, in Docker or Podman, as a Kubernetes DaemonSet, or in a
  Proxmox LXC container

**Security**
- Mutual TLS with a per-agent certificate from the hub's own CA
- 256-bit enrollment tokens, single-use by default, stored only as hashes
- CA pinning to close the trust-on-first-use gap at enrollment
- PBKDF2 password hashing, session and CSRF protection, login throttling
- One capability for the agent (`CAP_NET_RAW`), none at all for the hub
- **Zero third-party dependencies** — Go standard library only

---

## Quick start

```bash
git clone https://github.com/fqazzazee/NetScan-WoL.git
cd NetScan-WoL

# See what's ready first — needs no privileges, changes nothing.
./install.sh check

# Then install. With no arguments it asks whether this server should be a
# dashboard hub, an agent, or both.
sudo ./install.sh hub --names hub.example.com
```

The installer downloads the release build for your platform, or compiles from
the checkout if there is no published build for it. It sets up a hardened
systemd unit and prints where to find the first-start password.

To run it without installing anything:

```bash
make build
./bin/nswhub --names hub.example.com
```

Open `https://hub.example.com:8443`, sign in, set a real password, then go to
**Enrollment** and generate a token. The UI shows the exact command to run on
the agent machine:

```bash
nswagent enroll --hub https://hub.example.com:8443 \
  --token 8f3c… --ca-pin sha256:1a2b…
nswagent run
```

Or let the installer do the whole agent side, enrollment included:

```bash
sudo ./install.sh agent \
  --hub https://hub.example.com:8443 \
  --token 8f3c… --ca-pin sha256:1a2b…
```

The agent appears in the hub within seconds. Select it, run a scan, wake
something.

Full per-platform instructions: **[docs/INSTALL.md](docs/INSTALL.md)**.

---

## Why ARP

Ping sweeps send ICMP echo requests and wait. Plenty of hosts — Windows
workstations especially — drop ICMP at the firewall and stay invisible.

ARP operates at Layer 2. Every host on a broadcast domain must answer ARP to
participate in the network at all; there is no firewall rule that blocks it
without also breaking the host's own connectivity. So an ARP sweep finds
everything on the segment: firewalled workstations, printers, IoT devices,
anything with an address.

The same property makes ARP the better liveness probe, which is why status
checks try it first and fall back to ICMP and TCP only when they must.

The cost is that ARP does not cross a router. That constraint is exactly why v2
is distributed: one agent per broadcast domain you care about.

---

## How the pieces fit

**The hub** serves the web interface, runs a private certificate authority, and
dispatches commands. It holds no network privileges and never connects to an
agent.

**Agents** hold a long poll open against the hub. When you run a scan, the
command is handed to the waiting poll, the agent executes it locally, and posts
the result back. Latency is a few milliseconds; connectivity requirements are
outbound-only.

**Enrollment** exchanges a one-time 256-bit token for a client certificate. The
hub stores only the token's hash and consumes it atomically, so a single-use
token admits exactly one agent even if two try at once.

**Removing an agent** deletes its record. The certificate stays valid but maps
to nothing, so every request it makes is refused — revocation without a CRL.

---

## Command reference

### `nswhub`

```
--listen ADDR              operator web interface address (default :8443)
--agent-listen ADDR        serve the agent API on its own port
--data DIR                 state, CA and audit log
--names LIST               DNS names and IPs for the TLS certificate
--insecure                 plain HTTP, for use behind a proxy you control
--trust-proxy-headers      honour X-Forwarded-For
--print-pin                print the CA fingerprint and exit
--reset-password USER      reset an operator's password and exit
--log-level LEVEL          debug, info, warn, error
```

### `nswagent`

```
nswagent enroll   join a hub with an enrollment token
nswagent run      connect and serve commands
nswagent status   show this agent's identity and capabilities
nswagent interfaces  list interfaces and which can be scanned

enroll options:
  --hub URL            hub address
  --token HEX          64-character enrollment token
  --token-file PATH    read the token from a file instead
  --ca-pin sha256:...  expected hub CA fingerprint
  --name NAME          display name in the hub
  --labels K=V,K=V     tags shown in the UI
  --state DIR          where to keep the key and certificate
```

---

## Deployment

| Platform | Assets |
|---|---|
| systemd | `deploy/systemd/` |
| Docker / Podman | `deploy/docker/` |
| Kubernetes | `deploy/kubernetes/` |
| Proxmox LXC | `deploy/proxmox/create-agent-lxc.sh` |

One rule applies everywhere: **the agent must be attached to the broadcast
domain it is meant to scan.** A container on a bridge network, or a pod on the
cluster overlay, can only see its own segment. Use host networking, a macvlan,
or a bridged LXC interface.

---

## Requirements

**Building:** Go 1.24 or newer. No other dependencies — no module downloads, no
build tooling, no network access.

**Hub:** any Linux, macOS or Windows host. No privileges.

**Agent:** Linux for native ARP scanning, with `CAP_NET_RAW`. It runs without
that capability and without root, falling back to `arp-scan` or the kernel
neighbour table, and tells you which it used.

**Targets:** Wake-on-LAN enabled in BIOS/UEFI and in the network adapter. On
Linux, `ethtool eth0` should report `Wake-on: g`.

---

## Security

The full threat model, trust boundaries, cryptographic choices, and a candid
list of known limitations are in **[docs/SECURITY.md](docs/SECURITY.md)**.

The short version: agents authenticate with per-agent certificates over mutual
TLS; enrollment uses single-use 256-bit tokens stored as hashes; the agent needs
one capability and the hub needs none; and the project depends on nothing
outside the Go standard library.

If you run agents, pass `--ca-pin`. It is the one thing that closes the
trust-on-first-use window at enrollment, and the hub prints it next to every
token.

---

## Development

```bash
make build       # both binaries
make test        # test suite
make test-race   # under the race detector
make test-raw    # raw ARP socket path, in a private network namespace
make check       # vet and test
make images      # container images via podman or docker
```

The raw-socket tests need `CAP_NET_RAW`; `make test-raw` arranges it with
`unshare` and a dummy interface, so it works unprivileged.

---

## Upgrading from v1

v2 is a different architecture and shares no code or data format with v1. There
is no migration path for saved hosts; the v1 file was `MAC|Label|IP|Timestamp`
per line and is straightforward to re-enter or convert by hand against the
`POST /api/v1/hosts` endpoint.

The v1 single-machine workflow maps to v2 as: run the hub and one agent on the
same box.

Nothing in v2 collides with v1 by name or port, so an old install keeps running
unnoticed and scanning the same network. The installer looks for one on every
run and offers to take it out; `--remove-v1` and `--keep-v1` answer that in
advance, and

```bash
sudo ./install.sh remove-v1
```

does it on its own. Either way it removes `netscan-wol-web.service` and
`/opt/netscan-wol` and leaves `~/.netscan-wol` — saved hosts, history and logs
— where it is.

---

## License

MIT

## Contributing

Issues and pull requests are welcome.

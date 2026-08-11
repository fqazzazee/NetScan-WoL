# Installation

Every deployment follows the same three steps: start the hub, generate an
enrollment token, join an agent with it. The rest of this document is the
per-platform detail.

## Contents

- [The install script](#the-install-script)
- [Build from source](#build-from-source)
- [The hub](#the-hub)
- [Agents on a host](#agents-on-a-host-systemd)
- [Agents in Docker or Podman](#agents-in-docker-or-podman)
- [Agents in Kubernetes](#agents-in-kubernetes)
- [Agents in a Proxmox LXC container](#agents-in-a-proxmox-lxc-container)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Backup and recovery](#backup-and-recovery)
- [Troubleshooting](#troubleshooting)

## The install script

`install.sh` handles the host-based cases: it fetches or builds the binaries,
creates the service account, installs a hardened systemd unit, grants the agent
`CAP_NET_RAW`, and enrolls the agent if you give it a token.

Run it with no arguments and it asks what this server should be:

```
  What should this server run?

    1) Dashboard hub    the web interface and certificate authority.
                        Other machines join it as agents.
    2) Agent            scans and wakes machines on this network,
                        reporting to a hub elsewhere.
    3) Both             hub and agent on this one server.
    4) Check only       report what is ready and what is missing,
                        change nothing.
```

Or name the component directly:

```bash
sudo ./install.sh hub --names hub.example.com

sudo ./install.sh agent \
  --hub https://hub.example.com:8443 \
  --token 8f3c… --ca-pin sha256:1a2b…

sudo ./install.sh both --names $(hostname)     # single-box, like v1
```

### Checking prerequisites

`./install.sh check` reports what is ready and changes nothing. It needs no
privileges, so you can run it before deciding anything:

```
 System
  ✓ root privileges                installing is possible
  ✓ operating system               linux/amd64
  ✓ systemd                        services can be installed
  ✓ disk space                     41260 MB free at /usr/local

 Obtaining binaries
  ✓ curl                           release downloads possible
  ✓ source checkout                present, so a source build is possible

 Hub
  ✗ port 8443                      already in use; choose another with --listen
  ✓ certificate names              hub.example.com

 Agent
  ✓ setcap                         CAP_NET_RAW can be granted
  ✓ scannable interfaces           eth0 eth1
  ✓ hub reachable                  https://hub.example.com:8443
  ! CA pin                         not supplied; enrollment falls back to trust-on-first-use
```

It checks privileges, platform, systemd, disk space, how binaries can be
obtained, the Go version if building from source, whether the hub's port is
free, whether an existing CA would be reused, whether `setcap` is available,
whether any interface can actually carry an ARP scan, whether the hub is
reachable, and whether the token and pin are well formed. It exits non-zero if
anything is blocking.

Pass `--check` to any install to run the same checks first and abort rather
than proceed when something is blocking:

```bash
sudo ./install.sh agent --check --hub https://hub.example.com:8443 --token 8f3c…
```

### Options

| Option | Effect |
|---|---|
| `--check` | Run the prerequisite check first, and stop if anything blocks |
| `--version VER` | Release to install (default 2.0.0) |
| `--source` | Build from the checkout instead of downloading |
| `--prefix DIR` | Install prefix (default `/usr/local`) |
| `--no-service` | Binaries only, no systemd unit |
| `--no-start` | Create the unit but leave it stopped |
| `--force` | Reinstall, and re-enroll over an existing identity |
| `--uninstall` | Remove the component, keeping its state |

Notes on what it does:

- Release binaries are checksum-verified against the published `SHA256SUMS`.
  A mismatch aborts; a missing checksum file warns and continues, so a
  pre-release still installs.
- If there is no published build for your platform, it falls back to compiling
  from the checkout, which needs only a Go toolchain.
- `--uninstall` deliberately leaves state behind. For the hub that directory
  holds the certificate authority, and deleting it would silently invalidate
  every enrolled agent.
- After granting `CAP_NET_RAW` it checks the binary still executes. On a
  `nosuid` mount or inside some user namespaces, file capabilities make a
  binary unrunnable; in that case the capability is removed and the script says
  so, rather than leaving you with an agent that will not start.

For containers, Kubernetes and Proxmox, use the platform sections below
instead.

## Build from source

Go 1.24 or newer. There are no other dependencies — no module downloads, no
build tools, no network access required.

```bash
git clone https://github.com/fqazzazee/NetScan-WoL.git
cd NetScan-WoL
make build          # produces bin/nswhub and bin/nswagent
sudo make install   # installs to /usr/local/bin and grants CAP_NET_RAW
```

`make release` cross-compiles for linux/amd64, arm64 and arm with checksums.

## The hub

```bash
nswhub --names hub.example.com
```

On first start the hub creates its certificate authority, generates an admin
password, and prints both:

```
╭──────────────────────────────────────────────────────────────╮
│  NetScan-WoL Command Hub — first start                       │
│  Username:  admin                                            │
│  Password:  iJG8iHR2LG4dijJYGS6E                             │
╰──────────────────────────────────────────────────────────────╯

level=INFO msg="agents should pin this CA fingerprint" pin=sha256:4dd0706a…
```

Write down the pin. Agents use it to verify the hub.

**`--names` matters.** Every DNS name and IP address that a browser or an agent
will use to reach the hub must be listed, or the TLS certificate will not match
it. The hub adds `localhost`, `127.0.0.1` and its own hostname automatically.

Browse to `https://hub.example.com:8443`, sign in, and set a real password.

### Running it as a service

```bash
sudo make install-services
sudo systemctl enable --now nswhub
sudo journalctl -u nswhub | head -20   # the first-start password
```

The bundled unit uses `DynamicUser`, drops every capability, and confines the
hub to its own state directory.

### Splitting the agent plane

By default both the web UI and the agent API are served on one port, which is
simplest to expose through a single ingress. To firewall them separately:

```bash
nswhub --names hub.example.com --listen :8443 --agent-listen :8444
```

The join command shown in the UI is rewritten to point at the agent port.

## Agents on a host (systemd)

Generate a token in the hub UI under **Enrollment**, then on the target machine:

```bash
sudo install -m0755 nswagent /usr/local/bin/nswagent
sudo setcap cap_net_raw+ep /usr/local/bin/nswagent
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nswagent
sudo install -d -o nswagent -g nswagent -m0700 /var/lib/netscan-wol/agent

sudo -u nswagent nswagent enroll \
  --hub https://hub.example.com:8443 \
  --token 8f3c… --ca-pin sha256:4dd0706a… \
  --state /var/lib/netscan-wol/agent

sudo cp deploy/systemd/nswagent.service /etc/systemd/system/
sudo systemctl enable --now nswagent
```

To keep the token out of your shell history and the process list, use
`--token-file` or the `NSWAGENT_TOKEN` environment variable instead of
`--token`.

Check what the agent can see:

```bash
nswagent interfaces
```

## Agents in Docker or Podman

```bash
podman build -f deploy/docker/Containerfile.agent -t netscan-wol-agent:2.0.0 .

podman volume create nswagent-state

# Enroll once.
podman run --rm --network host \
  -v nswagent-state:/var/lib/netscan-wol/agent \
  netscan-wol-agent:2.0.0 enroll \
    --hub https://hub.example.com:8443 \
    --token 8f3c… --ca-pin sha256:4dd0706a… \
    --state /var/lib/netscan-wol/agent

# Then run it.
podman run -d --name nswagent --restart=unless-stopped \
  --network host --cap-drop=ALL --cap-add=NET_RAW \
  -v nswagent-state:/var/lib/netscan-wol/agent \
  netscan-wol-agent:2.0.0 run --state /var/lib/netscan-wol/agent
```

Substitute `docker` for `podman` throughout; the Containerfile is the same.

**Host networking is not optional.** ARP is a Layer 2 protocol, and a container
on a bridge network sits in its own broadcast domain — it can see other
containers and nothing else. Use `--network host`, or attach a macvlan
interface to the segment you want to scan.

**Rootless Podman cannot grant `CAP_NET_RAW`.** `--cap-add=NET_RAW` only adds
the capability within your user namespace, and raw sockets on the host network
need it in the initial namespace. A rootless agent falls back to the neighbour
table and says so in its log. Run the container rootful for full ARP scanning.

## Agents in Kubernetes

Read the comments at the top of `deploy/kubernetes/agent.yaml` before applying
it — the networking constraints are the same as for containers and matter more,
because a pod on the overlay network will happily scan the overlay and report
nothing you wanted.

```bash
kubectl apply -f deploy/kubernetes/hub.yaml
kubectl -n netscan-wol logs deploy/nswhub | head -20    # first-start password

# Label the nodes that sit on the network you want to reach.
kubectl label node worker-1 netscan-wol/agent=true

# Put a token and the CA pin into the enrollment Secret, then:
kubectl apply -f deploy/kubernetes/agent.yaml
```

Points worth knowing:

- The agent DaemonSet uses `hostNetwork: true`. Without it, ARP scans see only
  the pod network.
- It adds `NET_RAW` and drops everything else. `privileged: true` is not needed
  and would grant far more.
- A single-use token admits one pod. For a DaemonSet across several nodes, issue
  a token with `max_uses` set to the node count.
- Agent identity is kept on a `hostPath`, so a restarted pod reuses it instead
  of consuming another token.
- The hub is one replica by design: state is a file and the CA must not issue
  from two places at once.
- The hub's PVC holds the CA. **Losing it invalidates every enrolled agent.**

## Agents in a Proxmox LXC container

There is a script for this. Run it on the Proxmox host:

```bash
./deploy/proxmox/create-agent-lxc.sh \
  --hub https://hub.example.com:8443 \
  --token 8f3c… \
  --ca-pin sha256:4dd0706a… \
  --bridge vmbr0 \
  --hostname nswagent-lan
```

It creates an **unprivileged** container, installs the agent, enrolls it, and
sets up the service. Unprivileged is sufficient: the container holds
`CAP_NET_RAW` within its own user namespace, and because its veth is bridged
onto a real Proxmox bridge, that namespace is attached to the physical
broadcast domain.

To reach a different VLAN, pass `--vlan 50` and bridge accordingly. One agent
per broadcast domain you want to cover — that is the whole point of the
distributed design.

What does *not* work is an unprivileged container on an isolated or NAT bridge.
The agent would see only the container network.

## Behind a reverse proxy

The hub speaks TLS with its own certificate. A proxy in front of it can either
re-encrypt or terminate.

**Re-encrypting** keeps agents working unchanged, because they still reach the
hub's own TLS and can verify the CA pin. With nginx-ingress that is
`nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`.

**Terminating TLS at the proxy** is nicer for browsers, since you can use a
publicly trusted certificate. Agents then need a path to the hub's own TLS —
usually a separate listener via `--agent-listen`, exposed directly.

Running the hub itself plaintext behind a proxy:

```bash
nswhub --insecure --listen 127.0.0.1:8080 --trust-proxy-headers
```

Only do this when the proxy is on the same host or a trusted link.
`--trust-proxy-headers` makes the hub believe `X-Forwarded-For`; without a proxy
in front, that would let anyone reset their own login throttle by inventing a
header.

## Backup and recovery

Back up the hub's data directory — that is the whole system:

```
<data-dir>/
├── hub-state.json     agents, hosts, tokens, settings, password hashes
├── audit.log          append-only security log
└── pki/
    ├── ca.crt/ca.key  the certificate authority
    └── hub.crt/hub.key the hub's TLS certificate
```

Losing `pki/ca.key` means every agent must re-enroll. Back it up, and back it
up somewhere that is not readable by everyone, because it mints agent
identities.

Locked out of the web UI:

```bash
nswhub --data /var/lib/netscan-wol/hub --reset-password admin
```

Retrieve the CA pin at any time:

```bash
nswhub --data /var/lib/netscan-wol/hub --print-pin
```

## Troubleshooting

**The agent will not enroll: "no certificate in the hub's chain matches the
pin".** The pin does not match the hub you are reaching. Confirm it with
`nswhub --print-pin`, and check you are not being intercepted by a proxy.

**"enrollment token cannot be used: token has already been used".** Tokens are
single-use by default. Generate another.

**The agent connects but scans find almost nothing.** Almost always missing
`CAP_NET_RAW` or wrong networking. Check the agent's startup log, then:

```bash
nswagent interfaces     # what it can scan and why the rest are excluded
nswagent status         # its identity and capabilities
```

If capabilities do not include `arp-raw`, scans are falling back to the
neighbour table.

**A wake does nothing.** Magic packets do not cross a router by default. Check
the agent you sent from is on the same broadcast domain as the target — the
hub picks one automatically based on the host's last known IP, but you can pin
a specific agent per saved host. Also confirm Wake-on-LAN is enabled in the
target's BIOS/UEFI *and* its network adapter settings; on Linux, `ethtool eth0`
should show `Wake-on: g`.

**A host shows as online but with a MAC mismatch warning.** DHCP handed its
address to a different machine. Rescan to refresh the mapping.

**The browser warns about the certificate.** Expected: the hub uses its own CA.
Either accept it, add `pki/ca.crt` to your trust store, or terminate TLS at a
proxy with a publicly trusted certificate.

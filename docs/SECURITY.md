# Security overview

NetScan-WoL v2 does two things that deserve care: it scans networks, and it
turns machines on. Both are ordinary administrative actions and both are useful
to an attacker who gets hold of them. This document sets out what the system
protects, how, and where the limits are.

## What the system is

A **hub** holds the operator interface and a private certificate authority.
**Agents** run on the networks you want to reach. Agents dial out to the hub and
hold a connection open; the hub never connects to an agent. Every agent has its
own certificate, issued by the hub, and proves itself with it on every request.

The practical consequence is that an agent needs no inbound firewall rule, no
port forward, and no static address. It needs only to be able to reach the hub.

```
  operator browser              hub                        agent
  ───────────────               ───                        ─────
  session cookie  ──TLS──▶  ┌─────────┐  ◀──mTLS (agent   ┌──────────┐
  + CSRF token              │ web UI  │      dials out)   │ ARP scan │
                            │ agent   │                   │ WoL send │
                            │ API     │                   └────┬─────┘
                            │ CA      │                        │
                            └────┬────┘                   ┌────▼─────┐
                                 │                        │ the LAN  │
                            state + audit                 └──────────┘
```

## Trust boundaries

There are four, in decreasing order of trust.

| Boundary | Who is on the other side | How it is controlled |
|---|---|---|
| Hub data directory | Anyone with filesystem access | 0700 directory, 0600 keys and state |
| Operator API | A browser with a session | Password + session cookie + CSRF token |
| Agent API | An enrolled agent | Mutual TLS with a per-agent certificate |
| Enrollment | Anyone who reaches the port | 256-bit single-use token, rate limited |

Anyone who can read the hub's data directory owns the deployment: `pki/ca.key`
mints agent identities, and `hub-state.json` holds the password and token
hashes. Nothing in the design defends against that, so the directory
permissions are load-bearing rather than housekeeping.

## Agent identity and enrollment

Enrollment is the only point where a shared secret is used, and it is the one
step worth understanding in detail.

1. The operator generates a token in the hub UI. It is **256 bits** of
   cryptographic randomness, shown as 64 hex characters. The hub stores only a
   SHA-256 hash, so the token is displayed exactly once and cannot be recovered
   afterwards — only replaced.
2. The agent generates an Ed25519 key pair locally. The private key never
   leaves the machine.
3. The agent sends its CSR and the token to the hub.
4. The hub matches the token against stored hashes in constant time, consumes
   one use of it **atomically**, then issues a certificate.
5. The agent stores its certificate and the hub's CA, and uses mutual TLS from
   then on. The token is never used again.

Tokens default to **single use** with a **60-minute expiry**. Both are
adjustable, but a token that admits any number of agents forever is the thing
most likely to end up pasted into a wiki page and forgotten.

Only the public key is taken from the CSR. The subject, validity, and key usage
are all set by the hub, so an agent cannot talk its way into a different
identity by crafting a creative CSR.

### The trust-on-first-use gap, and how to close it

An agent that has never spoken to the hub has no CA to verify it against. If it
simply accepted whatever certificate answered, an attacker positioned in the
network path could impersonate the hub and capture the enrollment token.

This is why the hub prints a **CA pin** — the SHA-256 fingerprint of its
certificate authority — next to every token it issues, and why the join command
includes it:

```
nswagent enroll --hub https://hub.example.com:8443 \
  --token 8f3c… --ca-pin sha256:1a2b…
```

With `--ca-pin`, the certificate is verified before the token is transmitted.
Without it the agent enrolls anyway but prints a warning, because a first-run
experience that hard-fails tends to get worked around with `--insecure` flags
rather than fixed.

Carry the pin over from the hub UI. It closes the only window in the design
where an interception attack works.

## Revocation

There is no CRL and no OCSP. Removing an agent deletes its record; the
certificate stays cryptographically valid but no longer maps to anything, and
every request it makes is refused at the first check in the handler. Disabling
an agent has the same effect while keeping the record for reference.

This is simpler than certificate revocation and, for this shape of system,
strictly better: the check is centralised, immediate, and cannot be missed by a
client that failed to fetch a revocation list.

## Operator authentication

- Passwords are hashed with **PBKDF2-HMAC-SHA256, 600,000 iterations** and a
  16-byte random salt. That is the current OWASP guidance and costs roughly a
  quarter-second per login.
- The first-start password is generated, printed once to stderr, and marked
  must-change; the UI insists on a real one before anything else can be done.
- Failed logins are throttled per source address: 8 attempts in 10 minutes, then
  a 15-minute lockout.
- A password is verified against a dummy record even when the username does not
  exist, so response latency does not enumerate valid usernames.
- Changing a password invalidates every session for that user, including the one
  making the change. If the change was prompted by a suspected compromise,
  leaving the attacker's session alive would defeat the point.
- Sessions live in memory only. They expire after 12 hours absolute or 2 hours
  idle, and do not survive a hub restart.

## Web interface

- The session cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` whenever TLS
  is on.
- Every state-changing request also carries a CSRF token in the `X-NSW-CSRF`
  header, compared in constant time.
- The Content-Security-Policy is `'self'` for every directive, with
  `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`. The UI
  ships no third-party code and makes no external requests, so nothing looser is
  needed.
- The client never assigns network data to `innerHTML`. Hostnames and vendor
  strings come from devices on an untrusted segment; a printer with a crafted
  mDNS name should not be able to script the page.
- `X-Forwarded-For` is ignored unless `--trust-proxy-headers` is passed. A
  spoofable client address would let anyone reset their own login throttle.

## Agent privileges

The agent needs exactly one capability: `CAP_NET_RAW`, for the raw sockets ARP
and ICMP require. It does not need root, and every packaged deployment grants
the capability rather than the user:

| Deployment | Mechanism |
|---|---|
| systemd | `AmbientCapabilities=CAP_NET_RAW`, dedicated user |
| Docker / Podman | `--cap-drop=ALL --cap-add=NET_RAW` |
| Kubernetes | `capabilities: {drop: [ALL], add: [NET_RAW]}` |
| Proxmox LXC | `setcap cap_net_raw+ep` in an unprivileged container |

Without the capability the agent still runs. Scans fall back to the external
`arp-scan` binary if present, and then to the kernel neighbour table, which
reports only hosts the machine has recently talked to. The agent says so at
startup rather than leaving you to work it out from thin results.

The hub needs **no** capabilities and runs as a non-root user everywhere.

## Input handling

Two parsers read bytes straight off an untrusted network, and both are written
defensively:

- **ARP replies.** Every length and field is checked before use. Zero and
  broadcast sender addresses are rejected, as are replies for addresses that
  were never probed — other hosts' ARP chatter is constantly on the wire.
- **mDNS responses.** Compression-pointer following is depth-limited. A device
  can craft a name that points at itself, and without the cap that is an
  infinite loop in a network-facing parser. Every offset is bounds-checked.

Elsewhere:

- Scans are capped at a **/18**. A mistyped `/8` would otherwise queue sixteen
  million probes at the segment.
- Wake-on-LAN refuses the broadcast and all-zero MACs, and clamps the packet
  count to 16, so the endpoint cannot be used as a broadcast flooder.
- Request bodies are capped at 4 MiB.
- JSON decoding rejects unknown fields, so a typo in an API call fails loudly.
- The `arp-scan` fallback is invoked with arguments built from validated
  interface names and parsed CIDRs, never from operator free text.

## Auditing

An append-only JSON-lines log records sign-ins and failures, enrollments,
token issuance and revocation, agent removal and disabling, settings changes,
and **every wake command**.

Wakes are audited because a magic packet is a physical-world side effect. "Who
turned that machine on at 3am" is a question worth being able to answer.

The log is at `<data-dir>/audit.log`, one JSON object per line, readable with
`grep` or shippable to a collector when the hub itself is unavailable.

## Supply chain

The project uses **nothing outside the Go standard library**. `go.mod` has no
`require` block and there is no `go.sum`. For a tool that runs with raw socket
access on your network, the entire dependency surface being the Go standard
library is a deliberate design choice rather than an accident of scope.

Both binaries build with `CGO_ENABLED=0` into static executables, and the
container images are `FROM scratch` — no shell, no package manager, nothing for
an attacker who reaches the container to pivot with.

## Cryptography

| Purpose | Choice |
|---|---|
| Agent and hub keys | Ed25519 |
| Transport | TLS 1.2 minimum, AEAD ciphers with forward secrecy only |
| Agent authentication | Mutual TLS, one certificate per agent |
| Enrollment tokens | 256-bit random, SHA-256 stored, constant-time compared |
| Operator passwords | PBKDF2-HMAC-SHA256, 600,000 iterations |
| Session and CSRF tokens | 256-bit random |
| Certificate serials | 128-bit random |

Certificate lifetimes: CA 10 years, hub and agent leaves 2 years, backdated 10
minutes to absorb the clock skew common on appliances that boot without NTP.

## Known limitations

These are design decisions, not oversights, but you should know about them.

- **Without `--ca-pin`, enrollment is trust-on-first-use.** See above. Pass the
  pin.
- **A single operator role.** Anyone who can sign in can do anything: scan, wake,
  enroll, remove agents. There is no read-only or per-agent scoping.
- **The hub does not scale out.** State is a JSON file and the CA must not issue
  from two places at once. One replica, by design. This is sized for tens of
  agents and thousands of hosts, not a datacentre inventory.
- **Sessions are lost on restart.** Everyone signs in again. This is deliberate:
  persisting live session tokens next to the password hashes would widen what a
  stolen backup is worth.
- **A compromised agent can scan and wake on its own segment.** That is what an
  agent is for. Disabling it in the hub cuts it off immediately, but anything it
  did before that stands.
- **Wake-on-LAN is unauthenticated by design.** Magic packets carry no identity;
  any host on the segment can send one. The hub controls who can ask an agent to
  send, not who can send on the wire. SecureOn adds a six-byte password where
  the target NIC supports it, which is weak but better than nothing.
- **ARP scanning is visible.** It is not stealthy and is not meant to be. On a
  monitored network it will show up, and on a network you do not own it may
  breach policy. Scan what you are authorised to scan.

## Reporting a vulnerability

Open a security advisory on the GitHub repository rather than a public issue.

# localnetwork: the outbound-connection broker

A program that needs to make a network connection normally holds the authority
to make *any* connection: `socket(2)` plus `connect(2)` reach every address the
routing table can, bind and listen at will, and — with privilege — open raw
sockets. In the capability plane that is far more authority than most components
should carry, and it is exactly the authority an attacker wants when a component
is compromised (the classic server-side request forgery pivot). `localnetwork(8)`
is 5BSD's outbound-connection broker: it exposes `system.Network` as a
socket-free service provider and hands a component a *connected, hardened*
socket scoped to the network rights that component was actually granted — never
a general-purpose networking privilege.

| Component | Location |
|-----------|----------|
| Provider, policy, and worker | `usr.sbin/localnetwork/` |
| Client library `libnetworkcmp(3)` | `lib/libnetworkcmp/` |
| Operator tool | `usr.sbin/networkcmpctl/` |
| Service bundle | `usr.sbin/localnetwork/capbundle/` |
| Tests | `usr.sbin/localnetwork/tests/`, `lib/libnetworkcmp/tests/` |

## What it brokers, and what it deliberately does not

`localnetwork` exposes three operations and no more:

- **RESOLVE** — a bounded `getaddrinfo(3)` performed through Casper
  (`cap_dns`), so name resolution happens without the caller holding DNS or
  filesystem authority.
- **CONNECT** — an established TCP connection to a permitted destination,
  delivered as a hardened socket.
- **UDP** — a *connected* datagram socket to a permitted destination.

There is deliberately **no listen, no bind, and no raw socket**. Inbound
sockets and raw-socket access are a different and larger authority surface;
rather than smuggle them in behind an under-specified flag, they are reserved
for a future negotiated protocol version. The current interface is outbound
client connectivity, stated explicitly, so the absence of a listen path is a
contract rather than an oversight.

## The delivered socket is stripped

A connection is only as safe as the descriptor the client ends up holding. When
`localnetwork` delivers a socket it is not an ordinary full-authority socket
descriptor — it is narrowed, before delivery, to the rights a network client
legitimately needs:

- Capability rights limited to read, write, event, shutdown,
  `getsockopt`/`setsockopt`, and `fstat`.
- An ioctl allow-list of exactly **3** ioctls.
- Delivered with `CAP_XFER_ONCE`, so the single admitted hop consumes the
  transfer and the client cannot re-delegate it (see
  [Capability Transfer](../security/capability-transfer.md)).

The client can send, receive, poll, shut down, and inspect socket options — the
things a network client does — but it cannot reconnect the socket elsewhere,
turn it into a listener, or hand it onward. The dangerous parts of a socket's
generality are gone by the time the client touches it.

## Authority is derived from granted rights, not hardcoded

This is the part that makes `localnetwork` a capability service and not just a
proxy with an allow-list. A session's policy is **derived from the caller's
granted rights** — the per-service `identity.rights` bits the session carries —
not from a table inside the daemon and not from a hardcoded allow-all. The
relevant bits are the `NETWORKCMP_RIGHT_*` family:

| Right | Grants |
|-------|--------|
| `NETWORKCMP_RIGHT_RESOLVE` | name resolution |
| `NETWORKCMP_RIGHT_CONNECT` | TCP connect |
| `NETWORKCMP_RIGHT_UDP` | connected datagram |
| `NETWORKCMP_RIGHT_INET4` | IPv4 destinations |
| `NETWORKCMP_RIGHT_INET6` | IPv6 destinations |
| `NETWORKCMP_RIGHT_INTERNAL` | otherwise-blocked internal ranges (below) |

A session that carries **no** network rights gets **nothing** — the default is
deny, not allow. Each operation is checked against the bits the session actually
holds: a component granted only RESOLVE can look names up but cannot connect; one
granted CONNECT+INET4 reaches IPv4 TCP but not IPv6 or UDP. `SERVICE_RIGHTS_ADMIN`
is the full bypass, used by the operator plane. Because the policy is the
session's own rights, two clients of the same daemon can have genuinely
different network reach without any per-client configuration in `localnetwork`
itself.

## Destination constraint: SSRF defense

Rights govern *whether* and *how* a session may connect; a separate constraint
governs *where*. Before connecting, a **non-admin** session is blocked from a
set of sensitive destination ranges:

- loopback
- link-local
- RFC 1918 private ranges
- other internal ranges

The check happens **before** `connect(2)`, so a brokered connection cannot be
steered at the loopback interface or the internal network — the standard
server-side request forgery pivot, where an attacker who controls a URL or
hostname a component will fetch aims it at `127.0.0.1` or a metadata address.
A session that legitimately needs internal reach must carry
`NETWORKCMP_RIGHT_INTERNAL` (or admin); otherwise these ranges are refused
regardless of the resolved address, including addresses that resolve to them via
DNS.

## The service model

`localnetwork` is an ordinary socket-free provider (see
[serviced](../system/serviced.md) and
[Writing a Service Provider](../development/writing-components.md)): it publishes
`system.Network` in `activation.ipc`, stays stopped until first lookup, and
`pdfork(2)`s one worker per client that `cap_enter(2)`s. Consumers link
`libnetworkcmp(3)` and reach it lazily on first use; the CLI `networkcmpctl`
exercises resolve/connect/udp for operators. The client never opens a socket
itself — it asks the broker and receives a connected, stripped descriptor.

## What makes the attenuation *live*: the minter

The design above describes a fine-grained, default-deny network policy — but it
is only as fine-grained as the rights each session actually carries, and those
rights have to be **stamped onto the session by the minter**. `localnetwork`
enforces `identity.rights`; it does not invent them. The complementary work is
in the session/launch minter — `serviced` at launch and the auth-agent
(`system.authagent`) at the authentication boundary, see
[serviced](serviced.md) and
[The Authentication Boundary](../security/session-mint.md) — stamping the
per-manifest `NETWORKCMP_RIGHT_*` bits so that a component's declared network
needs become the exact rights its sessions hold.

Where that stamping is complete, a component reaches precisely the network its
manifest asked for and no more. Where it is not yet wired for a given
provider, that provider's sessions fall back on the coarse defaults, and the
attenuation this chapter describes is present in the broker but not yet
exercised end to end. The broker side is the mechanism; the minter stamping
per-manifest rights is what turns it into live, per-component network policy.

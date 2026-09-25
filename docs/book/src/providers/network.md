# system.Network (BSDNetwork)

## What it brokers

A process that can call `socket(2)` and `connect(2)` holds the authority to reach every address the routing table can, which is exactly what an attacker wants in a compromised component. BSDNetwork is the `system.Network` provider: a connection broker that performs name resolution and socket setup on a client's behalf and hands back a real, connected, rights-narrowed socket over `SCM_RIGHTS`. The broker never proxies data. Once the descriptor is delivered, the client owns all I/O on it and BSDNetwork retains no socket state.

Four things are brokered: forward resolution (RESOLVE), TCP connections (CONNECT), connected UDP sockets (UDP) and loopback TCP listeners on an OS-assigned port (LISTEN). Each delivered socket is limited with `cap_rights_limit(2)` to the data path (`CAP_READ`, `CAP_WRITE`, `CAP_EVENT`, `CAP_SHUTDOWN`, `CAP_GETSOCKOPT`, `CAP_SETSOCKOPT`, `CAP_FCNTL`, `CAP_FSTAT`, `CAP_IOCTL`), with ioctls limited to `FIONREAD`, `FIONBIO` and `FIOASYNC`, fcntl limited to `F_GETFL`/`F_SETFL`, and its transfer state latched to `CAP_XFER_ONCE` so it can cross to the client exactly once and never be re-sent (see [Descriptor and Process Protections](../capability/descriptor-protections.md)). A listening socket additionally carries `CAP_ACCEPT`; accepted connections inherit its rights.

The broker is born in capability mode. Casper's `cap_net` is retired: the in-process resolver in `usr.sbin/BSDNetwork/resolver.c` reads `/etc/resolv.conf`, `/etc/hosts` and `/etc/services` on demand through [system.Filesystem](filesystem.md) with `service_open_isolated(3)`, and issues its own bounded DNS queries on a dedicated thread so a slow resolver cannot stall socket operations. INET `bind` and `connect` are legal in capability mode because `sobindat()`/`soconnectat()` fall back to the protocol's plain bind and connect when no `*at` form exists (`sys/kern/uipc_socket.c`); this is the one-point kernel change that lets a sandboxed broker create sockets at all.

Each client is served by a private `pdfork(2)` worker enlisted in the client's coalition. The worker cannot fork, exec or receive unrelated descriptors. Session policy is resolved once at session creation from the caller's unforgeable manifest label and never changes; a request carries no policy object.

## Unit

Source: `usr.sbin/BSDNetwork/capbundle/bsdnetwork.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire name | `system.Network` (interface version `1.0.0`, ABI 1) |
| Bundle | `/Capabilities/System/Network.cap` (`bundle_id = "system.Network"`) |
| Program | `/Capabilities/System/Network.cap/Units/bsdnetwork.unit/bin/BSDNetwork` |
| Unit | `bsdnetwork` |
| User | `capability` |
| Launch | born in capability mode (`ambient` not set); `activation { boot = true; ipc = ["system.Network"]; }` |
| Control | `system` |
| Gates | none (`capabilities` block absent); no `directories` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024; nproc = 128; core = 0`; `umask = "0077"` |
| Config | `Units/bsdnetwork.unit/Config/bsdnetwork.conf` |

## Wire operations

Defined in `lib/libnetworkcmp/networkcmp_protocol.h`. Every message starts with `struct networkcmp_msg` (magic `NCMP`, `version`, `opcode`, `flags`, `status`); a reply's `status` is 0 or a negative errno. HELLO negotiates: the client sends `min_version`/`max_version`/`features`, the broker answers with the ABI version, the feature bits its session policy grants (`TCP`, `UDP`, `IPV6`, `DNS`, `LISTEN`) and `max_resolve_results`. A client should treat the HELLO reply as the binding contract for the session.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `HELLO` (1) | `networkcmp_hello` | `networkcmp_hello_reply` | `EPROTO` malformed |
| `RESOLVE` (2) | `networkcmp_resolve_request` + host and service bytes | `networkcmp_resolve_reply` + up to `NETWORKCMP_RESOLVE_MAX_RESULTS` (32) `networkcmp_resolve_result` + canonname | `EACCES` resolve off; `EBUSY` one already in flight; `ENOENT` no such name; `EAGAIN` try again; `EPROTONOSUPPORT` bad service or socket type; `EAFNOSUPPORT` pinned family denied; `EIO` |
| `CONNECT` (3) | `networkcmp_connect_request` (endpoint, `timeout_ms`) | header, plus one delivered fd | `EACCES` connect off or internal range; `EAFNOSUPPORT` family off; `ETIMEDOUT` deadline; kernel connect errors (`ECONNREFUSED`, ...) |
| `UDP` (4) | `networkcmp_connect_request` (`timeout_ms` ignored) | header, plus one delivered fd | `EACCES` udp off or internal range; `EAFNOSUPPORT` |
| `LISTEN` (5) | `networkcmp_listen_request` (`backlog`, 0 = `SOMAXCONN`) | `networkcmp_listen_reply` (`port`), plus one delivered fd | `EACCES` listen off; `EINVAL` reserved bits set |

`timeout_ms` bounds only the TCP handshake; zero selects a blocking connect. A resolve that exceeds the broker's 30 second deadline terminates the client's private worker rather than leaving the session stuck in `EBUSY`; the typed client observes peer death.

## Client library

Header `<networkcmp.h>` (installs `networkcmp.h`, `networkcmp_protocol.h`, `networkcmp_server.h`); link with `-lnetworkcmp` (`SHLIB_MAJOR 1`, depends on libservice and pthread). Manual: libnetworkcmp(3).

| Group | Functions |
|---|---|
| Session | `networkcmp_client_open`, `networkcmp_client_limits`, `networkcmp_client_close`, `networkcmp_hello` |
| Sockets | `networkcmp_connect`, `networkcmp_connect_ex` (adds `timeout_ms`), `networkcmp_udp`, `networkcmp_listen` |
| Resolution | `networkcmp_resolve`, `networkcmp_getaddrinfo`, `networkcmp_freeaddrinfo` |

The library keeps one process-wide session; repeated opens return borrows of it and `networkcmp_client_close()` releases a borrow. `networkcmp_getaddrinfo()` accepts `AI_PASSIVE`, `AI_CANONNAME`, `AI_NUMERICHOST`, `AI_NUMERICSERV`, `AI_ADDRCONFIG` (a documented no-op), `AI_V4MAPPED` and `AI_ALL`, returns an `EAI_*` status, and its list must be freed with `networkcmp_freeaddrinfo()`. A malformed reply marks the session terminal: every later call fails with `EPROTO`. A child after `fork(2)` cannot reuse the parent's session.

```c
#include <networkcmp.h>
#include <err.h>
#include <unistd.h>

int
dial(const char *host, const char *port)
{
	struct networkcmp_client *nc;
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *res;
	int fd = -1;

	if (networkcmp_client_open(&nc) == -1)
		err(1, "system.Network");
	if (networkcmp_getaddrinfo(nc, host, port, &hints, &res) != 0)
		errx(1, "resolve %s", host);
	if (networkcmp_connect_ex(nc, res->ai_addr, res->ai_addrlen,
	    5000, &fd) == -1)
		warn("connect %s", host);
	networkcmp_freeaddrinfo(res);
	networkcmp_client_close(nc);
	return (fd);	/* rights-narrowed; read/write/shutdown only */
}
```

## Command-line tool

networkcmpctl(8) is a bounded diagnostic client that reaches the broker only through libnetworkcmp and gains no extra network authority. Its session policy is whatever the invoking label's policy is.

| Verb | Example | Output shape |
|---|---|---|
| `config` | `networkcmpctl config` | the canonical manifest declaration for this component |
| `info` | `networkcmpctl info` | `version=1 features=0x0000000f max_resolve_results=16` |
| `resolve host [service]` | `networkcmpctl resolve www.freebsd.org https` | `count=2 ttl_seconds=0 canonname=...` then `result[0].family=inet6 address=... port=443 scope_id=0 ...` per entry |
| `connect addr port` | `networkcmpctl connect 96.47.72.84 443` | `connect ok: connected to 96.47.72.84:443` |
| `udp addr port` | `networkcmpctl udp 9.9.9.9 53` | `udp ok: connected datagram socket to 9.9.9.9:53` |
| `listen` | `networkcmpctl listen` | `listen ok: port=49152 accepted and verified` |

`listen` is an end-to-end self-test: it takes a listener from the broker, connects to it over one ordinary loopback socket, accepts, and verifies a byte flows. Under the shipped policy `connect 127.0.0.1 22` fails with `EACCES` because loopback is an internal range.

## Policy

Per-label policy lives in `/Capabilities/System/Network.cap/Units/bsdnetwork.unit/Config/bsdnetwork.conf` (UCL), read once at startup through the switchboard-delivered Config descriptor (`service_config_open(3)`), before any client is served. `default {}` applies to any label without a `clients {}` entry; a `clients {}` entry names only the dimensions it overrides and inherits the rest.

| Key | Meaning | Shipped default |
|---|---|---|
| `resolve` | RESOLVE permitted | `true` |
| `connect` | TCP CONNECT permitted | `true` |
| `udp` | connected UDP permitted | `true` |
| `inet4` / `inet6` | address families permitted | `true` / `true` |
| `internal` | loopback, link-local, RFC 1918 and ULA destinations permitted | `false` |
| `listen` | LISTEN permitted | not set; compiled default `false` |

`internal = false` is the SSRF guard: a non-admin session cannot be steered at a loopback, link-local or private address, including a name that resolves there, because `networkcmp_policy_family_permitted()` and the internal-range check run per result and per endpoint. A label whose policy permits no operation at all is refused a session with `EACCES`.

```ucl
clients {
	"org.example.render"  { connect = false; udp = false; }
	"org.example.metrics" { internal = true; }
	"org.example.rpc"     { listen = true; }
}
```

The entry schema is closed (an unknown key, a non-boolean, a duplicate or invalid label makes the file malformed), but the file-level direction is fail-soft: a missing or malformed file leaves the compiled-in default in force and logs a warning, so a bad edit cannot take the network provider down. A session whose channel carries `SERVICE_RIGHTS_ADMIN` (the bit switchboard stamps only onto an ambient root login session) bypasses the table and receives the full policy including internal reach; the applied source (`admin`, `label` or `default`) is logged and audited at session start.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDNetwork/tests` (package `bsdnetwork-tests`, `/usr/tests/usr.sbin/BSDNetwork`) | `provider_test` (16 cases), `config_test` (12), `policy_test` (7), `bundle_test.sh` (3) | provider_test drives the real request handler over a mac_capability channel: HELLO, CONNECT and UDP return a narrowed fd, denied labels get `EACCES`, loopback is refused to non-admin sessions, per-label config denies connect while allowing resolve, connect timeouts succeed/refuse/expire, the resolver does not block the session and its deadline terminates the worker, malformed channel traffic is rejected. config_test and policy_test cover the parser's closed schema and fail-soft behaviour. |
| `lib/libnetworkcmp/tests` (`libnetworkcmp-tests`) | `networkcmp_test` (8), `client_lifecycle_test` (5, against a fake service) | message encoding, HELLO contract, borrow/release lifecycle, terminal `EPROTO` after a malformed reply |
| `usr.sbin/networkcmpctl/tests` | `networkcmpctl_test.sh` (5) | argument handling, provider-unavailable exit, successful verbs against a fake broker, failure cleanup |

Run with `kyua test -k /usr/tests/usr.sbin/BSDNetwork/Kyuafile` on a booted plane; provider_test needs mac_capability channels and so runs inside the VM rig described in [Testing](../develop/testing.md). The `udp` and `listen` self-tests of networkcmpctl are the live proof that a born-in-capmode broker reaches the kernel connect and bind paths.

## Status and gaps

Status: shipped, committed on `dev`, VM-proven; the inventory (section 4 and section 10) records it as capmode, user `capability`, Casper retired, ops HELLO/CONNECT/LISTEN/UDP/RESOLVE.

Known gaps and drift:

- BSDNetwork(8) still says version 1 exposes only DNS, connect and udp and that listener authority is not in the client API; the header, library, ctl tool and man page libnetworkcmp(3) all ship LISTEN. The daemon page is stale on this point.
- `bundle_test.sh` refers to the pre-rename source directory `usr.sbin/bsdnetwork` and binary name, so it skips or fails outside the source tree layout it was written for.
- A timeout op for resolve (as opposed to the fixed 30 second deadline) is deferred, per the inventory.
- `AI_ADDRCONFIG` is a no-op: the resolver never suppresses a family based on the host's configured addresses.
- The `listen` policy key is not in the shipped `bsdnetwork.conf`; operators must add it explicitly per label.

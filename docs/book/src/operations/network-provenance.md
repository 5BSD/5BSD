# Network Stack Provenance

5BSD's packet filter and network stack are a hybrid. The packet filter is
OpenBSD's; the network stack under it is FreeBSD's; a 5BSD layer joins the
two, keeps the FreeBSD pf features that OpenBSD lacks, and changes the
FreeBSD stack and tools where 5BSD follows OpenBSD. This chapter records
which part comes from where, which differences are deliberate, and how to
bring each side forward. Keep it current: every change that moves code
between these columns, or adds a deliberate difference, updates this page.

The per-file detail lives next to the code:

- `contrib/openbsd-pf/README.5BSD`: the OpenBSD import (revision, contents)
  and every 5BSD edit to the vendor files, grouped by marker.
- `contrib/openbsd-pf/UPSTREAM.json`: the OpenBSD snapshot identity and the
  git tree ID of every imported subtree.
- `tests/sys/netpfil/pf/README.5BSD`: what happened to each FreeBSD pf test.
- `tests/sys/netpfil/integration/README`: the 5BSD seam tests (VNET
  /dev/pf, host-owned limits, capability plane, cloners, jail option,
  rdomains, sockets, securelevel, consumers, DTrace, bridge).

## Where each part comes from

| Part | Origin | Location |
|---|---|---|
| pf kernel: pf.c, pf_ioctl.c, pf_norm.c, pf_table.c, pf_lb.c, pf_if.c, pf_ruleset.c, pf_osfp.c, pf_syncookies.c, radix, pflog, pflow, pfsync | OpenBSD | `contrib/openbsd-pf/sys/net` |
| pfctl, authpf, ftp-proxy, tftp-proxy, pflogd, tcpdump | OpenBSD | `contrib/openbsd-pf/{sbin,usr.sbin}`; pflogd glue in `sbin/pflogd/pflogd_5bsd.[ch]` (libpcap activation, 32-bit savefile header, `-p` pidfile) |
| pf(4), pflog(4), pflow(4), pfsync(4), divert(4), pf.conf(5), pf.os(5), pfctl(8) | OpenBSD, with marked 5BSD sections | `contrib/openbsd-pf/share/man`, `contrib/openbsd-pf/sbin/pfctl` |
| OpenBSD regress suites | OpenBSD, verbatim | `contrib/openbsd-pf/regress` |
| Compatibility layer, pfil(9) hooks, VNET, ioctl dispatch, DTrace provider | 5BSD | `sys/netpfil/openbsd-pf` |
| Userland compatibility for the OpenBSD tools | 5BSD | `sys/netpfil/openbsd-pf/user` |
| IPv4, IPv6, TCP, UDP, SCTP protocol stacks | FreeBSD | `sys/netinet`, `sys/netinet6` |
| Routing (FIBs, nexthops), route(4) sockets, netlink | FreeBSD | `sys/net`, `sys/net/route`, `sys/netlink` |
| ifnet, if_clone, pfil(9), VNET, loopback, epair, bridge, carp, vlan | FreeBSD, with 5BSD changes listed below | `sys/net`, `sys/netinet` |
| dummynet(4) and dnctl(8) | FreeBSD | `sys/netpfil/dummynet`, `sbin/dnctl` |
| ifconfig, route, ping, netstat, vmstat | FreeBSD, with OpenBSD behaviour added | `sbin`, `usr.bin` |
| FreeBSD pf, libpfctl, pf netlink, pflowctl, IPFW, IPFilter, ipdivert(4), ALTQ | FreeBSD, retired | none (see `ObsoleteFiles.inc`) |

The OpenBSD import is pinned to the revision in `README.5BSD` (OpenBSD
8.0-current as of 2026-10-10). The FreeBSD side follows `dev`'s upstream
sync with `freebsd/main`.

## How the two are joined

The OpenBSD sources are compiled almost unchanged.
`sys/netpfil/openbsd-pf/openbsd_compat.h` is force-included into every
vendor file and maps OpenBSD's kernel interfaces (mutexes, rwlocks, SMR,
pools, timeouts, tasks, mbuf and interface helpers) onto FreeBSD's.
`pf_freebsd.c` attaches pf to pfil(9) per VNET and dispatches the
`/dev/pf` ioctls. Where the layer cannot express a difference, the vendor
file has a one-line edit with a marker comment:

| Marker | Meaning |
|---|---|
| `5BSD: m_tag` | OpenBSD's per-packet `struct pkthdr_pf` lives in an mbuf tag (`PACKET_TAG_PF`), so `MSIZE` stays 256 |
| `5BSD: VNET` | OpenBSD globals made per-VNET |
| `5BSD: DTrace` | SDT probe sites (dtrace_pf(4)) |
| `5BSD: jail` | the 5BSD `jail` rule option |
| `5BSD: dummynet` | `dnpipe`/`dnqueue` (FreeBSD pf feature) |
| `5BSD: sctp` | SCTP tracking, multihoming, `allow-related` (FreeBSD pf feature) |
| `5BSD: ether` | layer-2 `ether` rules (FreeBSD pf feature) |
| `5BSD: rename` | FreeBSD interfaces can be renamed; `pfi_rename_ifnet()` moves the interface to the kif of its new name (glue listens to `ifnet_rename_event`) |
| `5BSD: names` | FreeBSD can give two interfaces one name (a VNET jail's interface returning next to a renamed one); they share the kif of the name, as in FreeBSD pf, counted in `pfik_nifp` |
| `5BSD` | other small adaptations, listed in `README.5BSD` |

`grep -rn '5BSD' contrib/openbsd-pf/sys contrib/openbsd-pf/sbin` lists every
vendor edit. Keep each one minimal and marked; the logic of an extension
goes in its own file in `sys/netpfil/openbsd-pf` (`pf_dummynet.c`,
`pf_sctp.c`, `pf_ether.c`, `pf_jail.c`, `pf_divert.c`).

## 5BSD extensions to OpenBSD PF

| Feature | From | Notes |
|---|---|---|
| `jail <name\|jid>` rule option | 5BSD | matches the jail of the local socket; re-resolved on jail events |
| `dnpipe`, `dnqueue` | FreeBSD pf | dummynet(4) shaping, also on route-to; dummynet is loaded through the SystemExtension broker |
| `ether` rules | FreeBSD pf | separate layer-2 ruleset on the link-layer pfil hooks; `pfctl -s ethernet`, `-F ethernet`; ioctls `DIOC*ETHRULE*` |
| SCTP, multihoming, `allow-related`, `sctp.*` timeouts | FreeBSD pf | association tracking with verification tags; extra states for INIT/ASCONF addresses |
| Per-VNET pf | 5BSD | each VNET jail has its own rules, states, tables and interfaces; jails without their own VNET cannot open `/dev/pf`; pool limits are host-owned |
| `DIOCBINDJAIL` | 5BSD | moves an unused `/dev/pf` descriptor to a descendant jail's VNET; BSDNetwork uses it so system.Network.PF serves the caller's own states |
| pfsync IPv6 peers (`5BSD: pfsync6`) | FreeBSD feature, 5BSD code | IPv6 unicast or ff12::f0 peers; messages unchanged, IPv6 header with hop limit 255; `SIOC[GS]ETPFSYNC6` |
| pfsync CARP demotion (`5BSD: carp`) | OpenBSD design on FreeBSD carp | OpenBSD's carp-group counts drive `net.inet.carp.demotion` through `net.pfsync.carp_demotion_factor`; glue `pf_pfsync.c` |
| divert-to, divert-reply, divert-packet | OpenBSD semantics on FreeBSD sockets | `SO_BINDANY`, `IP_RECVDSTPORT`; OpenBSD divert(4) sockets are the only divert interface (ipdivert(4) retired) |
| FreeBSD DTrace contracts | dev (FreeBSD pf era) | limiter, table, syncookie and pfsync probes kept with the same names |

## FreeBSD stack changed to follow OpenBSD

| Change | Where |
|---|---|
| Routing domains (`rdomain`, `rtable`) built on FIBs; `SO_RTABLE` | `sys/net`, `sbin/ifconfig`, `sbin/route` (see [Routing Domains](rdomains.md)) |
| Loopback MTU 32768 and LRO/TSO on lo(4) | `sys/net/if_loop.c` |
| vether(4) | `sys/net` |
| "egress" interface group from the default routes of FIB 0, per VNET | `sys/net/if_egress.c` |
| ifconfig status in OpenBSD's format; `nd6 options` only with `-v` | `sbin/ifconfig` |
| SIOCSIFADDR/SIOCSIFNETMASK/SIOCSIFBRDADDR with OpenBSD semantics; contiguous netmasks; point-to-point address without a peer (no EDESTADDRREQ) | `sys/netinet/in.c` |
| First IPv6 address on an IPv6-disabled interface is tentative and gets DAD; inet6 point-to-point addresses may share a destination | `sys/netinet6/in6.c` |
| ifconfig: `prefixlen` for inet, `netmask` for inet6, non-contiguous masks rejected, no derived /31–/32 broadcast shown, `--> 0.0.0.0`/`--> ::` for an unset peer, inet6 peer implies /128, `eui64` attaches IPv6 | `sbin/ifconfig/af_inet.c`, `sbin/ifconfig/af_inet6.c`, `sbin/ifconfig/ifconfig.c` |
| ifconfig: a mask-less IPv4 address gets the classful default; a point-to-point address may omit the peer | `sbin/ifconfig/af_inet.c`, `sys/netlink/route/iface.c` |
| pflow and pfsync configured with ifconfig (pflowctl retired) | `sbin/ifconfig` |
| ping/ping6 `-w` and `-V`; `vmstat -m -v` pool listing; `route -T` | `sbin`, `usr.bin` |
| Larger interface unit numbers (`IF_MAXUNIT`) | `sys/net/if_clone.c` |
| A packet reused as a reply drops pf's state key, as OpenBSD's `m_resethdr()` does: ICMP reflection and TCP resets (`tcp_respond()`) | `sys/netinet/ip_icmp.c`, `sys/netinet6/icmp6.c`, `sys/netinet/tcp_subr.c` (`M_PF_UNLINK`) |
| tcpdump is OpenBSD's (OpenBSD pflog output) | `contrib/openbsd-pf/usr.sbin/tcpdump` |

## Deliberate differences from OpenBSD

These are recorded decisions; do not "fix" them to pass a test without a
new decision. The matching OpenBSD regress cases are expected to fail.

| Difference | Reason | Affected regress |
|---|---|---|
| FreeBSD TCP stack: RFC 5961 ghost-ACK check | security hardening kept | pf_state `negack_fin` |
| FreeBSD TCP SYN option layout (4 bytes tighter than OpenBSD's padding) | stack kept | pflow `flow_10_4`, `flow_10_6` |
| IPv4 link-local is never forwarded (RFC 3927 §2.7) | standards compliance | pflog `run-ping-14`, `run-ping6-14` |
| FreeBSD routing table, not OpenBSD's ART | OpenBSD routing project dropped | `sbin/route`, `sys/net/rtable` not in the gate |
| Queueing (HFSC, FQ-CoDel): rulesets with `queue` are refused | deferred to a later series | none |
| One global PF lock for rule evaluation (FreeBSD pf evaluated in parallel) | OpenBSD design kept for now; SMP work deferred | none |
| `set limit` belongs to the host; VNET jails cannot change shared pools | pools are host-wide | 5BSD `limits` tests |
| SCTP verification tags travel in pfsync's `pfss_ts_mod`; OpenBSD peers reject SCTP states | OpenBSD pfsync has no SCTP | none |
| egress is also rebuilt when a default route is deleted (OpenBSD rebuilds only on add, change and link state) | membership follows the routing table | none |
| pf locks at securelevel 2 as on OpenBSD; dummynet (dnctl) at 3 | user decision | none |
| 18 pfctl cases (pfr1–6, pfr8–15, pfsetup1, pfchksum1–3) | they fail on the OpenBSD reference too (stale upstream .ok files) | pfctl; expected failures in `sbin/pfctl/tests` |

5BSD also fixes OpenBSD PF where its code contradicts its own manual; these
are vendor edits to re-check on every import:

| Fix | Upstream behaviour |
|---|---|
| `source-track global` limit nodes are shared by all rules using it, as pf.conf(5) and FreeBSD pf say | OpenBSD keys every source node by rule, so the limit is per rule |

## Number allocation

5BSD additions take values that upstream will not reuse, so later merges
cannot collide:

- Socket options: 5BSD-only `SO_*` flags use the top bits (`SO_BINDANY`
  0x20000000, `SO_RXQ_OVFL` 0x40000000).
- pf rule flags: `PFRULE_ALLOW_RELATED` 0x40000000; SCTP timeouts are
  appended before `PFTM_MAX`.
- pf ioctls: `DIOCADDETHRULE` through `DIOCGETETHRULESET` are `'D'` 230–234;
  `DIOCBINDJAIL` is `'D'` 235.
- pfsync: `SIOCSETPFSYNC6`/`SIOCGETPFSYNC6` are `'i'` 242/243.
- Address family 44 (formerly AF_DIVERT, now removed) is reserved and not reused.
- Address families from 64, `NET_RT_TABLE` 1024, and the other ranges
  recorded in the FreeBSD sync notes.

## Bringing changes forward

**OpenBSD PF.** Re-import `contrib/openbsd-pf` at the new revision and
update `README.5BSD` and `UPSTREAM.json`. Reapply the marked edits
(`grep -rn '5BSD' contrib/openbsd-pf` on the old tree is the list); an
upstream change next to a marker needs a look at the matching glue.
Regress files stay verbatim. Then run the full gate: the OpenBSD regress
runner (`tools/test/pf-parity/openbsd-regress/regress.py`), the ATF suites
in `tests/sys/netpfil`, pfsync interoperability with an OpenBSD peer, and
the DTrace profiles.

**FreeBSD.** The protocol stacks, routing, netlink, ifnet, pfil, VNET and
dummynet merge from `freebsd/main` as usual. FreeBSD pf, libpfctl and pf
netlink are retired: upstream changes there are not merged, but a FreeBSD
pf change to dummynet, ether-rule or SCTP behaviour is a candidate for the
matching 5BSD extension (they derive from FreeBSD pf as of `dev`'s sync
with `freebsd/main` c2b7fe4a9e9). Files where both sides carry changes and
merges need care: `sys/sys/socket.h` and `socketvar.h`,
`sys/net/if_clone.c`, `sys/net/if_loop.c`, `sys/netlink/route/iface.c`,
`sbin/ifconfig/af_inet.c` and `af_nd6.c`, `sys/netinet/ip_input.c`
(forwarding policy), and `sys/netpfil/dummynet/ip_dn_io.c`, whose only
client is now pf.

After a merge on either side, check for things both sides added (the same
definition twice) and for 5BSD numbers that upstream has started to use.

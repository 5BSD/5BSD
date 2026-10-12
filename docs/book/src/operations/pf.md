# Packet Filter (pf)

5BSD's packet filter is OpenBSD's pf. The kernel code in `pf.ko`, `pfctl(8)`,
`authpf(8)`, `ftp-proxy(8)` and `tftp-proxy(8)` are OpenBSD's sources from
`contrib/openbsd-pf`, built through a compatibility layer in
`sys/netpfil/openbsd-pf`. The rule language, `pfctl` options and output, the
`/dev/pf` ioctls, pflog, pfsync and pflow are OpenBSD's; OpenBSD's pf.conf(5),
pfctl(8) and the PF User's Guide apply as written. This chapter covers what
is specific to 5BSD: one pf per vnet, transparent proxying on the 5BSD
network stack, and the 5BSD `jail` rule option. Observability (the `pf`
DTrace provider and its scripts) is in [Observability](observability.md).

Parity is measured with OpenBSD's own regression suites
(`contrib/openbsd-pf/regress`), run against a 5BSD guest by
`tools/test/pf-parity/openbsd-regress` and installed as the
`sys/netpfil/pf/openbsd` Kyua tests.

## One pf per vnet

Every vnet runs its own pf instance: rulesets and anchors, states and source
nodes, tables, state and source limiters, queues, the interface table,
fragment reassembly, status counters, syncookie state, and the pflog, pfsync
and pflow interfaces. A vnet jail therefore has a private firewall:

```sh
jail -c name=web vnet persist vnet.interface=epair0b
printf 'block in proto tcp\npass in proto tcp to port 80\n' |
    jexec web pfctl -f -
jexec web pfctl -e
jexec web pfctl -sr     # the jail's rules only
pfctl -sr               # the host's rules only
```

`/dev/pf` acts on the vnet of the process that opened it; the open keeps a
reference to the opener's jail, so a descriptor passed elsewhere still
addresses the same pf. The device is visible in a jail through the
`devfsrules_jail_vnet` devfs ruleset. A new vnet starts with pf disabled and
an empty ruleset.

Three things stay system wide. Memory pools are shared, so the limits set
with `set limit` belong to the host: a vnet jail may restate the current
values (pfctl loads every limit with a ruleset) but changing one fails with
`EPERM`. Tag names (`tag`/`tagged`) share one name space. The pf locks are
shared, so a large ruleset reload in one vnet briefly delays packet
processing in the others.

When a vnet goes away, its pf is torn down: the pflog, pfsync and pflow
interfaces are destroyed, rules, anchors, tables, states, source nodes and
queued fragments are freed and its timers stopped. A jail that is removed
while connections are in TIME_WAIT lingers as a dying jail until they
expire, and its pf is freed then.

## Transparent proxying

The OpenBSD rule options `divert-to`, `divert-reply` and `divert-packet`
behave as on OpenBSD:

- `divert-to address port port` delivers a TCP or UDP connection, whatever
  its destination, to a local socket bound to the divert address and port.
  The socket sees the original destination: `getsockname(2)` on the accepted
  TCP socket, or the `IP_RECVDSTADDR` and `IP_RECVDSTPORT` control messages
  (IPv6: `IPV6_PKTINFO` and `IPV6_RECVDSTPORT`) for UDP. Raw IP and ICMP
  sockets bound to the divert address receive diverted packets of their
  protocol; the stack does not answer a diverted ICMP echo itself.
- `divert-reply` delivers replies to sockets bound, with `SO_BINDANY`, to
  addresses that are not local, so a proxy can connect on behalf of its
  client using the client's address.
- `divert-packet port n` hands the packet to a divert(4) socket,
  `socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT)` (or `AF_INET6`) bound to port
  `n`. Writing a packet back with an unspecified destination address sends
  it out; with a local address it is received on the interface that has the
  address. Checksums are recomputed. This is OpenBSD's divert(4); the
  ipdivert(4) `PF_DIVERT` sockets of ipfw are unrelated.

A transparent HTTP proxy on the router:

```
pass in on $int_if inet proto tcp to port 80 divert-to 127.0.0.1 port 8080
pass in on $int_if inet6 proto tcp to port 80 divert-to ::1 port 8080
```

The proxy listens on `127.0.0.1:8080` and `[::1]:8080`; for each connection
`getsockname(2)` returns the address and port the client asked for.
`SO_BINDANY` is the socket-level form of `IP_BINDANY`/`IPV6_BINDANY`
and needs the same privilege. Its value differs from OpenBSD's, so
programs must use the symbolic name.

## Matching the jail of a socket (5BSD extension)

`jail` matches the jail of the local socket of a TCP or UDP packet, the way
`user` and `group` match its owner. It takes a jail name or jail id (`0` is
the host), a list, a range or a unary operator:

```
block out proto tcp to port 25 jail { web0 web1 }
pass in proto tcp to port 443 jail web0
block in proto udp jail != 0
pass out proto tcp jail 12
```

Because the decision is taken from the socket, `jail` separates jails that
share the host's addresses (`ip4=inherit`), which address rules cannot.
Packets that are only forwarded have no local socket and never match a
`jail` rule other than `jail != ...`. `pfctl` resolves names when the
ruleset is loaded, as `user` does; the rule keeps the jail id, so removing
the jail leaves a rule that no longer matches anything (and `pfctl -sr`
prints the number), and loading a ruleset that names a missing jail fails.
A name such as `outer.inner` addresses a nested jail; a rule for a jail does
not match its child jails. The `pf:rule:jail:match` DTrace probe fires with
the rule and the jail id each time the option matches.

`jail` is not part of OpenBSD's pf.conf; rulesets that use it do not load
on OpenBSD.

## Status

| Area | State |
|---|---|
| OpenBSD regress: pfctl, pf_table, pf_policy, pf_forward, pf_fragment | Run on 5BSD; remaining differences tracked in the parity report |
| Per-vnet pf | Done; `vnet_test` (isolation, limits, clones, teardown with live state, nested vnet jails) |
| divert-to, divert-reply, divert-packet | Done; `divert_test` and OpenBSD `pf_divert` |
| `jail` option | Done; `jail_test` |
| Routing domains (`rdomain`, `rtable`) | Planned: on FIBs |
| Queues (HFSC, FQ-CoDel) | Planned |

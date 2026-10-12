# Routing Domains

A routing domain is an isolated set of routing tables and interfaces, as on
OpenBSD (rdomain(4)). An interface belongs to exactly one routing domain, a
domain can hold several routing tables, and the same addresses can be used
in several domains at once: a host can serve two customer networks that both
use `10.0.0.0/24`, or keep a management network apart from the data plane,
without jails.

5BSD builds routing domains on FreeBSD FIBs. A routing table is a FIB; routing
domain N is FIB N made a domain of its own. FIBs created the FreeBSD way
(`net.fibs`, setfib(1)) are routing tables of domain 0, so FIB behaviour does
not change until the first routing domain is created. Routing domains are per
vnet: a vnet jail has its own. VNET jails isolate a whole network stack;
routing domains isolate addressing and routing inside one stack, and pf sees
all of them at once.

## Creating a domain

Moving an interface into a domain creates the domain, its routing table and
its loopback interface `lo<N>`:

```sh
ifconfig vether0 rdomain 3          # creates rdomain 3 and lo3
ifconfig vether0 10.0.0.1/24 up
ifconfig vether0
# vether0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> rdomain 3 ...
route -T 3 -n show
```

A cloneable interface that does not exist yet is created by configuring it,
as on OpenBSD: `ifconfig lo11 rdomain 11` creates `lo11`. The loopback of a
domain cannot be destroyed or moved. Moving an interface to another domain
(`rdomain N`, `-rdomain`, or `fib N` with a FIB of another domain) removes its
addresses and routes, since they belonged to the old domain. A routing table
that already has routes cannot become a domain.

vether(4), a virtual Ethernet interface without hardware, gives a domain an
Ethernet address without a port.

## What a domain isolates

- Packets received on an interface use its domain's routing table.
- An address is local only in its own domain. A packet for `10.0.0.1` that
  arrives in another domain is routed (or dropped) there, and a socket can
  only bind to addresses of its domain.
- Sockets receive only packets of their domain: two domains can both listen
  on `127.0.0.1:53`.
- Local traffic is looped through the domain's loopback interface `lo<N>`, so
  pf rules `on lo<N>` see it.

## Running programs in a domain

A process's routing table is its FIB:

```sh
route -T 3 exec sshd -D        # OpenBSD style
setfib 3 sshd -D               # FreeBSD style, same effect
ping -V 3 10.0.0.2             # ping on table 3
```

Sockets can select a table with `SO_SETFIB` (OpenBSD programs use the name
`SO_RTABLE`). Changing tables inside a domain is unprivileged, as setfib(2)
always was; entering a table of another domain needs root, as setrtable(2)
does on OpenBSD.

`route -T N add` creates routing table N when it is missing, as a table of
domain 0. `route -T N show` prints the table in OpenBSD's layout
(Destination, Gateway, Flags, Refs, Use, Mtu, Prio, Iface), with local
addresses flagged `l` on the interface that owns them.

## pf

pf works per routing domain: `on rdomain N` matches packets of domain N,
`rtable N` moves matching packets to table N (and so to its domain), and the
state table keeps states of different domains apart even when their
addresses are equal. `pfctl -V N -k ...` kills states of one domain.

```
pass in on rdomain 3 proto tcp to port 22
pass in on vether1 rtable 0          # route these into domain 0
```

## Interfaces for programs

| Interface | Meaning |
| --- | --- |
| `SIOCSIFRDOMAIN`, `SIOCGIFRDOMAIN` | set and get an interface's routing domain (`ifr_rdomainid`) |
| `net.route.0.0.1024.N` (`NET_RT_TABLE`) | `struct rt_tableinfo`: table N and its domain; `ENOENT` if N does not exist |
| `net.fibs` | number of routing tables; grows when a domain or table is created |

## Parity

The routing domain series is measured with OpenBSD's `regress/sys/net/rdomains`
suite and the pf suites that use domains (`pf_opts`, `pflog`), and with the
`sys/net/rdomain_test` Kyua tests. OpenBSD's `regress/sbin/route` suite also
checks route priorities, multipath and reference counts of OpenBSD's ART
routing table, which 5BSD's FIB routing table does not have.

# Handoff: PF consumers (branch pf/consumers)

Worktree `/usr/obj/5BSD-pf-consumers`, rebased on pf/parity `0328c32095a`.
Objdir `MAKEOBJDIRPREFIX=/usr/obj/usr/obj/5BSD-pf-consumers-objs`; logs in
`/usr/obj/5BSD-pf-consumers-logs/`.  No push, install or publication.

## Commits (oldest first)

| Commit | State |
|---|---|
| pf: Export pfsync and pflow statistics as sysctls (`net.pfsync.stats`, `net.pflow.stats`, glue `pf_sysctl.c`) | done, built |
| pf: OpenBSD `<net/pfvar.h>` for userland; retire FreeBSD pf, libpfctl, pflowctl (header switch; `device pf` builds OpenBSD PF; consumers snmp_pf, BSDNetwork/BSDFilesystem, netstat, libsysdecode, rescue, validation.c; ObsoleteFiles/mtree/UPDATING) | done, built |
| pflogd: Default snaplen of 160, as OpenBSD | done (pflogd.8 not updated, see below) |
| ifconfig: OpenBSD output format, -inet6; update the parsers (+ ATF test `sbin/ifconfig/tests/openbsd.sh`) | done, built, not VM-tested |
| tcpdump: OpenBSD tcpdump is the base tcpdump | done, built, not VM-tested |
| pf parity: Stage the OpenBSD tree on 5BSD DUTs; build pf-changerule (`stage-src-5bsd.sh`, `regress.py`) | done, not run |
| book: Tools around pf | done |
| conf: Build the pf jail glue (pf_jail.c) with "device pf" | done (fixes pf/parity) |
| share/doc/5bsd: Install the pf and rdomains book chapters | done (fixes pf/parity buildworld) |
| WIP: tests/sys/netpfil/pf: adapt FreeBSD pf tests to OpenBSD PF | unverified |
| this handoff | |

## Builds

- buildworld: BUILD_EXIT 0 on the base before the last rebase (bw8.log).
- GENERIC: built (bk1.log).
- LINT: failed on the old base: `MSIZE=256` static assert (fixed on
  pf/parity by febcf1f0ed7) and `-Werror` in vendor `if_pflow.c` (fixed:
  `OPENBSD_PF_C` in kern.pre.mk no longer adds `-Werror`).
- A rebuild on the rebased tree (bw9.log) was stopped in stage 4.2 for this
  handoff.  Next: `make -j6 -DNO_CLEAN buildworld`, then
  `make -j6 buildkernel KERNCONF="GENERIC LINT"` (generate LINT with
  `make -C sys/amd64/conf LINT`).

## VM work not done

No VM run of this branch has happened.

1. Image: `JOBS=4 sh tools/test/pf-parity/openbsd-regress/image-5bsd.sh
   /usr/obj/5BSD-pf-consumers /usr/obj/usr/obj/5BSD-pf-consumers-objs
   /usr/obj/5BSD-pf-parity/consumers/imgN /usr/obj/5BSD-pf-parity/xfer/fbsdpkg/flat`
   (img1 there predates the rebase).
2. Boot as dut2, 2 vCPUs: `python3.12 tools/test/pf-parity/openbsd-regress/vm.py
   start --cpus 2 dut2 5bsd <disk>`; ssh with
   `/usr/obj/5BSD-pf-parity/consumers/ssh_config` (private known_hosts).
   Run `setup-dut-5bsd.sh` on it, then
   `stage-src-5bsd.sh /usr/obj/5BSD-pf-consumers dut2`.
3. `regress.py 5bsd OUT --dut dut2 --suite pfctl` (expect pf-changerule to
   pass), `--suite pflog --suite pf_opts` (OpenBSD tcpdump output).
4. ATF: `sbin/ifconfig/tests/openbsd` (format, "no such interface",
   pflow lines; auto-create comes from pf/rdomains).
5. `tests/sys/netpfil/pf/ioctl/validation`: compiles against the OpenBSD
   ABI; its "size -1 must fail" expectations are FreeBSD semantics (OpenBSD
   treats some as no-op success).  Run, then set expectations from
   OpenBSD's pf_ioctl.c/pf_table.c behaviour.
6. `usr.sbin/traceroute/tests`: its tcpdump patterns are tcpdump.org
   format ("IP (tos 0x0, ttl 1, ...)"); rewrite from real OpenBSD tcpdump
   output.
7. snmp.sh (snmp_pf), netstat -s -p pfsync|pflow, blocklistd-helper (no
   change made; uses pfctl commands OpenBSD pfctl shares) need a run.

Host note: at load ~34 a 2-vCPU TCG guest stopped answering ssh; run the
VM when the host is quieter.

## tests/sys/netpfil/pf disposition so far

See `tests/sys/netpfil/pf/README.5BSD` (retired list with reasons, adapted
files, not-yet-reviewed files).  Retired: altq.sh, ridentifier.sh,
fragmentation_compat.sh, scrub_compat.sh, max_pkt_size.sh and FreeBSD-only
cases (keepcounters, nat-anchor, endpoint-independent, MAP-E, binat/rdr
compat, prefer-ipv6-nexthop, pfsync 13.1/14.0 versions, ALTQ queue ids,
pflowctl limits/observation domain).  Converted mechanically, unverified:
nat/rdr/binat/scrub/route-to syntax, pflog expectations, pflow via
ifconfig, debug levels.  Kept 5BSD extension tests (ether, dummynet, SCTP
multihome) will fail until those extensions are ported to OpenBSD PF.

## Blocked by the permission classifier

The user approved these; they need a Bash permission rule before they can
be done:
- Kernel ALTQ retirement: `git rm` of `sys/net/altq/*` except `if_altq.h`,
  of `sys/netpfil/pf/{pf.h,pf_altq.h,pf_mtag.h}`, and the edits removing
  `net/altq/altq_*.c` from `sys/conf/files`, `ALTQ*` from
  `sys/conf/options` and the ALTQ block from `sys/conf/NOTES`; plus
  ObsoleteFiles/UPDATING lines.  The tree currently keeps ALTQ (builds).
- `git rm -r contrib/pf/{authpf,ftp-proxy,tftp-proxy}` (stale FreeBSD
  copies, not built).
- `contrib/pf/pflogd/pflogd.8`: default snaplen 116 -> 160 (two places).

## Other notes

- rdomains `lo.ok` expects `flags=2008049<UP,LOOPBACK,RUNNING,MULTICAST,LRO>`.
  ifconfig shows LRO only when IFCAP_LRO is enabled; 5BSD's loopback does
  not set it, so that needs a kernel change (loopback MTU 32768 is routed
  separately).
- ifconfig's auto-create is the rdomain helper's (363cb0758e2).
- Ports: `/usr/obj/5BSD-pf-consumers-logs/ports-notes.txt` (ifconfig
  "lladdr" and format, tcpdump, pfvar.h users); no ports changes made.

## How to resume

1. `cd /usr/obj/5BSD-pf-consumers && git rebase pf/parity`.
2. Rebuild world, GENERIC and LINT (above); fix fallout.
3. Build an image, run the VM work list above; commit test fixes.
4. Finish the netpfil disposition (review the remaining files, run them),
   then turn the WIP commit into normal commits with the final table.
5. If the permission rule is added, commit the ALTQ retirement and the
   contrib/pf and pflogd.8 changes.

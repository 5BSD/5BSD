# PF parity handoff (pf/parity, 2026-10-12)

Goal: OpenBSD PF on 5BSD at 100% parity, measured by OpenBSD's own regress
suites (contrib/openbsd-pf/regress), then land pf/parity on dev.

Ground rules (from AGENTS.md and the coordinator):

- Do not publish packages, install on the host or push.
- Never use /usr/src or /usr/obj/usr/src, and never merge into dev
  yourself.
- Tests run only in QEMU VMs (2 vCPU, -j6 builds; four agents share the
  host).
- Change only harness plumbing. Never change expected outputs without a
  user decision.
- Vendor edits under contrib/openbsd-pf stay minimal and marked "5BSD".
  Record them in contrib/openbsd-pf/README.5BSD.

## Current state

The pf/parity tip contains the following:

- OpenBSD pf.ko, pfctl, authpf and ftp-proxy are built from
  contrib/openbsd-pf through sys/netpfil/openbsd-pf.
- One pf runs per vnet.
- divert-to, divert-reply and divert-packet work, plus divert(4),
  SO_BINDANY and IP/IPV6_RECVDSTPORT.
- The 5BSD `jail` rule option keeps the jail name and re-resolves it on
  jail create, rename and remove (DTrace probe pf:rule:jail:resolve).
- pfsync interoperates with OpenBSD.
- lo MTU is 32768.
- Queue definitions are refused with EOPNOTSUPP.
- pf reroute reloops ip_output and ip6_output.
- The pf/rdomains merge is in (rdomain/rtable on FIBs).
- **MSIZE 256 with an m_tag** (febcf1f0ed7):
  - OpenBSD's struct pkthdr_pf lives in PACKET_TAG_PF.
  - The vendor sites use PF_MTAG_R/W and PF_PDTAG_R/W, each marked
    "5BSD: m_tag" (README.5BSD describes the convention).
  - The LOCAL ONLY MSIZE 512 commit is reverted.
- The pf ifnet_departure_event handler runs before netinet's (0328c32095a).
  This fixes a panic in in_leavegroup_locked when a pfsync syncdev is
  destroyed.

What has been verified on the m_tag kernel (WITNESS/INVARIANTS GENERIC,
DUT obsdpf-1):

- ATF tests:
  - vnet_test 5/5
  - divert_test 4/4
  - jail_test 8/8
  - authpf_test 2/2
  - ftpproxy_test 2/2
  - pfsync_test 2/2 (sync and failover)
- No LOR or WITNESS reports in dmesg.
- Leak check: `vmstat -m` shows the mbuf_tag type at InUse 1 after all the
  ATF tests (baseline 1).

Two binaries on the DUT were stale. They were redeployed:

- ftp-proxy was built before the jail struct change, so it got ENODEV.
- ping6 lacked -V.

A clean buildworld covers both.

What has NOT been verified on the m_tag kernel: the full OpenBSD regress run.
Run results/5bsd-mtag-1 failed on the local suites with "Could not find
bsd.regress.mk". The DUT lost /usr/local/share/pf-parity/mk (the harness
`make` include path) after the reset and reboot. Reinstall it with
`setup-dut-5bsd.sh` or image-update.sh and rerun. The multi-host part of that
run may still be going (pf_forward onward). Its output is under the same
directory.

## Regress counts (5BSD DUT)

The latest complete results are from before the m_tag change, on the MSIZE 512
kernel.

| Suite | Result | Remaining failures explained |
|---|---|---|
| pf_forward | 136/136 | |
| pf_fragment | 17/17 | |
| pf_divert | 70/70 | |
| pf_policy | 11/11 | |
| pf_table | 4/4 | |
| pf_state | 6/7 | negack_fin: TCP-stack difference (RFC 5961 ghost-ACK check); user decision: document, do not weaken the stack |
| pfctl | 411/430 | 18 stale upstream cases, plus pf-changerule (needs pf/consumers header switch) |
| pf_trans | 1/2 | needs pf/consumers header switch |
| pf_print | 0/1 | needs pf/consumers header switch |
| pflog | 32 pass, 23 fail, 2 xfail | ping6 -V cases fixed on the DUT since (rerun); the rest are tcpdump output greps (pf/consumers tcpdump) |
| pf_opts | 19/27 | run-ping6 (ping6 -V, now fixed); 7 run-bpf-* tcpdump output greps (pf/consumers) |
| pflow | not rerun | needed ifconfig auto-create, which came with the rdomains merge |
| sbin/route, sys/net/rtable | out of scope | routing subsystem, not PF; FreeBSD routing retained by user decision |
| pfsync interop (pfsync-interop.sh, with the OpenBSD helper) | 3/3 | |

Per-suite results are in /usr/obj/5BSD-pf-parity/results/5bsd-obsdpf-2 and
earlier runs. The runner writes results.json plus <suite>.out and
<suite>.regress.log.

## Branches

- **pf/rdomains** (Helper A) is merged at 627c527a471.
- **pf/consumers** (Helper B) is NOT merged. It contains:
  - the pfvar.h header switch;
  - libpfctl and consumer deletions;
  - ifconfig output and tcpdump;
  - kernel ALTQ retirement.

  Its commits b0bb372a99a..ec1a72b0dcb were rebased on 0328c32095a. Its
  build was in progress at handoff (GENERIC and LINT). Its notes are on
  that branch (5a2793ed18a).
- A trial rebase of pf/parity onto dev 4481bcfaecd succeeded cleanly in the
  scratch worktree /usr/obj/5BSD-pf-rebase (detached HEAD). That was before
  the m_tag commits, so redo it.

## Remaining landing-gate checklist

1. Fix the DUT harness mk path and rerun the full regress on the m_tag kernel
   (`regress.py 5bsd <out>`). Rerun pflog, pf_opts and pflow.
2. Measure the m_tag per-packet cost. The WIP commit adds a `pf` mode to
   msize-bench.sh. Write the A/B driver (nopf vs pf on one kernel), then run
   it on a quiet host.
3. Merge pf/consumers when the coordinator says it is ready. Rebuild userland
   and rerun pfctl, pf_trans, pf_print, pflog and pf_opts.
4. Rebase onto dev 4481bcfaecd, or the dev the coordinator names.
5. Clean builds of buildworld plus the GENERIC, GENERIC-NODEBUG and LINT
   kernels (-j6, MAKEOBJDIRPREFIX=/usr/obj/5BSD-pf-parity/obj).
6. Full regress again, with every remaining failure explained (the table
   above).
7. Run the vnet, divert, jail, pfsync, authpf and ftp-proxy ATF tests. Also
   run pfsync-interop.sh.
8. Check that WITNESS is clean and repeat the mbuf_tag leak check.
9. Run `dtrace -l -P pf` and compile the pf DTrace scripts against a
   buildkernel-built pf.ko. The standalone kbuild.sh pf.ko has no CTF, so
   struct pf_pdesc does not resolve there.
10. Update the docs/book/src/operations/pf.md status table. It still says
    rdomains and queues are "Planned". Change it to rdomains done, queues
    refused (follow-up), and add the parity counts.
11. Tell the coordinator that pf/parity is ready to land.

## User decisions

- **MSIZE:** keep 256 and store pkthdr_pf in an m_tag:
  - allocate the tag lazily with M_NOWAIT;
  - no allocation on pass-through;
  - one tag lookup per pf_test;
  - free/copy callbacks carry the references.

  Done.
- **Queues:** follow after landing. For now, refuse them with EOPNOTSUPP and
  document that. Done.
- **negack_fin:** document it as a TCP-stack difference (RFC 5961 ghost-ACK
  check) and do not weaken the stack.
- **route and rtable suites:** out of scope. The OpenBSD routing-table project
  was dropped, and FreeBSD routing is retained.
- **lo MTU:** 32768. Done.
- **jail option:** track names and re-resolve them on jail events, with a
  DTrace probe, tests and docs. Done.
- **Kernel ALTQ retirement:** approved by the user (pf/consumers), but blocked
  by the classifier. If the classifier still denies it, stop and report.
  Do not work around it.

## Run roots, VMs, scripts

- Worktree: /usr/obj/5BSD-pf-src (branch pf/parity).
- Objdir: MAKEOBJDIRPREFIX=/usr/obj/5BSD-pf-parity/obj.
- Run record: /usr/obj/5BSD-pf-parity/20261010 (handoff.txt, state.json,
  journal.jsonl).
- Results: /usr/obj/5BSD-pf-parity/results/<run>. Logs:
  /usr/obj/5BSD-pf-parity/logs.
- Scratch: /usr/obj/5BSD-pf-parity/wip. It holds the pre-conversion vendor
  file copies and the rdomains-edits patch found in this worktree.
  /usr/obj/5BSD-pf-parity/analysis holds reports. Neither is in git.
- VMs: /usr/obj/5BSD-pf-parity/vms.
  - DUT: dut-obsdpf-1.qcow2, ssh port 2241, serial dut-serial.sock.
  - OpenBSD helper: helper.qcow2, port 2242.
  - QEMU: /usr/obj/5bsd-qemu-fstt/qemu-system-x86_64-fstt-fixed through
    tools/test/pf-parity/openbsd-regress/vm.py.
  - ssh: `ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config dut|helper`.
- Builds:
  - pf module only (no CTF): /usr/obj/5BSD-pf-parity/kbuild.sh pf "-k all".
  - Userland in buildenv: /usr/obj/5BSD-pf-parity/ubuild.sh <dir>.
  - Kernel plus the modules the DUT loads:

    ```
    env MAKEOBJDIRPREFIX=/usr/obj/5BSD-pf-parity/obj make -j6 buildkernel \
        KERNCONF=GENERIC NO_KERNELCLEAN=yes \
        MODULES_OVERRIDE="linux linux64 linux_common linsysfs linprocfs mqueue \
        fdescfs pty hwt zfs opensolaris dtrace if_epair if_bridge bridgestp \
        if_vether pf"
    ```

    After a struct pkthdr or struct mbuf change, rebuild all of these.
- Harness (tools/test/pf-parity/openbsd-regress, see README there):
  - `push-files.sh kernel|pf|prog:OBJREL:DEST` deploys and reboots. It waits
    for kern.boottime to change, then reruns setup-dut-5bsd.sh.
  - `run-atf.sh <test.sh> [case]` runs the ATF tests.
  - `regress.py 5bsd <out> [--suite S] [--rerun-failures]` runs the regress
    suites.
  - `dut-reset.sh` resets a hung DUT.
  - `pfsync-interop.sh` runs the pfsync interop test.
  - `msize-bench.sh` and `msize-ab.sh` run the benchmarks.
  - Use a ddb backtrace over the serial socket with
    tools/test/pf-parity/console.py.
- Resume: read this file and the journal. Boot the DUT and helper with vm.py
  if they are down. Redeploy the kernel and modules from the objdir. Fix the
  mk path. Then continue at checklist item 1.

## Open issues

- The full regress has not been run on the m_tag kernel (harness mk path; see
  above).
- The m_tag per-packet cost has not been measured.
- pf/consumers is not merged. pfctl, pf_trans, pf_print and the tcpdump-grep
  failures in pflog and pf_opts depend on it.
- The standalone pf.ko has no CTF, so the DTrace checks need a
  buildkernel-built module.
- In the m_tag fallback, a tag write that fails M_NOWAIT goes to a shared
  scratch struct and is counted (pf_fbsd_mtag_nomem, not yet exported as a
  sysctl). The write is lost, which is acceptable under memory exhaustion.
  Exporting the counter is a small follow-up.
- An open ZFS/filedesc WITNESS LOR is recorded in AGENTS.md. It is unrelated
  to pf.

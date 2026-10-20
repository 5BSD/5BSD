# PF consolidation status

> **Superseded (2026-10-15).** This records the 2026-10-10 IPFW retirement
> on FreeBSD pf, before 5BSD replaced FreeBSD pf with OpenBSD PF. It is kept
> as history; its evidence, limitations and next steps no longer describe
> the tree. For the current packet filter see
> [Packet Filter](book/src/operations/pf.md) and
> [Network Stack Provenance](book/src/operations/network-provenance.md).

The target is source retirement of IPFW and the complete PF feature/behavior
program in the Desktop kernel cleanup audit. Dummynet remains the shaping
engine. Build disablement alone is not completion.

## Implemented, qualification in progress

- Independent `sbin/dnctl`, `packages/dummynet`, and Dummynet startup ownership.
- Kernel shaper source under `sys/netpfil/dummynet`; shared packet ABI retained.
- IPFW engine, NAT extensions, ng_ipfw, control utilities, natd, package/startup
  registrations and dedicated tests removed. Native libalias consumers retained
  through a separate library package.
- Retired kernel configuration options and raw-IP firewall control hooks removed.
- OpenBSD `Stlimiters`/`Srclimiters` show names accepted as exact aliases, preserving
  existing native names and abbreviations. This is only part of P08.

## Evidence and limitations

Evidence root: `/usr/obj/5BSD-pf-consolidation-20261010`.
Three dnctl ATF cases and three build/removal contract tests pass. Standalone PF
and Dummynet module builds pass after shaper extraction. The first full kernel
build with IPFW disabled passed. The second build after actual source retirement
passed and was staged as GENERIC #13 (2026-10-10 14:47:02 UTC).

Smoke3 used four vCPUs, restricted user-mode networking, VNET packet tests and
an image without IPFW modules/utilities. DHCP/gateway traffic and all six PF
packet cases passed (enable/disable, IPv4, IPv6, shaping, NAT masking, logging).
All three dnctl cases passed. Smoke3 is retained as failed because the new
limiter assertion expected names instead of numeric IDs.

Smoke4 used the post-removal kernel and passed the same six packet cases and
three dnctl cases. Both limiter alias/native output comparisons passed, but
the source-limiter assertion confused address capacity with per-source limit.
Its failure is preserved. All 17 artifact hashes matched; QEMU exited 0 and
ZFS was healthy. The assertion now checks ID 2, capacity 128 and limit 3.
Smoke5 was not run because staging failed on a read-only test file. Smoke6
passed all ten cases on the post-removal kernel with four vCPUs and restricted
user-mode networking. All 17 runtime hashes matched; IPFW loading was rejected,
QEMU exited 0, buffers synced and ZFS was healthy. This image contains selected
updated artifacts, not a clean-world or pkgbase upgrade qualification. Earlier smoke1/2
harness failures are retained.

Obsolete IPFW/natd defaults were removed from rc.conf (shell syntax passes).
Five rc ordering comments no longer require the deleted IPFW service; all five
scripts pass shell syntax checks. At the smoke7 checkpoint, normal-boot ordering
was unqualified because that image used a dedicated test init script; smoke8
later verified normal PF/Dummynet/dnctl startup as described below.
Unused firewall tokens/options/prototypes were removed from the private dnctl
header, preserving all kernel ABI structures and original notices. dnctl
rebuild and all three parser ATF cases pass after this cleanup. Reviewed
recovery patches/inputs are under the evidence root's `removal-review/`.
The broadened remaining-consumer inventory includes build-knob spellings;
it records references for review, not a count of active dependencies.

## Libalias and bridge follow-up

Removed libalias's IPFW rule insertion/deletion code, firewall-only fields,
helper calls, PPP's `nat punch_fw` command, and obsolete manual descriptions.
The retired 0x100 mode request now fails before changing any other mode bits.
`LibAliasSetFWBase` remains a no-op compatibility symbol; `NO_FW_PUNCH` remains
an external consumer feature marker. Normal aliasing remains supported.
Library/helpers, PPP, kernel libalias modules and full GENERIC build pass.
The library regression suite used the rebuilt library: 22 passes, one existing
expected failure, zero unexpected failures or skips. The new test covers
retired-mode rejection, unchanged configuration and compatibility calls.

Removed the bridge's IPFW/ARP controls and their legacy L2 hook. Native PF
member/bridge IP filtering paths remain. Smoke7 passes all eleven cases in
the four-vCPU networked VM, including both filtering modes, fresh ARP, and
absence of retired sysctls. All 17 runtime hashes match; IPFW loading fails;
QEMU exits 0 with buffers synced and healthy ZFS. Exact results:
`/usr/obj/5BSD-pf-consolidation-20261010/smoke7-results.json`.
This remains selected-artifact testing, not clean-world/upgrade qualification.

## Public ABI and remaining consumers

The follow-up removes the public IPFW/NAT64/NPTv6 firewall headers. Dummynet's
56-byte flow structure retains its historical name and every field offset in
`netinet/ip_dn_flow.h`; a compiled ATF regression checks its layout. Packet-tag
cookies, shared divert metadata and reserved socket option numbers remain ABI.

Retired rescue, startup, periodic defaults, manuals, examples, DTrace and Python
test registrations are removed. Obsolete-file lists cover the retired installed
headers, modules, manuals, examples and Python source files. Administrator policy
files are preserved. Common firewall tests retain PF variants and drop IPFW/IPFilter variants; removed IPFW-only NAT/CGN fixtures do not establish PF parity.
The old shaper heap/scheduler harness is preserved under `sys/netpfil/dummynet/test`
with original notices, but is historical and not qualified against current APIs.

Both blocklist helpers select enabled PF and reject legacy IPFW configuration
without executing it. Dummynet has an independent startup service. The legacy
bridge SNMP leaf remains readable as disabled and rejects writes. The related
libnetgraph dependency fix was committed separately as `1ca64091990`.
Full GENERIC, native PF/Dummynet, dnctl, SNMP bridge and libnetgraph builds pass.
Three build-selection tests and two helper fixture tests (ten scenarios) pass.
The standalone ABI test initially lacked the uninstalled source header; its
rebuild with the source include path passes. No host headers were installed.

Custom ports changes make sshguard's default/packaged firewall script PF and
remove mpd's IPFW configure probe and compile definition. Both pinned distfiles
pass checksums; private builds, staging and `check-plist` pass. Existing deployed
configurations and package upgrades have not been qualified. The ports follow-up
is committed as `148e7fb74400edecee584f5e3d5471b172cd7986`.

The earlier concurrent world build stopped without a completion result. It does
not qualify a clean world.

### Final removal qualification (2026-10-10)

There are 18 distinct passing ATF cases across two component runs, each using
four vCPUs and restricted user networking. This is not a complete passing
18-case normal-boot run or a clean-world/package/upgrade qualification.

- Smoke8 verified normal rc startup: PF enabled, Dummynet loaded and pipe 65000
  configured before the harness loaded modules. DHCP/gateway and 37 runtime
  hashes passed. Thirteen cases passed: dnctl parser/configuration (three),
  flow ABI, limiter aliases, shaping, NAT masks, both real blocklist helpers,
  bridge filtering, PF enable/disable, IPv4, IPv6 and logging. The SNMP case
  failed on a missing symbolic MIB fixture, so the overall run failed.
- Smoke15 passed all seven focused cases: IPv4/IPv6, retired bridge SNMP reads
  and write rejection, IPv4/IPv6 pipes, FQ-CoDel and WF2Q+ heap coverage.
  All 42 runtime hashes matched, IPFW loading was rejected, ZFS was healthy,
  buffers synced and QEMU exited 0. The common production artifacts match
  smoke8. Only test/boot fixtures changed; the actual SNMP module load path
  was corrected to use the rebuilt versioned library and added to the hashes.
- Failed attempts remain recorded: smoke11 had an IPv4 failure and timed out
  with QEMU exit 124; its cause is not established. IPv4/IPv6 subsequently
  passed in smoke13, smoke14 and smoke15 without changing those tests.
  Smoke13 exposed symbolic SNMP definition parsing; the regression now tests
  the stable numeric wire OID, without claiming to fix that parser. Smoke14
  exposed a stale unversioned SNMP library in the private image, corrected
  before smoke15. Images smoke9, smoke10 and smoke12 were superseded, not run.

Evidence root: `/usr/obj/5BSD-pf-consolidation-20261010`.
See `finish-component-qualification.json`, `smoke8-results.json` and
`smoke15-results.json`. Smoke15 log SHA256:
`28808fd36486e77dfe1ddf6bcad5f5d6a1864b27b0f45fc5a5f3017c08875aa7`.
The next clean-world VM should rerun the full normal-startup gate, check removal
of installed obsolete files, and qualify package upgrades, existing policies
and recovery. Symbolic SNMP client/MIB parsing remains a separate review item.

### Package policy preservation regression (2026-10-10)

An isolated real-pkg transaction reproduced loss of a locally modified
`/etc/rc.firewall` when that file disappeared from the rc package manifest.
The rc package now saves existing content before replacement as
`/etc/rc.firewall.pkgsave.XXXXXX`, using a unique name and reporting its location.
The obsolete executable path is removed; the saved policy is for manual review
when migrating to PF. This does not translate or enable firewall rules.

`tools/test/pf-consolidation/package-upgrade-test.py` exercises the production
rc package scripts using fixture packages in a new isolated root. All eight
checks pass: Dummynet installation; IPFW package and file removal; removal of
the old rc.firewall path; saved policy content; preservation of a prior backup
and an unmanaged ipfw.rules file; and no backup on a fresh installation.
Run it with `python3.12 tools/test/pf-consolidation/package-upgrade-test.py
/new/evidence/directory`. It uses pkg-static without installing on the host.

Evidence: `/usr/obj/5BSD-pf-upgrade-20261010/package-policy-regression`.
The before-fix failure is retained in `package-policy-before-fix` alongside it.
The four-core baseline VM, clean world/kernel build, real combined-repository
upgrade and complete post-reboot suite remain pending. The VM upgrade checks
now require the saved policy to remain intact after reboot.

## Remaining work

- Extend kernel coverage beyond the passing smoke gate; qualify clean world,
  packages and fresh/upgrade images.
- Complete the broader inventory of remaining documentation/extension consumers;
  the core public-header, service and monitoring follow-up is described above.
- Audit ports/extension consumers and implement upgrade/recovery diagnostics;
  establish behavior for existing IPFW configurations before any deployment.
- Finish all P01–P12, G01–G12 and fifteen additional source-review requirements
  in the Desktop audit. This includes socket/diversion and routing isolation,
  queue guarantees, pools, counters/logging, pfsync/state-file compatibility,
  transaction behavior, companion tools and their full regression coverage.
- IPFilter source, tools, services and manuals were retired on 2026-10-11;
  deployment migration of existing policy and installed packages is still required.

No host firewall changes, installation, reboot or publication are authorized
by this source/test work. The goal remains active.

# PF consolidation status

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
scripts pass shell syntax checks. Full normal-boot ordering remains unqualified
because the smoke image uses a dedicated test init script.
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

## Remaining work

- Extend kernel coverage beyond the passing smoke gate; qualify clean world,
  packages and fresh/upgrade images.
- Remove obsolete manuals, examples, monitoring references,
  service consumers and any remaining unnecessary header code.
- Audit ports/extension consumers and implement upgrade/recovery diagnostics;
  establish behavior for existing IPFW configurations before any deployment.
- Finish all P01–P12, G01–G12 and fifteen additional source-review requirements
  in the Desktop audit. This includes socket/diversion and routing isolation,
  queue guarantees, pools, counters/logging, pfsync/state-file compatibility,
  transaction behavior, companion tools and their full regression coverage.
- IPFilter retirement remains part of the Desktop plan, separately pending.

No host firewall changes, installation, reboot or publication are authorized
by this source/test work. The goal remains active.

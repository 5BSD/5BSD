# Virtual-network module artifact qualification (2026-11-01)

## Native targets and configuration

`carp`, `if_bridge`, `if_epair`, `if_lagg` and `if_vlan` declare native module,
split-debug and installation-manifest targets for amd64, ARM64 and RISC-V64.
Their seven maintained C sources remain owned by `sys/net`, `sys/netinet` and
`sys/crypto`; CARP's SHA1 source is exported from its existing owner. No C source
or runtime networking behavior was changed.

Header providers declare the actual source dependencies observed in independent
Make dependency files across the three architectures. Option headers are
extracted from each target's real GENERIC config output, including empty headers.
The new carp/ofed/ratelimit/vlan providers contain no invented option definitions.
Existing bus/device/vnode interface generators and module/CTF/export/install
rules remain in use. The maintained frontend's format-5 kernel profile selects
ten artifact/manifest targets per run, with no executable test targets. This
requires no new frontend option, signing or publication policy; the manual is
updated with the supported scope and limits.

## Independent reference and actual checks

Thirty clean Make reference build/install configurations pass under
`/usr/obj/usr/src/bazel-virtual-interface-make-20261101/`.
They use independent object trees, recorded actual compiler/architecture flags
and an isolated header-only KERNBUILDDIR containing hash-recorded byte-identical
copies of authentic target GENERIC option headers. Pre-existing kernel generated
sources cannot be selected through that search path. No Make dependency fixes
were needed in this batch.

All six maintained build-bsd runs pass under
`/usr/obj/usr/src/bazel-virtual-interface-{amd64,arm64,riscv}-{plain,ctf}-r1-20261101/`.
All fifteen plain modules match Make byte for byte. All fifteen installed CTF
modules match every ELF section except build-ID/debuglink contents, including
code, symbols, relocations, CTF and existing SDT data. Actual native and Make
debuglink CRCs validate. Separate DWARF/build-ID/layout differences remain
recorded; source debugging remains unqualified. All forty-five file/debug install
records match destination, type, owner, group, mode and package/debug tags.
Directory metadata and linker.hints are outside this file comparison.

Execution-log auditing accounts for all forty-two target C compile actions,
checking their actual architecture triples, freestanding flags, complete source
inventory and absence of SDK include-file inputs. For each action, every declared
module option header and opt_global.h must be present. Actual option-header
input hashes equal the independent Make header hashes; both paths and hashes are
retained in compile-audit.json.

Artifact review, debuglink results, option/source input audit, bounded source
marker scan, profiles and reproduction scripts are retained under
`/usr/obj/usr/src/bazel-virtual-interface-review-20261101/`.

## Runtime and remaining system gates

The bounded seven-source scan records twenty existing SDT marker lines in
if_bridge.c, if_epair.c, if_lagg.c and if_vlan.c. ip_carp.c, ieee8023ad_lacp.c and
sha1.c have no matches for the audited SDT/KDTRACE/DTRACE/audit/CTR patterns;
review failover and LACP state-transition observability as runtime work proceeds.
This textual scan does not establish active probe counts or complete audit
coverage. Installed section comparisons preserve the existing compiled data.

Matching-kernel module load/unload, bridge/STP filtering and loops, epair/jail
lifecycle and traffic, LACP/link failure recovery, VLAN configuration/offload,
CARP advertisements/authentication/failover, IPv4/IPv6, vnet, live probes and
privilege/MAC/audit denials remain runtime qualification work. RSS, OFED,
rate-limit and other non-GENERIC option combinations are not qualified by this
default matrix.

This batch does not establish controlled CPU/RAM/disk-I/O/disk-allocation
performance, full bootstrap/sandbox closure, input-mutation behavior, complete
kernels/world/pkgbase, hardware repository publication or full-system boot.
No host installation, module loading, interface configuration or service changes
were performed. Make remains the production/default backend; BIP is excluded.

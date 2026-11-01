# PF/dummynet module artifact qualification (2026-11-01)

## Native graph and maintained policies

The current tree uses OpenBSD PF through its maintained 5BSD compatibility
layer. Native `pf` and `dummynet` module/install targets now cover amd64, ARM64
and RISC-V64. Their forty original C sources remain unchanged: fifteen vendor
PF sources, thirteen 5BSD PF glue sources, and twelve dummynet sources. Vendor
files are exported by their existing source owners; adaptation/compilation is
owned by `sys/netpfil/openbsd-pf`.

PF uses three ordinary native cc_library object groups: vendor, radix, and glue.
Their group defines and forced compatibility include match Make. The existing
object-selection rule assembles vendor-before-radix, radix, remaining vendor,
and glue segments in the exact maintained link order. No archive extraction,
object-file search or artificial sort changes that order.

The module object helpers accept explicit `header_overrides` and `warning_flags`.
Defaults retain normal kernel policies. PF's physical compatibility headers must
precede native headers, including overlapping sys/ioctl.h. A source-only CcInfo
provider declares their actual package-relative include directory and headers;
it adds no generated include directory or build action, and preserves the
wrappers' relative includes of vendor headers. PF/dummynet's shared dn_packet.h
ABI is provided explicitly by its dummynet owner.

PF's Makefile defines CWARNFLAGS before kern.mk, replacing the usual default
warning list. Its native object groups now use that exact maintained warning
policy, including -Werror, rather than adding generic kernel -Wall or disabling
new diagnostics individually. Actual recorded compile arguments are checked
against each independent Make configuration.

A shared compiler source-path mapping helper handles declared vendor sources
and the ./ spelling produced by forced-header quote lookup. This produces the
canonical diagnostic/SDT filenames expected by Make. The /usr/src strings here
are compiler provenance, not absolute file reads or runtime policy. No source or
binary output is rewritten to pass artifact comparisons.

## Independent evidence

All twelve isolated Make build/install configurations pass under
`/usr/obj/usr/src/bazel-packet-filter-make-20261101/`. Independent object trees
use recorded compiler/architecture flags and header-only KERNBUILDDIR inputs
copied byte for byte from actual target GENERIC option headers. No Make source
or dependency fix was needed for these two modules.

All six maintained build-bsd invocations pass under
`/usr/obj/usr/src/bazel-packet-filter-{amd64,arm64,riscv}-{plain,ctf}-r5-20261101/`.
Each existing format-5 kernel profile selects four artifact/manifest targets and
no executable tests. Six plain modules match Make byte for byte. Six installed
CTF modules match every ELF section except build-ID/debuglink contents,
including code, symbols, relocations, CTF and existing SDT data. Actual native
and Make debuglink CRCs validate. Separate DWARF/build-ID/layout differences are
retained; source debugging is unqualified. All eighteen file/debug install
records match destination, type, owner, group, mode and package/debug tags.
Directory metadata and linker.hints are outside this file comparison.

The execution audit covers all 240 target source compile actions: actual target
triples, freestanding flags, exact source inventory, no SDK include-file inputs,
PF wrapper-first include order, exact PF warning/group defines and matching
actual GENERIC option-header input hashes. It retains 1,632 option input checks.
All twelve actual linker parameter files have the exact maintained object order.
Their hashes are checked against execution records before retention. Eleven
link records come from this matrix; one amd64 plain dummynet link was reused by
Bazel's cache from a successful action in the retained r3 attempt. That
provenance is explicit, not counted as a newly executed link.

Three additional maintained build-bsd runs requalify the existing kgssapi plain
module on all three architectures after the common source-map change. Its
original generated RPC/KOBJ inputs still produce byte-identical independent
Make modules. Evidence is under
`/usr/obj/usr/src/bazel-packet-filter-kgssapi-regression-20261101/`.

Review, compiler/option audit, linker arguments/order audit, regression results,
profiles, bounded observability scans and reproduction scripts are retained in
`/usr/obj/usr/src/bazel-packet-filter-review-20261101/`. Earlier attempts remain:
r1 exposed cc_library's nonexistent generated include search path; r2 found the
missing shared packet header; r3 exposed the warning-policy mismatch; r4's
amd64 build passed but exact comparison found the forced-header filename
mismatch and its capture helper incorrectly required a cached link to execute.
Those attempts are superseded; their failures were not hidden or counted as
complete matrix passes.

## Observability and remaining gates

The bounded forty-source scan records 134 direct SDT/KDTRACE/audit/CTR marker
lines and 44 PF wrapper marker lines. A separate forced-header scan records
49 marker/configuration lines. These categories can overlap; they are textual
inventories, not active probe counts. Existing compiled sections match Make.
Unmarked sources are listed in the maintained observability log; review NAT64,
interface/rule lifecycle, AQM/scheduler/drop decisions, pfsync, quota and jail
boundary observability during runtime qualification.

Matching-kernel module load/unload, rule evaluation and updates, IPv4/IPv6/NAT,
state limits and sync, logging/flow export, queue/AQM/drop behavior and timing,
VNET/jails, MAC/audit denials, live probe arguments, failure recovery and
concurrency remain runtime work. Non-GENERIC option combinations are not covered.

This batch uses the existing build-bsd kernel profile/configuration API. The
manual is updated; no frontend command option, signing, staging or publication
policy change is needed. It does not establish complete kernels/world/pkgbase,
bootstrap/sandbox closure, input-mutation behavior, controlled CPU/RAM/disk I/O
performance, publication or full-system startup. No host firewall, network,
module, service or installation state changed. Make remains production/default;
BIP is excluded.

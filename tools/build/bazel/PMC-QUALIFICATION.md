# PMC userland native candidates

2026-11-01. Make remains the production backend. This tranche owns native
source and installation declarations for `pmc`, `pmccontrol`, `pmcstat`,
`pmcannotate` and `pmcstudy`. This is not whole-world, kernel, hardware-counter,
package-repository or publication qualification.

The programs use direct rules_cc `cc_binary` sources. Their maintained source
lists and library order are explicit. Mixed C/C++ `pmc` uses C++17 only for its
C++ translation units. The Make C++ final-driver runtime closure is represented
by native libc++/libcxxrt dependencies, including for the C-only source lists
of `pmccontrol` and `pmcstat`. PMC and pmcstat consume the existing internal
`libpmcstat_pie` variant, matching their Make PIE linkage; that internal archive
is not installed. The only reused-library change is narrow visibility for its
existing header target. No C/C++ source changes, host-library fallback or Make
interpretation are introduced into the production graph.

Installation candidates retain package `pmc`, the four maintained section 8
manuals, separate debug files and the original paths: pmcstudy in /usr/bin,
the other four programs in /usr/sbin. PMC has no maintained manual. There are
no maintained test subdirectories in these five component Makefiles. New
constraints preserve the FreeBSD OS requirement; existing library/toolchain
coverage currently limits this tranche's build evidence to amd64.

## Build and installation evidence

Independent Make references completed through the maintained install-reference
helper under /usr/obj/usr/src/bazel-{pmc,pmccontrol,pmcstat,pmcannotate,pmcstudy}-make-20261101.
Each uses fresh component objects and staging with the selected development
SDK/profile and 16 compilation jobs. A subsequent source-snapshot recheck finds
only native BUILD declarations changed; every actual Make/C/C++/header/manual
input remains identical to that reference.

The maintained frontend completed all ten program/install targets in
`/usr/obj/usr/src/bazel-pmc-tools-qualification-r2-20261101/` with explicit
`--target-arch amd64`. The first run's link failure is retained in the matching
`r1` directory: PMC calls terminfo directly, and Make's libncursesw.so linker
script supplies AS_NEEDED(-ltinfow). Native shared-library dependencies do not
implicitly reproduce that consumer script. Declaring the direct native
tinfo/tinfo_shared edge preserves the actual Make dependency closure and order.
No shared linker helper or binary-rewriting workaround was added.

Reports and the exact comparison script are retained in
`/usr/obj/usr/src/bazel-pmc-tools-parity-r2-20261101/`. All 24 installation records
match Make destinations, types, owners, groups, modes and pkgbase tags: PMC has
four records and each other component five. All four compressed manual payloads
match bytes. This is logical NO_ROOT metadata, not actual installed ownership
or privileged behavior. Dynamic dependency order, imported/exported symbols and
the checked ELF hardening contract match for all five programs. All native and
Make separate debug links validate against their actual debug files.

Every installed pmcannotate and pmcstudy ELF section matches except
.gnu_debuglink. PMC, pmccontrol and pmcstat have additional section differences,
including text/layout and read-only data. Their differing printable strings are
exactly native source-relative versus Make /usr/src-prefixed assertion paths,
including internal libpmcstat source paths. The complete raw differing-section
reports are retained. This bounded review does not establish complete machine
code equivalence, whole DWARF identity or debugger source resolution; no
per-program absolute source mapping was introduced merely to force byte parity.

The normal build-bsd format 5 native target interface, SDK, installation,
verification and package helpers support these component declarations unchanged.
No new frontend inputs or global policy switches are required. This tranche
uses the parent change's maintained frontend with its explicit default native
architecture; that does not constitute cross-compiling the PMC programs.

## Observability and runtime gates

No direct DTrace provider, SDT probe or explicit audit submission is present in
the five program source sets inspected here. Existing library instrumentation
is retained. Whether the privileged counter-control and process-observation
operations need additional program-level audit/probes remains an observability
review item; a successful link cannot establish this coverage.

No live hardware counters, module loading, recording, process attachment,
interactive terminal view, annotation tool subprocesses or profiler data format
compatibility have been exercised. In particular pmcstudy performs CPU discovery
and can invoke pmccontrol before parsing help options; help is not treated as
an isolated hardware-independent runtime test. Host service configuration,
installation, upgrade, VM startup and reboot are not part of this tranche.

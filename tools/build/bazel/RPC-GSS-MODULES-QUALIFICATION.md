# RPC/GSS module artifact qualification (2026-11-01)

Scope: `krpc`, `kgssapi`, and `kgssapi_krb5` for amd64, ARM64 and RISC-V64,
with plain and CTF/split-debug artifacts. These contain 57 maintained C sources
and seven generated C sources. Source ownership remains with `sys/rpc` and
`sys/kgssapi`; the module packages assemble their declared object groups.

Kernel RPC generation uses the native rpcgen executable, the declared SDK
preprocessor and runtime, and the maintained schemas. Header/client generation
uses rpcgen's stdout interface, followed by the original grep exclusions for
pthread.h/string.h. The distinction matters: passing a temporary filename with
`-o` changes rpcgen's header guards. XDR generation retains `-c -o` semantics.
KOBJ interfaces use the maintained makeobjops generator, not copied output.

## Reference quality

The first Make reference batch exposed a missing `vnode_if.h` dependency in
`sys/modules/krpc/Makefile`; it is now explicitly declared. Existing amd64
GENERIC objects had masked the missing dependency.

The next reference review found that kmod's KERNBUILDDIR search path reused
pre-existing TLS RPC generated files from the amd64 GENERIC object directory.
That reference is superseded. The independent reference under
`/usr/obj/usr/src/bazel-rpc-gss-make-r3-20261101` uses a separate header-only
KERNBUILDDIR with hash-recorded, byte-identical copies of actual target GENERIC
option headers. Compiler architecture flags are queried from the original
configured kernel. All 18 Make builds/installations pass; all 78 protocol/KOBJ
source and header instances are independently generated and hash-recorded.
No host installation or module loading is performed.

## Native artifact and input evidence

All six maintained build-bsd runs under
`/usr/obj/usr/src/bazel-rpc-gss-{amd64,arm64,riscv}-{plain,ctf}-r10-20261101`
pass. These kernel profiles select module/install targets and no executable tests.
All nine plain module artifacts match the independent Make references byte for
byte. All nine installed CTF artifacts match every ELF section except build-ID
and debuglink contents; CTF, code, symbols and relocations match. Both native and
Make debuglink CRCs validate. Separate DWARF/build-ID/layout differences remain
recorded; source debugging is unqualified. All 27 file/debug install records
match destinations, types, owners, groups, modes and package/debug tags. Directory
metadata and linker.hints are outside this file comparison.

The retained action audit covers all 384 target C compile actions, with their
actual architecture triples, freestanding flags, complete 64-source inventories
and no SDK include-file inputs. Sixty generated RPC source/header instances match
Make byte for byte. Eighteen KOBJ source/header instances differ only in the
recorded generated comment identifying `kgss_if.m` by basename versus absolute
source path; no executable tokens differ. The audit retains the actual native
input hashes, generated file copies and exact differences, rather than modifying
outputs to pass comparison. Native stdout RPC generation is now qualified with
the correct header guards. The default file-output path remains exercised by
XDR generation. Nine generation/filter actions executed in this consistent
matrix; other generator outputs were reused from the declared action cache.

Review, input audit, generated files/differences, bounded observability scan and
reproduction scripts are retained under
`/usr/obj/usr/src/bazel-rpc-gss-review-20261101/`.
Native r7/r8 analysis failures and the superseded r9 header-guard attempt remain
available under the corresponding `bazel-rpc-gss-*` evidence paths.

## Remaining gates and frontend integration

The bounded 57-source scan records thirteen existing SDT marker lines in three
RPC source files. It does not establish active probe coverage or identify every
place that should have new audit or DTrace instrumentation. Provider registration,
live arguments and authentication/audit paths require runtime qualification.

These artifact targets use the maintained build-bsd kernel profile and existing
format-5 configuration; they introduce no frontend option, signing policy or
publication change. Production/default backend selection remains unchanged.

Matching-kernel load/unload, RPC/TLS/GSS/Kerberos traffic and authentication,
NFS recovery, live observability, full kernels/world/pkgbase, bootstrap and
sandbox closure, and controlled CPU/RAM/disk performance remain open. Cross
compilation is not a runtime pass. BIP remains excluded.

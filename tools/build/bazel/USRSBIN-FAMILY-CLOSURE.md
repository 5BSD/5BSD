# usr.sbin production parent and remaining migration

## Source-owned graph (2026-11-05)

`//usr.sbin:production_installation_archives` declares the AMD64 production
selection from `usr.sbin/Makefile` and `Makefile.amd64` using native labels and
configuration selects. No Make query, directory glob or Python selection feeds
this graph at build time. Existing children supply the actual compilation,
generation, linking and archive actions. The parent preserves installation
request and directory-metadata output groups.

The parent owns `nvram(8)` even though AMD64 does not build its executable.
This contribution was absent from the earlier explicit child-only build request.
It installs the original manual under utilities (utilities-man with split
manual packages). Endpoint visibility grants the new parent access without
making private implementation headers public; existing package access remains.

Explicit settings include apm, authpf, bsdinstall, caroot, cxgbetool, mlx5tool
and pkgbootstrap. Their initial AMD64 defaults are enabled. Effective authpf
requires pf; pkgbootstrap requires OpenSSL and crypt. Blacklist/blocklist now
share the original bidirectional disabling dependency.

## Qualified selected construction

All evidence below is under `/usr/obj/usr/src`.

- `bazel-usrsbin-parent-native-r3-20261105` passes the normal build-bsd frontend
  with sixteen jobs: 242 selected child owners plus the parent-owned manual,
  producing 336 installation archives. The source-settings test is cached and
  passing. This request also builds ssh, sshd, sshd-session, sshd-auth, the SSH
  configuration header and both default telnet archives after the option fix.
- Its `parent-review/review.json` resolves immutable captures with the maintained
  artifact resolver. Of the 1,006 earlier logical outputs, 1,005 are unchanged.
  The only changed archive is bsd-build: all metadata and other payloads agree;
  its updated compressed manual matches the current source. Exactly three new
  parent-manual outputs are added (archive/request/directory metadata).
- The added manual matches independent original Make metadata and compressed
  payload from `bazel-usrsbin-parent-manual-make-r1-20261105`. That reference
  explicitly empties SUBDIR and executes the real parent's all-man/maninstall;
  it proves this manual only, not installation of the complete family.
- `bazel-usrsbin-parent-selection-r2-20261105/review.json` compares actual
  configured direct parent edges with independent Make recursion. Default,
  disabled blocklist, disabled netgraph/Bluetooth, disabled CA root support,
  disabled OpenSSL and reduced profiles select respectively
  242/238/238/240/234/206 owners in both systems. These analyses do not establish
  alternate-profile compilation or runtime; some selections still depend on
  explicitly incompatible child implementations.

The initial parent run failed on seven daemon endpoint visibility declarations;
the corrected grants preserve narrow parent/package access. The initial option
review also found the Kerberos-support mismatch below. Failed attempts remain
retained; they are not accepted results.

## Kerberos option semantics

The old Boolean condition unconditionally disabled Kerberos support with crypto.
The maintained Make options instead apply a final dependent-option pass:
KERBEROS_SUPPORT follows effective KERBEROS unless explicitly enabled/disabled.
The typed `kerberos_support` setting now takes `auto`, `yes` or `no` and defaults
to auto. The selected recorded SDK profile explicitly enables support, represented
as yes in the qualification input. This distinguishes an actual independent
choice from its default; it does not invent a fallback library implementation.

All SSH dependency and unsupported-Heimdal conditions use the shared effective
condition. The generated SSH header receives that same condition as a Boolean
attribute, rather than treating a nonempty string as true. Telnet's unsupported
configuration guards use the shared condition too. Existing raw Boolean requests
must use the new declared values; this work has not landed as a stable interface.
The build-bsd manual documents the setting. Generic format-5 dispatch supports
these typed settings and labels without C dispatcher changes. Make backend,
staging/signing, hardware and publication contracts are unchanged.

`bazel-kerberos-minimal-native-r1-20261105` builds the explicitly disabled SSH
header and both minimal telnet archives. The maintained archive verifier compares
both with fresh original `bazel-kerberos-minimal-telnet-make-r1-20261105`: member
order and per-member symbols agree. This is not code-byte or runtime equivalence.
`bazel-kerberos-auto-native-r1-20261105` builds the automatic-disabled header.
These selected source-settings tests pass from cache.
`bazel-kerberos-option-review-r1-20261105/review.json` resolves captured headers
and compares Make's effective support in the explicit-yes, explicit-no and
automatic-disabled cases. All three agree. It also executes explicit native
build requests for each of the seven missing optional/test selections and
for SSH/telnet Heimdal with automatic support enabled. All nine requests reject
as incompatible at that earlier checkpoint. Bootparamd, FDT/ofwdump and
freebsd-update have since been implemented and qualified below. The other
rejection gates remain. This proves rejection at that checkpoint, not implementation;
it does not establish live SSH authentication or daemon runtime.

## Three optional production groups (2026-11-05)

The bootparamd, FDT/ofwdump and freebsd-update gates are replaced with native
parent selects after implementing their real producers:

- bootparamd and callbootd generate their header, server/client and XDR sources
  from the source-owned bootparam_prot.x schema using declared native rpcgen,
  preprocessor and runtime/tool inputs. Their inherited warning option, TFTP
  definition and conditional NIS definition are preserved. No generated stubs
  or staged generated C files replace those actions.
- ofwdump declares its two C sources and local headers against the selected
  declared SDK's installed firmware interfaces. Hardware access remains untested.
- freebsd-update installs its unchanged script, manual and configuration with
  original ownership, modes and configuration tag. Its package-owned /etc
  directory is explicit. This legacy optional updater is not the pkgbase or
  BSDFoundry upgrade path and is not run by qualification.

`bazel-optional-admin-native-r2-20261105` passes the normal frontend with all
three options enabled: 245 selected immediate owners and 340 installation
archives. Its source-settings test is cached and passing.
`bazel-optional-admin-selection-r1-20261105/review.json` independently confirms
all 245 configured owners against Make for this expanded profile.
`parent-output-comparison.json` preserves all 1,009 prior logical outputs byte
for byte and adds exactly the four new archive/request/directory-metadata triples.

The run's `original-review/review.json` compares fresh original references:
`bazel-optional-bootparamd-make-r1-20261105`,
`bazel-optional-ofwdump-make-r1-20261105` and
`bazel-optional-freebsd-update-make-r2-20261105`. The three groups match 8/5/5
unique component metadata records, coalescing only identical repeated directory
claims. All six script/configuration/manual payloads match exactly. The three
programs pass strict ELF dependency/interface/hardening comparisons, native and
original debug CRC validation, and safe usage-status/stdout/stderr comparisons.
The updater passes shell syntax checking only. Active RPC, NIS-enabled bootparamd,
firmware device access, update execution, other ABIs, alternate package profiles
and comparative resource acceptance remain unqualified.

The review's `input-equivalence.json` also verifies that the source-owned RPC schema
and selected firmware headers match the original Make SDK inputs byte for byte.

The initial native script archive omitted the package-owned /etc directory;
the original component reference identified it. The corrected manifest and fresh
reference preserve it. No C or shell production source was changed, and no
failed/missing payload was filtered out. Generic frontend settings/labels already
represent these options; no C dispatcher, backend, signing or publication
interface change is needed. See observability-audit.md for instrumentation gaps.

## Explicit remaining work

This production parent rejects installed tests and other ABIs. It also rejects
lpr, NIS and sendmail while those selected subtrees lack native production
closures. These constraints identify migration
work; they are not evidence that all configurations have been converted.

Finish those optional owners and original installed tests, then remove each gate
only after construction and installation qualification. Reconcile complete
original Make metadata/payload/ancestor directories and pkgbase ownership for the
whole family. Live capability-daemon behavior and SSH login/authentication remain
runtime work. Complete world, other architectures, bootstrap independence and
reproducibility, packages/hardware/combined publication, VM and controlled
CPU/RAM/disk I/O/footprint/cache/sandbox acceptance remain required.
Make stays production/default. BIP is excluded. No host installation, upgrade,
publication or reboot is performed by these checks.

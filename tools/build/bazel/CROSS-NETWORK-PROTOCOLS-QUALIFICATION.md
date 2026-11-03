# ARM64/RISC-V network protocol and interface module qualification

## Qualified scope (2026-11-03)

Twenty-eight selected network protocol/interface module leaves per architecture
pass ARM64/RISC-V builds and artifact checks. Fifty of 56 plain modules equal
untouched Make bytes; six equal explicit identical-source canonical-filename
controls. CTF/runtime checks retain the same 50/6 distinction. The review
covers 344 actual compiler contexts/55,296 canonical consumed pairs, 224 ordered
links and 168 installation records. It preserves WireGuard's forced header,
TCP-specific defines and Netlink's relative CTF object paths. A missing tuntap
generated-header prerequisite and localized TCP timer API exports are corrected
in maintained Make and native metadata. Twelve actual provider tests pass
across six profiles, including amd64 regressions. Separate DWARF, runtime,
full-system and performance gates remain open. See
[CROSS-NETWORK-PROTOCOLS-QUALIFICATION.md](CROSS-NETWORK-PROTOCOLS-QUALIFICATION.md).

The 28 leaves cover Geneve, OpenVPN, tuntap, vether, VXLAN, WireGuard,
IPv4/IPv6 multicast routing, IPsec, ERTT, libalias and its seven protocol
modules, Netlink, nlsysevent, SCTP, SEND, SIFTR, TCP BBR/HPTS/RACK/MD5 and XDR.
They own 81 source groups, 84 physical C sources and 86 ordered objects per
architecture. This is a selected cohort, not complete world or cross-kernel
qualification. No module is loaded or executed.

## Native build and input policy

Source-owned BUILD declarations select each architecture's real GENERIC
configuration, option headers, complete ordered objects, exports, aliases and
installation metadata. The migration reference retains 56 parent-chain-aware
Make source/object queries and 69 regular Makefiles, with /dev/null explicitly
recorded as a character-device configuration sentinel. Actual compiler META
commands and dependency files independently verify the input closure. Neither
runtime builds nor Bazel analysis discover sources through Make or import a
migration-generated JSON inventory.

WireGuard retains its forced compatibility header after opt_global.h, with
both identity and order checked against the actual consumed inputs. TCP BBR
and RACK retain MODNAME/STACKNAME defines. Netlink retains NETLINK_MODULE and
the route/*.o paths used for CTF ordering. The shared module wrapper forwards
an optional ctf_object_paths argument into the existing validated CTF rule;
the default remains empty. Object link ordering remains a separate complete
basename inventory. Both actual Netlink CTF profiles pass the original CTF
section and layout checks. Twenty-seven other leaves exercise the default.
Only one new precise physical header view was needed; existing providers and
architecture option extractions supply the remaining declared prerequisites.

The maintained build-bsd C frontend and backend were reviewed. Existing
format-5 inputs, typed kernel target selection and unsigned qualification
handling cover these declarations; no new CLI or alternate builder is needed.
Six normal build-bsd bazel-test profiles use the native-r3 execution SDK and
all 16 logical CPUs. They do not establish self-hosted bootstrap or a fully
qualified FreeBSD sandbox. Publication, verified boot and root protection are
not claims of this module qualification. Make remains the production default;
BIP remains excluded.

## Two source prerequisite/export corrections

The original isolated tuntap builds failed on both architectures and both
plain/CTF modes: syscallsubr.h includes mount.h/vnode.h, which consumes
vnode_if.h. Adding vnode_if.h to the maintained module SRCS declares the
existing generation rule rather than relying on a populated kernel object
tree. All 112 fresh original cross-target build/install controls then pass.

BBR and RACK each import six public tcp_hpts.h symbols from tcphpts. The old
module export default localized those definitions. The current kernel permits
local-symbol lookup by default, so the finding is a dependency on that
compatibility behavior, not evidence of an observed runtime loading failure.
Maintained Make now explicitly exports the provider's non-static API;
existing amd64 and new cross-target metadata use the same policy. Four fresh
cross-target exporter controls pass after this correction. The native positive
tests require all twelve exact API edges. Negative tests relocalize the real
provider artifact and must reproduce exactly those twelve hidden references.
These tests check supplied provider bindings; they do not prove all imports
have a compatible kernel/external provider or that modules load at runtime.

Eight original amd64 regression variants cover tuntap, tcphpts, BBR and RACK.
Their two normal Bazel profiles pass four actual provider tests and the
artifact review: 22 compiler contexts/4,452 consumed pairs, eight ordered
links and twelve installation records. Two plain modules match untouched Make;
the BBR/RACK pair matches explicit same-source filename controls. The four
CTF/runtime comparisons retain that same two/two distinction.

## Filename and debug boundaries

Make's nlsysevent source argument contains a double slash. BBR/RACK arguments
contain parent components. Native provenance uses canonical source paths;
__FILE__ strings consequently differ. Untouched artifacts and section hashes
are retained, never relabeled as whole-byte matches. Both builders' actual
source arguments, same-file identity, source hashes and declared native
macro-prefix mappings derive the comparison controls. The controls append
only explicit macro-prefix mappings to otherwise unchanged original compiler
policy and ordinary Make build/link/install recipes. Their actual consumed
inputs and forced-header order must remain identical to the untouched build.
No production source, Make source path or per-program comparison exception is
changed to manufacture a byte match.

Six cross-target module/architecture pairs have filename spelling differences,
producing twelve plain/CTF controls; all twelve are needed. Two amd64 pairs
produce four further controls. For CTF/runtime comparisons, every section's
contents and layout match the declared reference except build-ID/debuglink
values; their encoding/metadata and original/native debug CRCs are checked.
All 56 cross-target and four amd64 separate debug files differ. Semantic DWARF,
source-package mappings and debugger source lookup remain open.

The first untouched-only review rejected nlsysevent's raw mismatch and remains
retained. A second observer attempt selected an uncaptured generic_debug label;
the debug payload was already captured by install_manifest. The accepted
observer explicitly selects that producer/output and validates receipt,
manifest, file hash and configuration identity, without a fallback or rebuild.
The initial rejected Make controls and source-list path-flattening observer
failures remain available as well.

## Instrumentation and evidence

The bounded physical-source scan records 157 candidate marker lines across
84 sources. Seventy-one have no direct matched marker; that is a review queue,
not proof of missing instrumentation. Sixty-eight cross-target variants retain
exact compiled SDT/DTrace/tracepoint-related section contracts against their
declared references. Live probe firing, security-audit delivery and tracing
costs remain unqualified; no probe or C implementation was changed here.

Evidence under /usr/obj/usr/src:

- bazel-cross-network-protocols-work-r1-20261103: versioned source resolution,
  actual dependency inventory, source bindings, six input profiles, filename
  mappings/proofs, resource guards, command records and observability inventory.
- bazel-cross-network-protocols-context-r4-20261103: current original Make
  contexts; earlier contexts and rejected attempts remain separate.
- bazel-cross-network-protocols-make-r2-20261103: 112 original reference
  variants before the explicit timer export correction; its four affected
  exporter references are independently superseded by
  bazel-network-hpts-export-make-r1-20261103. Every accepted reference retains
  equal before/after input bindings; the main set binds 8,646 inputs.
- bazel-cross-network-protocols-{arm64,riscv}-{plain,ctf}-r1-20261103:
  completed frontend receipts, captured payloads, action/input captures and
  test reports; corresponding -actual-capture directories retain dependencies,
  generated inputs and ordered link parameter files.
- bazel-cross-network-protocols-make-filename-controls-r1-20261103: twelve
  explicit same-source controls; raw original outputs remain separate.
- bazel-network-amd64-{plain,ctf}-r1-20261103 and corresponding captures;
  bazel-network-amd64-make-r1-20261103 and
  bazel-network-amd64-filename-controls-r1-20261103: amd64 regression evidence.
- bazel-cross-network-protocols-review-r3-20261103: accepted full cross-target
  review, exact provider-test/source supplement and commit binding.
- bazel-network-amd64-review-r1-20261103: accepted amd64 regression review.

Full-world/package aggregation, complete cross-kernels/drivers, boot/runtime,
upgrade, bootstrap, sandbox and measured CPU/RSS/disk-I/O/disk-space comparisons
remain separate completion gates. Reference time/resource observations are not
an end-to-end performance result. No host installation or reboot occurred.

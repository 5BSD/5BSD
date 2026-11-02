# IPv4/TCP built-in kernel qualification

## Scope (2026-11-02)

Forty-three previously unmatched physical sys/netinet translation units selected
by the fresh amd64 GENERIC inventory now have native built-in object targets.
They cover selected ARP/IGMP/IPv4, PCB/raw/UDP, TCP and SCTP CRC support. This
cohort does not establish a complete TCP/IP subsystem, full native kernel link,
module closure, alternate configurations or ARM64/RISC-V64 completion.
No production C source, network service or runtime policy was changed.

Each source owns its compilation target and narrow physical header contexts in
the packages that own those files. The TCP log device interface now has its own
sys/dev/tcp_log source package; no root-package cross-tree header fallback was
added. Existing root declarations do not reference that path. The eventual
TCP log device implementation is still a separate product to reconcile.

Existing native built-in kernel and CTF helpers are reused. The actual selected
config tree supplies opt_ipstealth.h, opt_mrouting.h and opt_route.h; other option
extraction rules are reused through consumer-specific views. There is no Make
query, metadata interpretation or option-content substitution in native build
actions. Per-source physical prerequisites remain explicit native metadata.

## Frontend and references

The normal build-bsd bazel-test format-5 API already expresses these object
targets, the kernel target kind, typed CTF/debug settings and selected SDK.
No new frontend C/CLI option, helper API or backend replacement is needed.
The source-owned API was exercised with all sixteen logical CPUs and the fresh
post-upgrade SDK described in VM-KERNEL-QUALIFICATION.md. Make remains the
production default, and BIP remains excluded.

Evidence is retained under /usr/obj/usr/src:

- bazel-kernel-ipv4-make-metadata-r1-20261102: supported Make per-object meta
  recipe capture with filemon disabled. All forty-three existing object hashes
  stayed unchanged. The objects come from the previously successfully linked
  fresh Make GENERIC reference, not a new post-upgrade kernel compilation.
  The actual recipes and current source/configuration inputs are checked;
  nofilemon does not provide a full dynamic dependency trace.
- bazel-kernel-ipv4-amd64-ctf-r1-20261102: successful normal frontend build,
  immutable artifact captures, execution log and receipt. The target list builds
  forty-three object groups; tests=[] means no runtime cases were executed.
- bazel-kernel-ipv4-review-r1-20261102: retained recipes, profile, review scripts,
  original section hashes, actual compiler/CTF input bindings, filename and
  symbolic relocation checks, and source-bound observability findings.

## Checks performed

All forty-three original .text sections and all forty-three .SUNW_ctf sections
match Make byte for byte. Successful compiler output digests bind to declared
converter inputs and then to immutable captured object digests. All forty-three
actual compiler actions preserve Make's ordered warning vector, macro definitions
and stack-protector selection.

The prerequisite review verifies 7,328 physical bindings (366 unique files) and
187 consumed generated bindings, including option and vnode interface headers.
There are no new generated-header content exceptions in this cohort.

Thirty-three objects have raw runtime-section differences. Forty-three diagnostic
filename expansions name exact hashed physical inputs with relative native
versus absolute Make spellings. All 23,075 nondebug relocations compare equally
by symbolic target after accounting for those exact filenames/string offsets.
Every original section hash and string is retained. No object is rewritten to
force parity. Whole object/debug/symbol/string-table byte identity is not claimed.

The bounded source scan includes TCP_PROBE, IP_PROBE, UDP/MIB wrappers as well as
SDT/DTrace, audit, CTR and lockstat markers. Fourteen sources contain recognized
markers; twenty-nine do not. The earlier generic-marker-only scan is retained
separately and must not be interpreted as the TCP/IP probe inventory. Unchanged
code, data/interface inputs and relocation comparisons preserve existing compiled
probe plumbing; this is not evidence of live event delivery or complete audit
coverage. Packet/session/retransmit/timer/MIB events, denial behavior and tracing
cost require the matching isolated test kernel. Review shared coverage before
proposing additional instrumentation on packet hot paths.

Disk reserve monitoring did not fire. Resource/timing records are observations,
not controlled CPU/memory/disk/cache performance comparisons. Remaining gates
include other network/custom objects, complete native kernel aggregation, version,
link/post-processing/install, cross builds, modules, full world/pkgbase/hardware
publication, runtime/VM and performance qualification. The full goal stays active.

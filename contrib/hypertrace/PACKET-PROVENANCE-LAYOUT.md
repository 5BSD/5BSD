# Packet provenance layout review

**Historical review:** The 512-byte inline layout and isolated 256-byte
candidate described below were the pre-merge state. The active
`experimental/hypertrace` branch now uses `MSIZE=256` with persistent V1 and
V2 packet-ID sidecars. See `PACKET-PROVENANCE.5BSD` and gate 8 of
`INTEGRATION-GATES.5BSD.md` for the current integrity contract and the
remaining live migration qualification. Statements below that the layout
change has not been applied refer only to the former branch state.

The experimental branch embeds a 32-byte `mbufid_t` in every packet header
and changes `MSIZE` from 256 to 512 bytes. That doubles the allocation size
of every mbuf, including traffic that never carries a HyperTrace ID. The
public 32-byte ID and VirtIO packet-ID wire format need not change.

The present wire check validates the ID's shape, not its origin. Bhyve
accepts a canonical ID supplied by a guest, including an ID naming a
different node. That preserves forwarding of an already identified packet,
but a guest can also fabricate the same bytes. Until an authenticated
lineage mechanism distinguishes those cases, cross-guest IDs are tracing
hints rather than proof of which guest originated a packet.

The newer 5BSD OpenBSD-PF port already uses a lazy `PACKET_TAG_PF` after an
earlier local test enlarged `MSIZE` to 512 for inline PF state. That port
returned `MSIZE` to 256; HyperTrace's inline packet ID is a separate change.
The precedent supports the allocation strategy, but the packet-ID tag needs
its own copy, persistence, and failure semantics.

The proposed kernel layout change removes the inline `pkthdr.mbufid`, returns
`MSIZE` to 256, and stores an ID in a persistent `m_tag` only when a packet
needs one. `m_mbufid()` would return the existing tag or `NULL`; callers that
write an ID would use `m_mbufid_ensure(m, how)` and handle allocation failure.
The tag must survive normal packet-header copies and interface crossings,
while ordinary untagged packets incur no ID allocation. The existing
32-byte on-wire representation remains unchanged.

An isolated copy of `sys/sys/{mbuf.h,param.h}` with only those two layout
edits was compiled on LP64. The current headers report `MSIZE=512`,
`sizeof(struct mbuf)=288`, `sizeof(struct pkthdr)=96`, `MHLEN=384`, and
`MLEN=480`. The isolated candidate reports `MSIZE=256`,
`sizeof(struct mbuf)=256`, `sizeof(struct pkthdr)=64`, `MHLEN=160`, and
`MLEN=224`. This establishes structural fit on LP64, not runtime safety or
32-bit compatibility. The current allocation is 512 bytes despite the
288-byte C structure size; the candidate would occupy the full 256 bytes.
Experimental amd64, arm64, and RISC-V GENERIC kernels booted in QEMU all
report the mbuf zone size as 512 bytes via `vmstat -z`, confirming the
current runtime allocation size across these architectures. This is a
baseline measurement, not a throughput or memory comparison against `dev`.

An i386 FreeBSD 16 cross-target syntax and record-layout check also passes:
the current ILP32 headers have an 88-byte packet header and 284-byte mbuf
structure within `MSIZE=512`; the isolated candidate has a 56-byte packet
header and 252-byte mbuf structure within `MSIZE=256`. Its packet-data offset
falls from 112 to 80 bytes and ordinary-data offset stays 24 bytes. This
checks compile-time fit on ILP32; it does not exercise a 32-bit kernel or
packet path.

The existing mbuf operations provide the required ownership primitives:
`m_move_pkthdr()` transfers the tag list and clears it on the source,
`m_dup_pkthdr()` deep-copies tags through `m_tag_copy_chain()`, and
`m_tag_delete_nonpersistent()` preserves tags marked `MTAG_PERSISTENT` at
interface boundaries. The sidecar needs a unique cookie and persistent tag
type, plus allocation with the caller's sleep policy. Its getter must never
allocate. Incoming VirtIO and TAP IDs must fail the packet with `ENOBUFS` if
the required sidecar cannot be allocated; locally generated BPF and socket
IDs need the same explicit failure path rather than dereferencing `NULL`.
No raw pointer to sidecar storage may survive a header move, copy, or free;
the VirtIO wire header must contain a value copy before DMA submission.
The guest VirtIO-net TX path now copies an existing canonical ID before any
allocation. When no node identity is available, it emits the reserved zero
wire ID without allocating an absent sidecar; a malformed existing ID is
cleared. Otherwise it generates directly into the mbuf so the generation
probe observes the stored ID. Audit and LRO validity checks now require the
same magic and zero padding as the wire decoder. The source-extracted fixture
covers those cases, a node-identity race, and allocation failure. This does
not change the current inline mbuf layout.

The call-site audit found writers in BPF, socket send, TAP input, and VirtIO
net, plus readers in socket/audit probes, TAP output, VirtIO net, UDP probes,
and scatter/gather code. Both `M_NOWAIT` and `M_WAITOK` writers now check for
a missing sidecar; read-only probe paths use null-safe validity helpers. A
kernel-wide build must check structure-size
assertions and module linkage. Native mbuf copy/clone/free tests, VirtIO/TAP
cross-guest ID tests, and live network throughput and memory measurements
against the `dev` layout are required before accepting the redesign.

This layout change has not been applied. It needs explicit approval because
it changes a core kernel ABI and packet allocation behavior.

## Isolated 256-byte sidecar candidate, 2026-10-15

An isolated source copy at
`/usr/obj/5BSD-hypertrace-packet-sidecar-candidate` now implements the
persistent packet-ID tag, restores `MSIZE=256`, and leaves the 32-byte wire ID
unchanged. The experimental worktree still has the inline 512-byte layout.
The candidate avoids allocating a tag for unobserved socket datagrams and
BPF writes. The initial gate responded to any enabled SDT probe; the revised
candidate responds only to packet-ID-consuming `ddtrace:pkttag`, `udp:send`,
and `vtnet:if_vtnet:txq:enqueue` probes, or to active audit, and skips
allocation when no origin identity is available. The dedicated SDT enable
count passes a focused classifier test, including unrelated probes and
multiple simultaneous packet probes. VirtIO-net TX still creates an ID at
its negotiated wire boundary. Tagged TAP output now preserves an existing
canonical ID or creates one directly in the export prefix when an origin is
available. `tunread()` frees the packet after copying it, so this does not
need a transient tag. A missing origin uses the reserved zero ID.

A 16-job amd64 GENERIC kernel and module build passed at
`/usr/obj/5BSD-hypertrace-validation/packet-sidecar-buildkernel-amd64.log`;
the incremental build after send-path gating passed at
`packet-sidecar-buildkernel-gated-amd64.log`. A temporary boot-time check in
the isolated kernel exercised the real mbuf tag implementation: allocation,
repeat lookup, deep packet-header copy, persistence across nonpersistent-tag
cleanup, and transfer on packet-header move all passed. The rootless QEMU
boot reported a 256-byte mbuf zone and passed DTrace BEGIN and a syscall
probe. Its result is
`/usr/obj/5BSD-hypertrace-validation/packet-sidecar-qemu-20261015/result-builtin.json`.
The guest used a previously built world with the candidate kernel, so this
does not yet prove a matched candidate world.

A second QEMU run sent 10,000 untraced UDP datagrams to localhost. The
`mbuf_tag` allocator request count remained at 2 before and after, and the
same boot passed the built-in tag checks and DTrace probes. The evidence is
`packet-sidecar-qemu-20261015/result-udp.json` and its `serial-udp.log`.
This establishes that the idle localhost socket path does not allocate ID
tags; it is not a throughput measurement or a tagged VirtIO/TAP test. Custom
test KLDs failed to load in the disposable guest even when they contained no
mbuf code, so the native tag check was linked into the isolated kernel for
this qualification run. The temporary SYSINIT test is not part of the
experimental worktree. A 16-job amd64 development buildworld passed before
the packet-probe gate revision; the revision changes kernel-only paths.

The revised 16-job GENERIC kernel and modules passed at
`/usr/obj/5BSD-hypertrace-validation/packet-sidecar-buildkernel-probe-gate-amd64.log`.
A rootless QEMU guest staged from the candidate world and revised kernel
passed DTrace BEGIN, a syscall probe, 10,000 untraced UDP datagrams, and
the live dttransport descriptor-ownership test. Its result is
`/usr/obj/5BSD-hypertrace-validation/packet-sidecar-matched-gate-20261015/result-dttcommit.json`.
For a positive packet-gate test, a temporary sysctl in this isolated kernel
set a synthetic node ID of 42. With an unrelated `bpf:::open` SDT probe
enabled, another 10,000 UDP datagrams added zero `mbuf_tag` requests;
with `udp:::send` enabled, 10,000 datagrams added exactly 10,000 requests.
A tagged TAP read exported a canonical ID with host 42 and added zero tag
requests. `result-syntheticterm.json` and its serial log record the run.
The first synthetic harness used `SIGINT` to stop a background DTrace
process and stalled; a bounded `timeout` corrected the harness. The
temporary writable node-ID control and boot-time SYSINIT tag test were
then removed from the candidate source and archived in the validation
directory. The clean candidate kernel rebuilt in
`packet-sidecar-buildkernel-final-amd64.log`; a matched QEMU smoke run in
`result-final.json` passed with a 256-byte mbuf zone, native DTrace,
dttransport ownership, and untraced UDP. `vmstat -m` omitted `mbuf_tag`
from both snapshots, meaning it recorded no allocation requests.

The final incremental 16-job amd64 candidate buildworld passed in
`/usr/obj/5BSD-hypertrace-validation/packet-sidecar-buildworld-final-amd64.log`.
The clean candidate also passed 16-job arm64 and RISC-V GENERIC kernel/module
builds (`packet-sidecar-buildkernel-final-arm64.log` and
`packet-sidecar-buildkernel-final-riscv.log`). A rootless arm64 guest boot
with the candidate kernel and reference world passed native DTrace,
immstack(), and the 256-byte mbuf-zone check in
`packet-sidecar-qemu-kernel-only-arm64/result.json`. The same mixed-world
checks passed on RISC-V in `packet-sidecar-qemu-kernel-only-riscv/result.json`.
At that stage, matched-world guest boots for both architectures, tagged
VirtIO/TAP throughput benchmarking, real cross-guest lineage, and live
bhyve remained required before promotion. The synthetic node-ID run proves
local gate and TAP behavior, not a real HyperTrace
VirtIO DTrace session.

The matched arm64 and RISC-V candidate worlds and GENERIC kernels also
booted in rootless QEMU. Each guest reported a 256-byte mbuf zone and
sent 10,000 untraced UDP datagrams without increasing mbuf_tag allocation
requests; native DTrace, KINST, and orderly shutdown passed. Results are
in `/usr/obj/5BSD-hypertrace-validation/cross-kinst-final-qualification.json`.
This extends compile-only architecture coverage to matched runtime smoke
coverage. It does not measure tagged VirtIO/TAP throughput or prove
cross-guest packet provenance, and the experimental worktree remains at
512-byte mbufs.

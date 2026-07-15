# vsock / virtio transport status notes

Status of the bhyve virtio transport with respect to the current virtio
specification (virtio 1.4), written while bringing up AF_VSOCK. Captures the
spec research, an audit of our bhyve virtio code, why our current out-of-spec
vsock device nevertheless works with Linux guests, and the gap list to reach
a conformant virtio 1.4 vsock device.

Researched and written 2026-07-09. Companion docs:
`tests/sys/kern/vsock_bhyve_testplan.md` (e2e test plan),
`share/man/man4/vsock.4`.

Implementation update (2026-07-14): bhyve now has a generic modern PCI
transport backend in `virtio_pci_modern.c`, with vsock as its first consumer.
For upgrade compatibility, vsock continues to default to its existing legacy
identity and transport.  `transport=modern` explicitly selects the conformant
non-transitional identity and capability-based transport.  Historical audit
sections below describe the code before that implementation unless marked as
updated.

---

## 1. Executive summary

- The authoritative current spec is **virtio 1.4, OASIS Committee
  Specification 01, 8 April 2026**. virtio 1.3 never advanced past
  Committee Specification *Draft* (CSD01, Oct 2023); 1.4 is the first full
  CS since 1.2 (July 2022). Cite 1.4 in commits/docs.
- The vsock device section (§5.10, device type 19) is **unchanged from 1.3
  to 1.4** (`git diff v1.3-wd02..v1.4-cs01 -- device-types/vsock/` in the
  spec repo is empty). Our vsock **device logic is already 1.4-complete**:
  we offer exactly the full 1.4 feature set (STREAM/SEQPACKET/
  NO_IMPLIED_STREAM, bits 0–2).
- Before the 2026-07-14 implementation, bhyve provided **only the pre-OASIS
  legacy (virtio 0.9.5) PCI transport** — BAR0 I/O ports, 32-bit features,
  and a 32-bit 4K-aligned queue PFN. The new generic backend adds modern
  vendor capabilities, VIRTIO_F_VERSION_1, 64-bit feature windows,
  queue_enable, and separately addressed split rings. Packed rings and later
  optional transport features remain future work.
- A "legacy-only" device is **not conformant to any 1.x spec** (clause 7.4:
  a device must be transitional or non-transitional), and vsock
  specifically has **no legal transitional identity at all** — our
  transitional-range device ID 0x1013 is invented. It works against Linux
  purely because Linux's probing is more permissive than the spec
  (section 6 below).
- Implemented opt-in state: **non-transitional modern vsock** at device ID
  0x1053, revision ≥ 1, with the capability-based modern transport —
  matching QEMU's modern device. The old interface remains the default solely
  as a compatibility contract. Gap list and implementation details follow.

---

## 2. Spec lineage

| Version | Status / date | Relevant additions |
|---|---|---|
| 0.9.5 "legacy" | Rusty Russell draft, pre-OASIS (2012); superseded by 1.x | I/O-port BAR0 transport, 32-bit features, queue PFN, split ring only |
| 1.0 | OASIS CS01 Dec 2014; errata rollup CS04 Mar 2016 | "Modern" capability-based PCI transport, VIRTIO_F_VERSION_1, 64-bit features, transitional-device concept. **No vsock, no packed ring** |
| 1.1 | CS01 Apr 2019 | **Packed virtqueues**; **first publication of the Socket Device (vsock, §5.10)**; feature bits 33–38 (ACCESS_PLATFORM, RING_PACKED, IN_ORDER, ORDER_PLATFORM, SR_IOV, NOTIFICATION_DATA) |
| 1.2 | CS01 1 Jul 2022 | Bits 39 (NOTIF_CONFIG_DATA), 40 (RING_RESET); common-cfg `queue_notify_data`/`queue_reset`; PCI caps SHARED_MEMORY_CFG (8), VENDOR_CFG (9); **vsock gains F_SEQPACKET**; many new device types (fs, iommu, sound, mem, pmem, …) |
| 1.3 | **CSD01 6 Oct 2023 — draft only, never a full CS** | Device groups (§2.12), admin virtqueues (§2.13) + VIRTIO_F_ADMIN_VQ (41, PCI-only); **vsock gains F_NO_IMPLIED_STREAM (2)** |
| 1.4 | **CS01 8 Apr 2026 — current** | See below |

### What 1.4 added over 1.3 (none of it vsock-specific)

- **VIRTIO_F_SUSPEND (43)** + new device-status bit **SUSPEND (16)**:
  driver-initiated suspend/resume.
- Major **admin-virtqueue expansion**: device capability query/set
  (GET_DEV_CAP/SET_DRIVER_CAP), resource objects, and **"device parts"
  get/set — the device state save/restore building blocks for live
  migration** (common parts 0x0000–0x01FF, device-specific 0x0200–0x05FF).
  vsock defines **no device parts**; its migration state remains
  implementation-defined.
- Bits 41/42 reclassified (42 was a legacy net bit); reserved-for-future
  range now 44–49 and 128+.
- New device types: CAN (5.20), SPI (5.21), Media/V4L2 (5.22), RTC with
  alarms (5.23); IDs reserved through 49 (46 TEE, 47 CPU balloon, 49 USB
  dual-role); ID 50 (unified video codec) queued post-CS01.
- virtio-net: RSS contexts, flow filters, IPsec inline offload, UDP tunnel
  GSO.
- PCI transport itself **essentially unchanged**: only an endianness
  clarification in `virtio_pci_cap64` (`offset_hi`/`length_hi` u32 → le32).
  A new `newtransport.tex` section defines mandatory requirements for
  future transports. The only transport-version bump queued on master
  post-CS01 is **MMIO v3** (async reset), irrelevant to PCI.
- **Legacy interface is NOT deprecated**: "Legacy interface support is
  OPTIONAL. Thus, both transitional and non-transitional devices and
  drivers are compliant with this specification." Direction of travel is
  legacy-guest *emulation* over the admin VQ of a modern SR-IOV PF, not
  restriction.

---

## 3. The two PCI transports (what the spec requires)

### 3.1 Legacy PCI transport (0.9.5; retained normatively in §4.1.4.10, §4.1.5.1.3.1, §6.3)

- Vendor 0x1AF4, device ID **0x1000–0x103F**, **revision ID must be 0**
  (§4.1.2.3). The **virtio device type is carried in the PCI subsystem
  device ID** (subsystem vendor = 0x1AF4).
- BAR0 is an **I/O** region (MMIO not allowed, §4.1.4.10):

  | Offset | Reg | Size |
  |---|---|---|
  | 0x00 | Device (host) features | 32 R — **bits 0–31 only** |
  | 0x04 | Guest (driver) features | 32 RW |
  | 0x08 | Queue address (PFN = phys/4096) | 32 RW |
  | 0x0C | queue_size | 16 R |
  | 0x0E | queue_select | 16 RW |
  | 0x10 | queue_notify | 16 RW |
  | 0x12 | device_status | 8 RW |
  | 0x13 | ISR (read-to-clear) | 8 R |
  | 0x14/0x16 | config/queue MSI-X vector (iff MSI-X) | 16 RW |

  Device-specific config follows, and **moves from offset 20 to 24 when
  MSI-X is enabled**. Ring alignment fixed at 4096; **no queue size
  negotiation** — the driver must use the size the device reports.
- Device-specific config is **guest-native endian** (modern is
  little-endian).
- Legacy-only feature bits (§6.3): NOTIFY_ON_EMPTY (24) MAY be offered;
  **ANY_LAYOUT (27) MUST be offered by transitional devices**; no
  VERSION_1 (its absence is how drivers detect a legacy device, §2.2.3).

### 3.2 Modern PCI transport (§4.1, virtio 1.0+)

- Device ID = **0x1040 + device type** (vsock: 0x1053). Non-transitional
  devices SHOULD have revision ≥ 1 and subsystem device ID ≥ 0x40, "to
  reduce the chance of a legacy driver attempting to drive the device"
  (§4.1.2.1). Drivers MUST match any revision (§4.1.2.2).
- Structures are located by **vendor-specific PCI capabilities**
  (cap_vndr 0x09): `struct virtio_pci_cap { cap_vndr, cap_next, cap_len,
  cfg_type, bar, id, padding[2], le32 offset, le32 length }` with
  cfg_type COMMON_CFG=1, NOTIFY_CFG=2, ISR_CFG=3, DEVICE_CFG=4,
  **PCI_CFG=5 (mandatory, §4.1.4.9)**, SHARED_MEMORY_CFG=8 (1.2+),
  VENDOR_CFG=9 (1.2+). At least one COMMON_CFG and one NOTIFY_CFG MUST be
  present.
- **Common config** (§4.1.4.3, all little-endian, 4-byte-aligned offset):
  `device_feature_select/device_feature/driver_feature_select/
  driver_feature` (le32 ×4 — 64-bit features via 32-bit select windows),
  `config_msix_vector`, `num_queues`, `device_status`,
  `config_generation`, then per-queue via `queue_select`: `queue_size`,
  `queue_msix_vector`, **`queue_enable`**, `queue_notify_off`,
  `queue_desc`/`queue_driver`/`queue_device` (le64 ×3), plus gated fields
  `queue_notify_data` (F_NOTIF_CONFIG_DATA), `queue_reset` (F_RING_RESET),
  `admin_queue_index`/`admin_queue_num` (F_ADMIN_VQ).
- Key device MUSTs (§4.1.4.3.1): status reads back 0 only when reset
  completes; queue_enable 0 on reset; queue_size 0 or power-of-2 (unless
  RING_PACKED); feature-select windows present 0 beyond defined bits and
  echo valid driver bits; 64-bit fields support independent hi/lo 32-bit
  access (§4.1.3.2).
- Notify address = `notify_cap.offset + queue_notify_off *
  notify_off_multiplier` (§4.1.4.4); multiplier 0 (single shared doorbell)
  is legal and simplest.
- ISR byte (§4.1.4.5): bit0 queue, bit1 config change, read clears; INTx
  only, MSI-X paths don't touch it. MSI-X NO_VECTOR = 0xFFFF; device MUST
  read back NO_VECTOR on vector-allocation failure (§4.1.5.1.2.1).

### 3.3 Transitional vs non-transitional (§1.3.1, §4.1.2.3, clause 7.4)

- A conformant implementation **MUST be one or the other** (clause 7.4).
  "Legacy-only" — what bhyve ships — is a 0.9.5-era artifact conformant to
  no 1.x spec.
- **Transitional** device MUST implement **both** transports *and*: device
  ID from the **fixed table** in §4.1.2.1 (net 0x1000, block 0x1001,
  balloon 0x1002, console 0x1003, SCSI 0x1004, entropy 0x1005, 9P 0x1009 —
  the complete list, even in 1.4), revision 0, subsystem device ID =
  device type, ANY_LAYOUT offered, and assume feature bits 32–63
  unacknowledged when driven through the legacy interface.
- **Non-transitional**: 0x1040+type, rev ≥ 1, modern only, and MUST offer
  VIRTIO_F_VERSION_1 (§6.2). §4.1.4.11 suggests (SHOULD) presenting a
  dummy all-zeroes I/O BAR0 so buggy legacy drivers fail gracefully.
- Detection is by **feature bit, not transport**: a transitional driver
  detects a legacy device by VERSION_1 not being offered; a transitional
  device detects a legacy driver by VERSION_1 unacknowledged at
  FEATURES_OK (§2.2.3).

### 3.4 Reserved feature bits (§6, current through 1.4)

| Bit | Name | Since | Requirement |
|---|---|---|---|
| 24 | NOTIFY_ON_EMPTY | legacy | legacy-only, MAY |
| 27 | ANY_LAYOUT | legacy | transitional device MUST offer |
| 28 | RING_INDIRECT_DESC | legacy/1.0 | optional |
| 29 | RING_EVENT_IDX | legacy/1.0 | optional |
| 32 | **VERSION_1** | 1.0 | **device MUST offer (§6.2)**; driver MUST accept if offered; device MAY refuse operation without it |
| 33 | ACCESS_PLATFORM | 1.1 | SHOULD offer if DMA is translated/limited (IOMMU) |
| 34 | RING_PACKED | 1.1 | optional |
| 35 | IN_ORDER | 1.1 | optional |
| 36 | ORDER_PLATFORM | 1.1 | optional |
| 37 | SR_IOV | 1.1 | only with SR-IOV capability |
| 38 | NOTIFICATION_DATA | 1.1 | optional; changes notify write format (§4.1.5.2) |
| 39 | NOTIF_CONFIG_DATA | 1.2 | optional |
| 40 | RING_RESET | 1.2 | optional |
| 41 | ADMIN_VQ | 1.3 | optional, PCI-only |
| 43 | SUSPEND | 1.4 | optional; pairs with status bit SUSPEND (16) |

For a non-transitional device, **only VERSION_1 is mandatory**.

---

## 4. vsock in the spec (§5.10, device type 19)

- First specified in **virtio 1.1** (absent from 1.0 CS04) — vsock
  post-dates the modern transport and was never given a legacy interface.
- Modern PCI device ID **0x1053**. Queues: 0 = rx, 1 = tx, 2 = event.
  Config: `struct virtio_vsock_config { le64 guest_cid; }`, upper 32 bits
  reserved/zero. Reserved CIDs: 0, 1, 0xffffffff, 0xffffffffffffffff;
  CID 2 = well-known host.
- Feature bits (complete list, unchanged 1.3 → 1.4):
  - `VIRTIO_VSOCK_F_STREAM` (0)
  - `VIRTIO_VSOCK_F_SEQPACKET` (1) — 1.2+
  - `VIRTIO_VSOCK_F_NO_IMPLIED_STREAM` (2) — 1.3+; without it SEQPACKET
    implies STREAM support
- **`VIRTIO_VSOCK_F_DGRAM` does not exist.** The datagram effort (Bobby
  Eshleman RFC series, proposed bit 3) stalled: last real revision v6
  (Amery Hung, Jul 2024); Stefano Garzarella declared no bandwidth for v7
  in Jul 2025. The last substantive spec-repo vsock commits are from 2023.
  Do not design around DGRAM arriving soon.
- **No transitional identity exists for vsock**: it is not in the
  §4.1.2.1 fixed transitional ID table, and §5.10 contains zero "Legacy
  Interface" sections — clause 7.4 therefore offers no legacy conformance
  target. A legacy-transport vsock device is **not spec-conformant, full
  stop**. Conformant vsock = non-transitional, 0x1053, rev ≥ 1, modern
  transport, VERSION_1 offered.
- QEMU precedent: `vhost-vsock-pci` registers generic and
  non-transitional variants but **no transitional variant**, and calls
  `virtio_pci_force_virtio_1()` (modern-only) on machine types ≥ 5.1.
- 1.4's migration machinery (admin-VQ device parts) defines **no
  vsock-specific parts**; vsock live-migration state is
  implementation-defined.

---

## 5. Where our tree is (audit, 2026-07)

### 5.1 bhyve host side: legacy transport only

Core transport is `usr.sbin/bhyve/virtio.c` / `virtio.h`, which include
the *legacy* register header (`dev/virtio/pci/virtio_pci_legacy_var.h`,
virtio.c:35).

- `vi_set_io_bar()` (virtio.c:126) allocates BAR0 as `PCIBAR_IO` sized
  `VIRTIO_PCI_CONFIG_OFF(1) + vc_cfgsize`. `vi_pci_read`/`vi_pci_write`
  (virtio.c:564–816) dispatch on the legacy `config_regs[]` table
  (virtio.c:520–536): HOST/GUEST_FEATURES, QUEUE_PFN/NUM/SEL/NOTIFY,
  STATUS (write 0 → `vc_reset`), ISR (read-to-clear + lintr deassert),
  MSI config/queue vector regs. Device config offset shifts by 4 with
  MSI-X enabled, classic legacy behavior (virtio.c:596–614, 716–733).
- **No modern code at all**: grep for `VIRTIO_PCI_CAP`, `common_cfg`,
  `notify_off`, `VERSION_1`, `queue_enable`, `RING_PACKED`, `cfg_type`
  across bhyve → zero code hits (one explanatory comment at virtio.h:176).
  No `#ifdef`/TODO scaffolding either.
- **Features are 32-bit**: `vs_negotiated_caps` is `uint32_t`
  (virtio.h:247); HOST/GUEST_FEATURES are 4-byte legacy regs, so feature
  bit 32 (VERSION_1) is unreachable by construction. (`vc_hv_caps` is
  already `uint64_t`, virtio.h:280, but only the low word is exposed.)
- **Virtqueues**: split ring only; `vi_vq_init()` (virtio.c:176) takes the
  32-bit PFN (`phys = pfn << 12`, VRING_ALIGN 4096; `vq_pfn` is uint32_t,
  virtio.h:320). EVENT_IDX supported (`vq_endchains`, virtio.c:503–510);
  indirect descriptors supported with validation (`vq_getchain`,
  virtio.c:331–383: negotiation-gated, rejects nested indirect, bounds- and
  `len % 16`-checked, 512-descriptor loop guard). NOTIFY_ON_EMPTY
  handled (virtio.c:500–502).
- **Interrupts**: INTx via `vs_isr` byte + `pci_lintr_assert`, read of ISR
  clears and deasserts (virtio.c:656–661); MSI-X with one vector per queue
  plus a config vector (`nvec = vc_nvq + 1`, virtio.c:156), programmed via
  the legacy VIRTIO_MSI_* regs (virtio.c:797–805).

### 5.2 Per-device inventory (host)

All PCI IDs from virtio.h:164–180; vendor 0x1AF4; subsystem device ID =
virtio device type (legacy convention).

| Device model | Dev ID | Subdev (type) | Features offered |
|---|---|---|---|
| pci_virtio_net.c | 0x1000 | 1 | MAC, STATUS, NOTIFY_ON_EMPTY, RING_INDIRECT_DESC; runtime MTU, MRG_RXBUF |
| pci_virtio_block.c | 0x1001 | 2 | SEG_MAX, BLK_SIZE, FLUSH, TOPOLOGY, RING_INDIRECT_DESC; runtime DISCARD |
| pci_virtio_console.c | 0x1003 | 3 | SIZE, MULTIPORT, EMERG_WRITE |
| pci_virtio_scsi.c | 0x1004 | 8 | RING_INDIRECT_DESC |
| pci_virtio_rnd.c | 0x1005 | 4 | none |
| pci_virtio_9p.c | 0x1009 | 9 | MOUNT_TAG |
| pci_virtio_input.c | 0x1052, rev 1, subven 0x108E, subdev 0x1100 | — | none |
| pci_virtio_vsock.c | **0x1013** | 19 | STREAM (0), SEQPACKET (1), NO_IMPLIED_STREAM (2) |

vsock specifics (pci_virtio_vsock.c:3007–3106): class SIMPLECOMM,
subclass 0x80 ("other", so serial drivers stop probing), 3 queues with
per-queue notify, MSI-X on BAR 1, same legacy I/O BAR0 path as every other
device. Commit df28995f11f deliberately moved vsock from modern 0x1053 to
transitional-range **0x1013** because at 0x1053 the guest bound
`virtio_pci_modern`, which then failed on our missing capability
structures and the driver never attached. Note 0x1013 (= 0x1000 + 19 by
analogy) is **not in the spec's transitional table** — it's invented.

Feature-bit definitions live in `sys/sys/vsock.h:84–94`. Note
`VIRTIO_VSOCK_F_NO_IMPLIED_STREAM` (bit 2) there matches the **standard**
virtio 1.3/1.4 bit — same number, same semantics (it is not a local
invention, despite originating locally). Our vsock feature set is exactly
the full 1.4 set.

### 5.3 Guest side: already dual-transport

`sys/dev/virtio/pci/` has **both** `virtio_pci_legacy.c` (probes
0x1000–0x103F, rev 0, type from subsystem ID; virtio_pci_legacy.c:198)
and `virtio_pci_modern.c` (probes 0x1040–0x107F, unconditionally sets
VIRTIO_F_VERSION_1 in child features; virtio_pci_modern.c:259, 442). The
guest vsock driver (`sys/dev/virtio/vsock/virtio_vsock.c`) binds by
device *type* 19, so it attaches through either transport. **A modern
bhyve transport is therefore immediately testable against our own guest.**

---

## 6. Why our out-of-spec vsock works on Linux (and its limits)

- Linux `vp_legacy_probe()` (drivers/virtio/virtio_pci_legacy_dev.c)
  accepts **any** vendor-0x1AF4 device with ID in 0x1000–0x103F and
  revision 0 — it does **not** check the spec's fixed transitional table —
  and takes the virtio type from the subsystem device ID. Our 0x1013 /
  subdev 19 therefore binds virtio_pci_legacy → virtio_vsock.
- Linux's vsock class driver (net/vmw_vsock/virtio_transport.c) matches
  `{ VIRTIO_ID_VSOCK, VIRTIO_DEV_ANY_ID }`, has **no VERSION_1
  requirement and no validate callback**, and its feature table negotiates
  **only SEQPACKET (bit 1)** — STREAM is assumed, NO_IMPLIED_STREAM is
  never negotiated. It runs happily over a legacy transport.
- Endianness lines up **by accident of architecture**: legacy
  device-config space is guest-native-endian while vsock packet headers
  are defined little-endian; these coincide on amd64. A big-endian guest
  over legacy vsock is undefined territory.
- Linux is permissive in the other direction too: `vp_modern_probe()`
  accepts 0x1000–0x107F with no revision check (ID < 0x1040 → type from
  subsystem ID). So "works on Linux" tells you nothing about conformance;
  stricter guests (or future Linux tightening) may reject us. QEMU sets
  the de facto ecosystem expectation that vsock is modern-only.

## 6.1 Other spec holes / ecosystem gaps worth remembering

- **Linux never negotiates STREAM (0) or NO_IMPLIED_STREAM (2)** — a
  SEQPACKET-only device cannot actually communicate stream-absence to a
  Linux guest; our NO_IMPLIED_STREAM offer is spec-correct but a no-op
  against Linux today.
- **Legacy has no queue-size negotiation** (§4.1.5.1.3.1) — guests must
  live with whatever size we report; the modern transport removes this.
- **No DGRAM** in spec or Linux (stalled, see §4); AF_VSOCK datagram
  semantics remain hyperv/vmci-only territory upstream.
- **vsock has no defined live-migration state** even in 1.4's device-parts
  framework.
- The OASIS TC landing page is stale (still announces 1.2);
  docs.oasis-open.org and the GitHub repo are authoritative.

---

## 6.2 FreeBSD Unix-socket SEQPACKET relay traps (host side)

The host device relays vsock SEQPACKET over a Unix `SOCK_SEQPACKET`
socketpair. FreeBSD's Unix-socket SEQPACKET semantics differ from Linux's
in four ways that each produced (or hid) a real bug — verified empirically
2026-07-09 with direct syscall tests and a Linux (Alpine) guest. Anyone
touching `vtvsock_conn_data_cb` / `vtvsock_rx_inject_frags` must respect
these:

1. **`recvmsg(MSG_PEEK|MSG_TRUNC)` returns bytes COPIED, not datagram
   length.** With a 1-byte probe iov it returns `1` for *every* record
   (Linux returns the full record length). Sizing a read from that probe
   truncates to 1 byte. **Use `FIONREAD` to size SEQPACKET reads** (the
   STREAM path already did). This was the host→guest "1-byte shred" bug.

2. **A short SEQPACKET read does NOT discard the tail.** Reading 1 byte of a
   17-byte record leaves 16 bytes queued (Linux/POSIX discard the remainder
   and set `MSG_TRUNC`). Combined with (1), a record was not merely
   truncated but shredded into N one-byte records — invisible to
   byte-stream test tools (which concatenate) and to the device harness
   (which mocks `recv` with Linux semantics). Only a record-oriented
   receiver (Linux `recv`, one record per call) exposes it.

3. **Record boundary = `MSG_EOR`, not the write() call.** Two plain
   `write()`s without `MSG_EOR` COALESCE into one record; a record can also
   span multiple reads if it exceeds `SO_SNDBUF` (default 64 KiB). The
   device treats each read as a record (EOM on read end), which is correct
   only when a record is sent as one `send()` that fits the 64 KiB
   socketpair buffer. Larger/dribbled records split. See the "Host
   application contract" block in `pci_virtio_vsock.c`.

4. **Zero-length SEQPACKET sends are dropped.** `sendmsg("",0,MSG_EOR)`
   returns 0 but queues nothing (`FIONREAD`=0, peek=EAGAIN). The
   empty-record inject path is therefore unreachable dead code on FreeBSD;
   kept for portability to systems that do queue empty records.

**Sizing/window numbers (measured):** Linux guest advertises `buf_alloc` =
256 KiB (default AND max via `SO_VM_SOCKETS_BUFFER_SIZE`); our device
advertises 256 KiB to match; the relay socketpair `SO_SNDBUF`/`SO_RCVBUF`
is the FreeBSD default 64 KiB and is the binding host→guest single-record
ceiling. Guest→host reassembles to 4 MiB (`VTVSOCK_MAX_PEER_BUF_ALLOC`).

---

## 7. Gap list: legacy-only → conformant virtio 1.4 vsock

The spec offers no middle ground (clause 7.4), and vsock cannot be
transitional (§4), so the target is **non-transitional modern-only**.
Work lands in `usr.sbin/bhyve/virtio.c`/`virtio.h` (transport core) and
`pci_virtio_vsock.c` (identity); other device models can stay legacy or
later opt into true transitional (both transports) once the modern core
exists.

1. **Modern PCI capability plumbing**: emit vendor caps (0x09) for
   COMMON_CFG, NOTIFY_CFG, ISR_CFG, DEVICE_CFG in a memory BAR, plus the
   **mandatory PCI_CFG window cap** (§4.1.4.9) with its
   config-space-window read/write semantics.
2. **Common config structure** (§4.1.4.3): feature select windows,
   num_queues, device_status, config_generation, and the per-queue block
   (size / msix_vector / **enable** / notify_off / desc / driver / device).
   Little-endian, correct read-back rules (reset completion, queue_enable
   clearing, out-of-range selects present 0).
3. **64-bit feature negotiation**: widen `vs_negotiated_caps` and the
   negotiation path to 64-bit; keep the low-32 window for the legacy path.
4. **Offer VIRTIO_F_VERSION_1 (bit 32)** — the only mandatory bit; a
   modern-only device MAY refuse FEATURES_OK without it.
5. **Modern virtqueue init**: 64-bit desc/avail/used addresses +
   queue_enable replacing the PFN path; independent hi/lo 32-bit access to
   64-bit fields; per-queue notify offsets (multiplier 0 = one shared
   doorbell is legal and simplest).
6. **vsock PCI identity**: device ID **0x1053**, revision **≥ 1**,
   subsystem device ID ≥ 0x40; retire the 0x1013 hack. Optionally the
   §4.1.4.11 dummy zeroed I/O BAR0 for buggy legacy drivers.
7. Optional/deferrable (all spec-optional): packed ring (34),
   NOTIFICATION_DATA (38), RING_RESET (40), ACCESS_PLATFORM (33),
   SUSPEND (43), ADMIN_VQ (41). Already have: EVENT_IDX (29),
   RING_INDIRECT_DESC (28).

Interim position (what we ship today) is intentional and documented in
commit df28995f11f: legacy identity 0x1013 so guests attach via the
legacy transport. It works against Linux and our own guest, but is
out-of-spec and should be treated as a bridge, not an endpoint.

---

## 8. Detailed build specification (modern transport)

Written against the actual normative text of virtio 1.4 CS01
`transport-pci.tex` (spec repo tag `v1.4-cs01`) and the current bhyve
code. Section references are to 1.4 §4.1. Design target: **modern-only
(non-transitional) vsock**, with the transport core written so other
device models can later become genuinely transitional.

### 8.1 Design decisions

1. **vsock is modern-only.** No legal transitional identity exists (§4);
   QEMU precedent agrees. Other devices keep legacy BAR0 untouched for
   now; the modern core is opt-in per device.
2. **One 64-bit memory BAR** holds all four structures (QEMU-style
   region layout), located by vendor capabilities:

   | BAR offset | Structure | Length |
   |---|---|---|
   | 0x0000 | common cfg | 56 (through `queue_device`; gated fields omitted — they exist only if NOTIF_CONFIG_DATA / RING_RESET / ADMIN_VQ negotiated, which we don't offer) |
   | 0x1000 | ISR status | 1 |
   | 0x2000 | device-specific cfg | `vc_cfgsize` |
   | 0x3000 | notify | 4 |

   BAR index: 2 (BAR 1 stays MSI-X as today; BAR 0 left unallocated for
   modern-only devices, or optionally the §4.1.4.11 dummy I/O BAR).

   **Cross-checked against QEMU** (hw/virtio/virtio-pci.c:2215–2233):
   QEMU uses legacy_io_bar 0 / msix_bar 1 / modern_mem_bar 4 with
   common at 0x0000, ISR at 0x1000, device at 0x2000, notify at 0x3000
   (each region sized 0x1000) — the same layout as ours modulo BAR
   index. bhyve's `pci_emul_alloc_bar(..., PCIBAR_MEM64, ...)` is
   already exercised by pci_nvme.c and pci_passthru.c, so no new BAR
   infrastructure is needed.
3. **`notify_off_multiplier = 0`** — explicitly legal ("the device uses
   the same Queue Notify address for all queues", §4.1.4.4 note). All
   queues share one 2-byte doorbell; the written value is the vq index,
   which is exactly today's `VIRTIO_PCI_QUEUE_NOTIFY` dispatch
   (virtio.c:776–791). `queue_notify_off` reads as 0 for every queue.
   Device MUSTs satisfied: cap.offset 2-byte aligned; multiplier 0;
   cap.length ≥ queue_notify_off*mult + 2 → length 4 ok (§4.1.4.4.1).
   (QEMU defaults to multiplier 4 with `queue_notify_off = vq index`,
   i.e. per-queue doorbells 4 bytes apart, virtio-pci.c:363–368 and
   2082; Linux bounds-checks `off*mult + 2 <= notify.length` either way,
   virtio_pci_modern_dev.c:715. Multiplier 0 is the simpler start;
   per-queue doorbells are a compatible later optimization — only the
   cap contents change, no driver-visible ABI break.)
4. **Features offered (modern path)**:
   `VIRTIO_F_VERSION_1 (32) | VIRTIO_RING_F_INDIRECT_DESC (28) |
   VIRTIO_RING_F_EVENT_IDX (29) | device bits`. Do NOT offer
   NOTIFY_ON_EMPTY (24) or ANY_LAYOUT (27) on the modern path — both are
   legacy-interface bits (§6.3). Ring code (vq_getchain / vq_endchains)
   already handles 28/29 and is ring-layout-identical under VERSION_1.
5. Not offered initially (all optional): RING_PACKED (34),
   NOTIFICATION_DATA (38), NOTIF_CONFIG_DATA (39), RING_RESET (40),
   ACCESS_PLATFORM (33), SUSPEND (43), ADMIN_VQ (41).

### 8.2 PCI config space: capabilities to emit

Emitted at device init via `pci_emul_add_capability()` (pci_emul.c:1088),
after the MSI-X cap. Five caps, cap_vndr 0x09 (§4.1.4 struct
virtio_pci_cap, all fields LE):

| # | cfg_type | bar | offset | length | extra |
|---|---|---|---|---|---|
| 1 | COMMON_CFG (1) | 2 | 0x0000 | 56 | — |
| 2 | NOTIFY_CFG (2) | 2 | 0x3000 | 4 | `le32 notify_off_multiplier = 0` (20-byte cap) |
| 3 | ISR_CFG (3) | 2 | 0x1000 | 1 | — |
| 4 | DEVICE_CFG (4) | 2 | 0x2000 | vc_cfgsize | — |
| 5 | PCI_CFG (5) | — | RW | RW | `u8 pci_cfg_data[4]` (20-byte cap) |

MUSTs: at least one COMMON_CFG (§4.1.4.3.1), one NOTIFY_CFG
(§4.1.4.4.1), one ISR_CFG (§4.1.4.5.1), one DEVICE_CFG if the device has
device config (§4.1.4.6 — vsock does: guest_cid), **one PCI_CFG
(§4.1.4.9.1)**. `cap_len` must include the extra fields. Common-cfg and
device-cfg offsets MUST be 4-byte aligned; our 0x1000 spacing
over-satisfies everything.

**PCI_CFG is the only cap with runtime behavior**: `cap.bar`,
`cap.offset`, `cap.length`, `pci_cfg_data` are driver-writable, and a
read/write of `pci_cfg_data` MUST execute the corresponding BAR access
(§4.1.4.9.1). bhyve plumbing: `pci_emul_capwrite()` (pci_emul.c:1385)
currently special-cases only MSI/MSI-X caps — extend it (or the
`pe_cfgwrite`/`pe_cfgread` handlers, pci_emul.h:66–69) to dispatch
vendor-cap accesses to a new `vi_pci_cfg_cap_rw()` that validates
bar/offset/length (1, 2 or 4; offset aligned to length) and forwards to
`vi_pci_read`/`vi_pci_write`. Reject/ignore accesses outside regions
declared by the other caps (driver-normative, but don't trust the
driver).

### 8.3 Data-structure changes (virtio.h)

```
struct virtio_softc:
  uint32_t vs_negotiated_caps remains unchanged; modern high feature bits
  live in the transport's uint64_t driver_features field
+ uint32_t vs_device_feature_select
+ uint32_t vs_driver_feature_select
+ uint8_t  vs_config_generation                    [static 0 for vsock]
+ new vs_flags bit: VIRTIO_MODERN (device model opted into modern core)

struct vqueue_info:
+ uint64_t vq_desc_gpa, vq_driver_gpa, vq_device_gpa
+ uint16_t vq_enabled
+ uint16_t vq_qsize_max                            [device default; vq_qsize
                                                    becomes the driver-set
                                                    current size]
  (vq_pfn stays for the legacy path)

virtio.h IDs:
+ #define VIRTIO_DEV_MODERN(type)  (0x1040 + (type))   /* vsock -> 0x1053 */
```

Constants for cfg_type / common-cfg offsets already exist guest-side in
`sys/dev/virtio/pci/virtio_pci_modern_var.h` — include that instead of
redefining (mirrors how virtio.c:35 includes the legacy header today).

### 8.4 Common config: field-by-field semantics (§4.1.4.3)

New `vi_common_cfg_read/write(vs, offset, size, value)` dispatched from
`vi_pci_read/write` when `baridx == modern bar && offset < 0x1000`.
Access-width rule (§4.1.3.1/4.1.3.2): accept 1/2/4-byte accesses per
field width; 64-bit fields MUST support independent lo/hi 32-bit access
— i.e. treat `queue_desc..queue_device` as six le32 registers.

| Off | Field | Semantics / normative requirements |
|---|---|---|
| 0x00 | device_feature_select (RW) | store; no side effect |
| 0x04 | device_feature (RO) | `sel==0` → low 32 of hv_caps; `sel==1` → high 32 (includes bit 32 VERSION_1); **`sel>=2` → 0** (MUST, §4.1.4.3.1) |
| 0x08 | driver_feature_select (RW) | store |
| 0x0C | driver_feature (RW) | write: merge into `vs_negotiated_caps` window masked by hv_caps; read: MUST present valid bits previously written (mask-at-write satisfies "MAY present invalid bits" latitude). Call `vc_apply_features` at FEATURES_OK, not per-write |
| 0x10 | config_msix_vector (RW) | maps to `vs_msix_cfg_idx`; read MUST return mapped vector or NO_VECTOR (0xFFFF); MUST be unmapped after reset (vi_reset_dev already does, virtio.c:120) |
| 0x12 | num_queues (RO) | `vc_nvq` |
| 0x14 | device_status (RW) | see 8.7 reset/status |
| 0x15 | config_generation (RO) | `vs_config_generation`; MUST change after any device-config change a driver could have half-read. vsock guest_cid is constant → constant 0 is conformant. Device models that mutate config (net status/MTU) must bump it under the softc lock |
| 0x16 | queue_select (RW) | `vs_curq`; out-of-range select is legal — all per-queue fields then read 0 (queue_size MUST read 0 for unavailable queue) |
| 0x18 | queue_size (RW) | reads `vq_qsize` (0 if unavailable); writable to shrink: accept powers of 2 ≤ `vq_qsize_max`, ignore invalid writes (driver MUST NOT write them; device MUST present 0-or-power-of-2) |
| 0x1A | queue_msix_vector (RW) | `vq_msix_idx`; NO_VECTOR echo rules as config vector |
| 0x1C | queue_enable (RW) | write 1 → validate + map rings (8.5); MUST read 0 on reset; driver MUST NOT write 0 (ignore if it does) |
| 0x1E | queue_notify_off (RO) | 0 (multiplier-0 design) |
| 0x20–0x37 | queue_desc/driver/device (RW, le64 as 2×le32) | store GPAs; consumed at queue_enable |

### 8.5 Modern virtqueue init (replaces PFN path)

New `vi_vq_init_modern(vs, vq)` called on `queue_enable = 1`:
map the three areas independently via `paddr_guest2host()` —
`vq_desc` (16×qsize bytes), `vq_avail` (6 + 2×qsize bytes),
`vq_used` (6 + 8×qsize bytes). `vq_desc/vq_avail/vq_used` are already
three independent pointers filled from a contiguous block today
(virtio.c:191–202), so this is mechanical. Modern alignment minimums
(desc 16 / avail 2 / used 4, spec §2.6) replace the 4096 legacy
alignment — validate and refuse enable (leave queue_enable reading 0 +
set DEVICE_NEEDS_RESET) on garbage. Everything downstream
(vq_getchain, vq_relchain*, vq_endchains, EVENT_IDX, indirect) is
unchanged: split-ring layout is identical under VERSION_1.

### 8.6 Notify and interrupts

- Doorbell: 2-byte write at BAR2+0x3000; value = vq index → reuse the
  existing QUEUE_NOTIFY dispatch body (virtio.c:776–791).
- ISR byte at BAR2+0x1000: reuse `vs_isr` read-to-clear + lintr deassert
  (virtio.c:656–661). Bit 0 = queue, bit 1 = config change; MUST reset
  to 0 on read; with MSI-X enabled the device MUST NOT rely on it
  (existing `vi_interrupt` split already correct, virtio.h:359–372).
- Config-change notification: add `vi_config_changed(vs)` helper = bump
  `vs_config_generation`, set ISR bit 1 / fire `vs_msix_cfg_idx`
  (§4.1.5.4). vsock never needs it, net will.
- MSI-X: `config_msix_vector`/`queue_msix_vector` live in common cfg
  instead of legacy BAR0 regs; semantics identical to today's
  VIRTIO_MSI_* handling (virtio.c:797–805). We never fail vector
  mapping, so the echo-on-read behavior we have satisfies the
  NO_VECTOR failure-reporting MUST (§4.1.5.1.2.1).

### 8.7 Status and reset semantics (§2.1, §4.1.4.3.1)

- Write 0 to `device_status` → `vc_reset` + `vi_reset_dev()`, and the
  read MUST return 0 only once reset completes — our reset is
  synchronous under the softc lock, so read-after-write is trivially
  correct. Extend `vi_reset_dev()` (virtio.c:97) to also clear:
  feature selects, `vq_enabled`, the three GPAs, and driver-shrunk
  `vq_qsize` back to `vq_qsize_max`.
- FEATURES_OK handling (new for modern): on status write containing
  FEATURES_OK, verify `VIRTIO_F_VERSION_1` was accepted; if not, do not
  latch FEATURES_OK (device "MAY fail to operate" without VERSION_1,
  §6.2 — QEMU's forced-virtio-1 behaves this way). This is where
  `vc_apply_features` moves (from the legacy GUEST_FEATURES write,
  virtio.c:757–762).
- DEVICE_NEEDS_RESET (bit 6) becomes settable by the transport on fatal
  ring errors — today's `EPRINTLN + return -1` paths in vq_getchain are
  the natural producers.

### 8.8 vsock device model changes (pci_virtio_vsock.c)

- Identity: `PCIR_DEVICE = 0x1053` (VIRTIO_DEV_MODERN(19)),
  `PCIR_REVID = 1`, subsystem device ID ≥ 0x40 (use 0x0053), keep
  vendor/subvendor 0x1AF4 and class SIMPLECOMM/0x80. Delete the 0x1013
  block and the virtio.h:173–180 comment.
- Replace `vi_set_io_bar(&sc->vsc_vs, 0)` with new
  `vi_set_modern_bar(&sc->vsc_vs, 2)`; keep `vi_intr_init(..., 1, ...)`
  (MSI-X stays on BAR 1).
- hv_caps |= VERSION_1 | INDIRECT_DESC | EVENT_IDX (device bits 0–2
  unchanged). Device config (`vsc_config.guest_cid`, le64) is already
  independently hi/lo accessible via the existing 4-byte `vc_cfgread`
  path — satisfies §4.1.3.2.1.
- Guest fallout — **resolved with a transport knob**: our guest binds
  `virtio_pci_modern` (0x1040–0x107F, virtio_pci_modern.c:259) which
  requires exactly the caps we now emit; Linux `vp_modern_probe`
  likewise. To avoid stranding old guests that only carry a legacy
  driver, keep the current 0x1013 identity available behind a
  device config option (bhyve config nvlist, like the existing vsock
  options): `-s N,virtio-vsock,cid=C,transport=modern|legacy`,
  default `legacy`. The legacy path is the existing code and PCI identity,
  unchanged and still out-of-spec. Modern behavior is opt-in, so existing
  launchers and guests do not change behavior during an upgrade.

### 8.9 Device-normative conformance checklist

Every device MUST from 1.4 §4.1 that applies to this design, with its
discharge point:

| MUST (§) | Discharged by |
|---|---|
| vendor 0x1AF4, ID 0x1040+type (4.1.2.1) | 8.8 identity |
| ≥1 cap of each: common/notify/ISR/device/PCI_CFG (4.1.4.*) | 8.2 |
| cap_len covers extra data (4.1.4.1) | 8.2 (20-byte notify + pci_cfg caps) |
| common cfg offset 4-aligned (4.1.4.3.1) | 8.2 layout |
| feature windows: present offered bits per select, 0 beyond; echo valid driver bits (4.1.4.3.1) | 8.4 rows 0x04/0x0C |
| config_generation changes on half-read config change (4.1.4.3.1) | 8.4/8.6 (constant for vsock) |
| reset on status=0, read 0 when done (4.1.4.3.1) | 8.7 |
| queue_enable 0 on reset (4.1.4.3.1) | 8.7 |
| queue_size 0 if unavailable; 0-or-power-of-2 (4.1.4.3.1) | 8.4 rows 0x16/0x18 |
| 64-bit fields: independent hi/lo access (4.1.3.2.1) | 8.4 le32-pair dispatch; 8.8 cfgread |
| notify: offset 2-aligned, multiplier 0-or-even-pow2, length ≥ off*mult+2 (4.1.4.4.1) | 8.1 item 3 |
| ISR: set bits before notifying, INTx OR-rule, reset-on-read (4.1.4.5.1) | 8.6 |
| device cfg offset 4-aligned (4.1.4.6.1) | 8.2 layout |
| PCI_CFG: execute BAR access on pci_cfg_data r/w (4.1.4.9.1) | 8.2 vi_pci_cfg_cap_rw |
| MSI-X: NO_VECTOR echo/failure, unmapped on reset, map/unmap any event (4.1.5.1.2.1) | 8.6; vi_reset_dev |
| no interrupt when vector NO_VECTOR (4.1.5.3.1/4.1.5.4.1) | existing vi_interrupt + guard |
| VERSION_1 offered (6.2) | 8.8 hv_caps |

### 8.11 Test hooks

- `tests/sys/kern/vsock_device_harness/` already compiles the bhyve
  device model against stub `pci_emul.h`/`virtio.h` — extend stubs with
  the capability API and add cases: capability-chain walk, feature
  windows (select 0/1/2), queue_enable lifecycle, status reset
  read-back, PCI_CFG window access, ISR read-to-clear.
- e2e (see `vsock_bhyve_testplan.md`): 5BSD guest must now attach via
  `virtio_pci_modern`; Linux guest via `vp_modern_probe`. Negative
  test: legacy-only guest driver must NOT attach to the 0x1053 device.

## 9. Feasibility: reference implementations

Verified against downloaded copies of the Linux driver side and the QEMU
device side (working copies in the session scratchpad under `refimpl/`;
canonical URLs in §14). **Licensing note: Linux and QEMU are GPLv2.
These are behavioral references only — do not copy code into this tree.
The implementation is written from the OASIS spec (§8); the references
are for verifying our behavior against what real drivers demand.**

### 9.1 What Linux actually requires to attach (driver side)

`drivers/virtio/virtio_pci_modern_dev.c: vp_modern_probe()` (line 223):

- Device ID 0x1000–0x107F, vendor 0x1AF4 (no revision check).
- **Hard-required capabilities**: COMMON_CFG (line 256), ISR_CFG (266),
  NOTIFY_CFG (269) — probe fails with -EINVAL if any is missing.
  DEVICE_CFG (290) is optional at the transport level, but vsock needs
  it (the class driver reads `guest_cid` from device config).
- **PCI_CFG is never used by Linux** — it maps BARs directly. The
  PCI_CFG window is still a device-side MUST (§4.1.4.9.1) and our own
  guest/other drivers may use it, but a bug there won't block Linux
  bring-up; it can be validated by unit tests rather than guest debug.
- Notify: reads `notify_off_multiplier` from the cap and bounds-checks
  `queue_notify_off * multiplier + 2 <= notify cap length` per queue
  (line 715) — our multiplier-0/length-4 choice passes trivially.
- VERSION_1: the virtio core refuses to finalize a modern-transport
  device that doesn't offer it — offering bit 32 is what makes Linux
  proceed.
- The vsock class driver on top negotiates only SEQPACKET (§6.1 of this
  doc) — nothing else changes for it; the transport swap is invisible
  above the virtio core.

Our own guest (`sys/dev/virtio/pci/virtio_pci_modern.c`) has the same
shape: probes 0x1040–0x107F (line 259), requires the cap structures
(finds COMMON_CFG at lines 733/791), unconditionally negotiates
VERSION_1 (line 442). So both target guests attach given exactly the
§8.2 capability set — the design is sufficient, not just necessary.

### 9.2 What QEMU does (device side, the de facto reference)

`hw/virtio/virtio-pci.c`:

- Region layout identical to §8.1 (lines 2215–2233); modern BAR is a
  prefetchable MEM64 sized `pow2ceil(notify.offset + notify.size)`
  (line 2243).
- Caps emitted via `virtio_pci_add_mem_cap()` (1433) — a generic
  "append vendor cap" helper, same role as our
  `pci_emul_add_capability()`.
- **PCI_CFG window** (lines 823–858): QEMU's PCI config-space write/read
  hook detects accesses hitting `pci_cfg_data` within the stored
  config cap and forwards them to the BAR address space with the
  driver-written bar/offset/length — precisely the §8.2
  `vi_pci_cfg_cap_rw()` design, so that design is proven, not novel.
- vsock variant (`hw/virtio/vhost-vsock-pci.c`) forces virtio-1
  (modern-only) — the identity/feature choices in §8.8 match the
  reference exactly.

### 9.3 bhyve-side feasibility checklist

| Needed | Exists? |
|---|---|
| MEM64 BARs | yes — `PCIBAR_MEM64` used by pci_nvme.c, pci_passthru.c |
| arbitrary capability chains | yes — `pci_emul_add_capability()` (pci_emul.c:1088) |
| config-space write interception | yes — `pci_emul_capwrite()` (pci_emul.c:1385) + per-device `pe_cfgwrite/pe_cfgread` (pci_emul.h:66); needs the vendor-cap dispatch added |
| per-BAR read/write dispatch | yes — `pe_barwrite`/`pe_barread` already route by baridx; `vi_pci_read/write` just needs the modern-BAR branch |
| separate desc/avail/used mappings | yes — already three pointers (virtio.c:191–202) |
| unit-test harness for the device model | yes — `tests/sys/kern/vsock_device_harness` compiles the real `pci_virtio_vsock.c` against mock headers |

Conclusion: **no missing infrastructure**. The work is additive code in
`virtio.c`/`virtio.h`, one dispatch hook in `pci_emul.c`, and identity
changes in `pci_virtio_vsock.c`.

## 10. Test suite

Layered like the existing vsock tests (`tests/sys/kern/`), extending
rather than replacing them. Everything below is host-side testable
except the e2e matrix.

### 10.1 Unit: transport conformance (extend `vsock_device_harness`)

The harness already `#include`s the real `pci_virtio_vsock.c` with
mocked bhyve headers (tests/sys/kern/Makefile:61–78), so transport
behavior is testable as plain ATF C without a VM. Extend the mock
`pci_emul.h` with the capability API and add a `virtio_modern_test.c`
(ATF_TESTS_C in the same Makefile). Cases, each tied to the §8.10
checklist row it proves:

- **Capability chain**: walk config space from the cap pointer; assert
  the five caps exist, cfg_types/bar/offset/length match §8.2,
  `cap_len` covers the notify/pci_cfg extra fields.
- **Feature windows**: select 0 → device bits 0–2 + ring bits;
  select 1 → bit 32 set; select 2, 3, 0xFFFF → 0. Write driver
  features with invalid (unoffered) bits → readback shows only valid
  bits.
- **Status lifecycle**: ACKNOWLEDGE → DRIVER → FEATURES_OK with
  VERSION_1 accepted → latched; without VERSION_1 → FEATURES_OK reads
  back clear. DRIVER_OK ordering. Write 0 at every stage → full reset,
  immediate readback 0.
- **Queue plumbing**: num_queues == 3; queue_select out of range →
  queue_size 0; queue_size shrink to smaller power of 2 accepted,
  non-power-of-2 / larger-than-max ignored; queue_enable readback;
  64-bit queue_desc written as two dwords in both orders reads back
  whole.
- **Ring mapping**: enable with valid GPAs → doorbell + a real
  RX/TX packet round-trip through the existing harness data path;
  enable with unaligned or out-of-range GPAs → queue stays disabled,
  DEVICE_NEEDS_RESET set, process survives.
- **Reset semantics**: after device reset: queue_enable 0, GPAs 0,
  vectors NO_VECTOR, features 0, shrunk queue_size restored to max.
- **ISR**: set by queue + config events; read returns then clears;
  second read 0.
- **PCI_CFG window**: read/write of each region through the window
  matches direct BAR access; misaligned offset (not multiple of
  length), length ∉ {1,2,4}, reserved bar → ignored/all-ones, no
  crash. (Linux never exercises this — unit tests are the only
  coverage it gets. Same for the multiplier-0 notify bounds.)
- **MSI-X**: vector write/readback, NO_VECTOR default after reset,
  no interrupt delivered for NO_VECTOR queues.
- **Hostile-driver fuzz**: bounded-random register writes (all
  offsets/sizes/values, seeds logged for replay) against the common
  cfg, notify, PCI_CFG window; invariants: no crash, no ring mapping
  without valid enable, `desc__drop`-style rejection paths fire. This
  mirrors the existing harness's hostile-guest-input philosophy
  (vsock_provider.d "Security" probes).
- **Legacy knob**: `transport=legacy` still produces the 0x1013
  identity + BAR0 layout (regression-pins the compat path).

### 10.2 Integration: wire and socket tests (existing suites, new matrix)

`vsock_test`, `vsock_wire_test`, `vsock_iov_test` currently run against
the legacy device. Parameterize `run_vsock_tests.sh` to run the full
socket/wire suite twice: `transport=modern` and `transport=legacy`.
The wire format (virtio_vsock packets) is transport-independent, so
identical results are the pass criterion.

### 10.3 End-to-end matrix (bhyve rig; see vsock_bhyve_testplan.md)

| Guest | Expectation |
|---|---|
| 5BSD guest, modern device | attaches via `virtio_pci_modern`; full vsock ATF suite green |
| 5BSD guest, `transport=legacy` | attaches via `virtio_pci_legacy` (compat pin) |
| Linux guest, modern device | `vp_modern_probe` path; socat/iperf-vsock data; `lspci -vv` shows caps |
| Linux guest, MSI-X disabled (pci=nomsi) | INTx + ISR path works |
| legacy-only driver vs modern device | must NOT attach; no crash, clean probe failure |

Plus soak: connection churn + credit-stall traffic overnight with the
DTrace overview script attached (below) watching for leaks
(`conn__count` monotonic drift) and unexplained `transport__error`s.

## 11. Observability: DTrace and logging

### 11.1 USDT probes

The device protocol remains under the `vsock` provider.  Generic PCI
transport events use a separate `virtio` provider declared in the same
`vsock_provider.d` build input, so future virtio devices can reuse it without
depending on vsock-specific code:

```
/* Modern transport lifecycle (§8) */
probe transport__features(uint64_t features);
probe transport__status(uint8_t oldval, uint8_t newval);
probe transport__queue__enable(uint16_t idx, uint64_t desc,
    uint64_t driver, uint64_t device, uint16_t qsize);
probe transport__queue__notify(uint16_t idx);
probe transport__cfg__window(uint8_t bar, uint32_t off,
    uint32_t len, uint8_t iswrite);
probe transport__config__changed(uint8_t generation);
probe transport__reset();
probe transport__error(const char *why);        /* + DEVICE_NEEDS_RESET */
```

`transport__error` is the probe twin of every "driver confused?"
one probe whose `why` string discriminates the condition, following the
existing `desc__drop` pattern.

### 11.2 share/dtrace script

Add `share/dtrace/vsock-transport` next to the four existing vsock
scripts (share/dtrace/Makefile `SCRIPTS+=`, `PACKAGE= dtrace`):
one-screen live view of negotiation, status transitions, queue
enables/notify rates, and transport errors — the bring-up tool for the
e2e matrix and the first thing to attach when a guest won't probe.

### 11.3 Logging conventions

Host configuration failures (invalid transport, BAR, queue maximum, memory,
BAR allocation, or capability allocation) use `EPRINTLN`.  Guest-controlled
invalid accesses are deliberately not printed, because an untrusted guest
could flood stderr; fatal queue validation is exposed through
`virtio:::transport-error` and `DEVICE_NEEDS_RESET`.  Negotiation, status,
queue, reset, config-window, and config-change activity is observable through
the other `virtio` probes without enabling verbose logging.

## 12. Audit integration

Two distinct planes:

- **Guest-facing kernel (AF_VSOCK syscalls)**: bind/connect/accept are
  already audited generically (AUE_BIND/AUE_CONNECT/...), but
  `audit_arg_sockaddr()`/BSM only encode AF_INET/INET6/UNIX socket
  addresses — a `sockaddr_vm` is silently dropped from the record, so
  vsock audit trails currently lack the CID/port. Work item (kernel +
  contrib/openbsm, following the serviced BSM precedent in commit
  db5e9bcccaa): add a `sockaddr_vm` BSM token (au_to_sock_vm or an
  extension of the generic socket token), teach
  `audit_arg_sockaddr()` about AF_VSOCK, and document the record shape
  in vsock.4. This is independent of the transport work but belongs in
  the same milestone: vsock is a guest↔host trust boundary and the
  audit trail should name endpoints.
- **Host device model (bhyve)**: bhyve has no BSM producer, and the
  device model shouldn't grow one; the security-event surface is the
  existing `desc__drop`/overflow probes plus the new
  `transport__error` probe. If
  host-side audit records for guest vsock connections are ever
  required, the right place is the host kernel vsock backend (it sees
  every connect), not the PCI emulation.

## 13. Packaging (pkgbase)

No new package is needed; every artifact lands in an existing one.
Touchpoints when the code lands:

| Artifact | Package | Mechanism |
|---|---|---|
| transport code (virtio.c/h, pci_virtio_vsock.c, vsock_provider.d) | `bhyve` | usr.sbin/bhyve/Makefile already `PACKAGE= bhyve`; new .c/.h just join SRCS |
| new unit tests (virtio_modern_test) | `tests` | tests/sys/kern/Makefile `ATF_TESTS_C+=`; installed test binaries land in the existing `tests/sys/kern` mtree node. Verify `etc/mtree/BSD.tests.dist` only if adding a new *directory* (the harness sources are build-time only and install nothing — note the b37eaf47c41 "mtree fix" was exactly this class of bug) |
| `vsock-transport` dtrace script | `dtrace` | share/dtrace/Makefile `SCRIPTS+=` (PACKAGE= dtrace already set) |
| vsock.4 update (transport option, audit record) | man page package via share/man/man4 | existing file, no packaging change |
| openbsm audit event/token additions | `runtime`/audit config | contrib/openbsm/etc/audit_event + libbsm, per the serviced precedent |

The `transport=modern|legacy` knob keeps upgrade behavior decoupled
from packaging: a pkgbase upgrade of the `bhyve` package changes the
default device identity, and the knob is the rollback lever — worth a
UPDATING entry when the default flips.

## 14. References

### Specifications
- virtio 1.4 CS01 (current): https://docs.oasis-open.org/virtio/virtio/v1.4/virtio-v1.4.html
  (artifacts incl. diff-from-1.2: https://docs.oasis-open.org/virtio/virtio/v1.4/cs01/)
- virtio 1.3 CSD01 (draft only): https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html
- virtio 1.2 CS01: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
- virtio 1.1 CS01 (first vsock): https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html
- virtio 1.0 CS04: https://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html
- Spec source repo (master = v1.4-cs01 as of writing): https://github.com/oasis-tcs/virtio-spec
  - vsock section source: https://github.com/oasis-tcs/virtio-spec/blob/master/device-types/vsock/description.tex
  - 1.3→1.4 changelog: https://github.com/oasis-tcs/virtio-spec/blob/master/cl-os-1.3wd01_to_1.4.tex
- OASIS virtio TC (landing page stale): https://www.oasis-open.org/committees/virtio/

### Key spec sections (1.2/1.4 numbering)
§2.2.3 feature-bit-based legacy detection · §4.1.2–4.1.2.3 PCI IDs,
transitional rules · §4.1.4.3 common cfg · §4.1.4.4 notify ·
§4.1.4.9 PCI_CFG (mandatory) · §4.1.4.10 legacy interface ·
§4.1.4.11 non-transitional vs legacy drivers · §4.1.5.1.3.1 legacy vq
layout · §5.10 Socket Device · §6/6.1/6.2/6.3 feature bit requirements ·
§7.4 conformance targets (transitional xor non-transitional)

### Linux (why legacy vsock works there)
- https://github.com/torvalds/linux/blob/master/drivers/virtio/virtio_pci_legacy_dev.c
- https://github.com/torvalds/linux/blob/master/drivers/virtio/virtio_pci_modern_dev.c
- https://github.com/torvalds/linux/blob/master/net/vmw_vsock/virtio_transport.c
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_pci.h
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_vsock.h

### QEMU precedent (device-side reference implementation)
- https://github.com/qemu/qemu/blob/master/hw/virtio/virtio-pci.c —
  modern transport device model (BAR layout, cap emission, PCI_CFG
  window); the §9.2 line numbers refer to this file
- https://github.com/qemu/qemu/blob/master/hw/virtio/vhost-vsock-pci.c —
  vsock forced modern-only

GPLv2 both — behavioral reference only, never copy into this tree.
Local working copies of these plus the Linux files below were saved
during this research (session scratchpad `refimpl/`); re-fetch from the
URLs when needed, they are not part of the repo.

### vsock datagram effort (stalled, not in spec)
- LWN overview: https://lwn.net/Articles/933317/
- Garzarella status, Jul 2025 (no v7 driver): https://lkml.org/lkml/2025/7/29/675

### This tree
- Host device model: `usr.sbin/bhyve/pci_virtio_vsock.c`; transport core
  `usr.sbin/bhyve/virtio.c`, `virtio.h`
- Guest transports: `sys/dev/virtio/pci/virtio_pci_legacy.c`,
  `virtio_pci_modern.c`; guest vsock `sys/dev/virtio/vsock/virtio_vsock.c`
- Feature bits: `sys/sys/vsock.h`
- Relevant commits: 3da15d5694c (AF_VSOCK + guest transport + bhyve
  device), df28995f11f (legacy PCI identity for vsock), d2a42306516
  (NO_IMPLIED_STREAM et al.), b37eaf47c41 (tests + bhyve e2e test plan)

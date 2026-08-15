# bhyve VirtIO GPU 2D design

Status: modern PCI, protocol, queue, retained 2D state, and portable
checkpoint foundation implemented; live guest and host-display qualification
remain pending.

The normative reference is VirtIO 1.4 CS01 section 5.7.  The pinned Linux
driver is the live guest reference and pinned QEMU is used only to compare
device-model behavior.  No Linux or QEMU implementation code is copied.

The initial device is modern-only, unaccelerated 2D.  It exposes controlq
and cursorq, one scanout, no VIRGL, no blob resources, no shared-memory
region, no resource UUIDs, and no context-init feature.  It advertises
`VIRTIO_GPU_F_EDID` and returns one deterministic EDID 1.4 base block whose
preferred timing matches the configured scanout, which defaults to
1024-by-768.

`virtio_gpu_2d_protocol.c` is the transport-neutral command boundary.  It:

- decodes every scalar as little-endian;
- requires the exact 24-byte control header and command-specific body;
- accepts only the fence flag and echoes its identifier in responses;
- keeps 2D commands on controlq and cursor commands on cursorq;
- accepts Linux/QEMU's deployed cursorq convention of a readable-only command
  completed with used length zero, while optionally supporting a complete
  response buffer;
- treats resource ID zero on cursor update as cursor removal and ignores the
  unused resource/hotspot fields on cursor move, matching the specified
  command semantics and Linux behavior;
- validates all reserved fields;
- validates the eight baseline 32-bit pixel formats;
- checks rectangles for zero size and addition overflow;
- permits resource ID zero only where `SET_SCANOUT` uses it to disable a
  scanout;
- validates the 1--16 scanout namespace independently of the eventual
  configured scanout count;
- validates every attach-backing entry, including count, exact array size,
  nonzero length, reserved padding, and address-range overflow; and
- requires the full 408-byte display-information response capacity before
  accepting `GET_DISPLAY_INFO`; and
- accepts only scanout zero for the exact 32-byte `GET_EDID` request, validates
  its reserved padding, and requires the complete 1056-byte EDID response
  capacity before executing it.

`virtio_gpu_2d_edid_encode()` constructs the EDID from bounded integer timing
parameters rather than a host structure.  It emits the required header,
EDID 1.4 version, preferred detailed timing, monitor name, explicit dummy
descriptors, zero extension count, and a valid base-block checksum.  The
entire 1024-byte protocol EDID field is initialized even though the returned
EDID size is 128 bytes.  This prevents host padding disclosure and keeps the
wire result deterministic across host architecture and compiler ABI.
The same timing validator rejects configured dimension pairs which cannot be
represented by the EDID detailed timing, so display information and EDID can
never describe different monitors.

`virtio_gpu_2d_state.c` owns the retained 2D model.  It provides:

- explicitly configured limits for resource count and total host pixel bytes;
- overflow-checked 32-bit pixel surfaces and duplicate-ID rejection;
- transactional backing attachment represented by fixed-width guest physical
  ranges, with no persistent host mapping;
- an architecture-neutral DMA-read callback, including scatter/gather reads;
- atomic transfer staging, so a failed DMA read cannot publish a partly
  updated resource;
- one scanout with validated cropping and flush intersection translated to
  scanout-local coordinates, with both command and restore paths rejecting a
  visible extent larger than the configured virtual monitor;
- enforcement of the section 5.7.6.1 attach-backing-before-scanout sequence,
  while permitting a later detach to leave the retained host copy displayed;
- an atomic scanout-copy operation that captures a requested rectangle and
  its pixel format under the same resource lock, preventing display callbacks
  from combining metadata and pixels from different resource generations;
- separate cursor state with the required 64-by-64 resource and validated
  hotspot;
- deterministic reset and unref cleanup, including scanout and cursor
  detachment; and
- a versioned, fixed-width, little-endian snapshot that transactionally
  validates and reconstructs resources, pixels, backing descriptors, scanout,
  and cursor state.

The snapshot contains guest physical backing descriptors because they refer to
the restored guest-memory address space.  It never contains translated host
addresses, DMA mappings, callbacks, display handles, locks, pointers, file
descriptors, native structures, host endianness, host page size, or
Intel-specific state.  This boundary is therefore suitable for the current
Intel host without embedding an amd64 dependency.

`virtio_gpu_2d_display.c` converts all eight baseline VirtIO GPU formats to
the console's architecture-independent `0x00RRGGBB` representation.  Its
format table is driven by independent specification byte vectors, preserves
alpha in the lower-level ARGB conversion, forces X channels opaque, honors
independent source and destination strides, and rejects invalid dimensions or
truncated rows.  The same adapter now provides rounded straight-alpha cursor
composition into XRGB, including exact transparent and opaque behavior and
unaligned-safe host-word access.  It does not depend on amd64 byte order or
directly alias guest pixels as native console words.

`pci_virtio_gpu.c` composes this state into a modern-only VirtIO PCI device
with device ID 16, a 256-entry control queue, and a 256-entry cursor queue.
It uses the common split/packed queue engine, common DMA mapping boundary,
interrupt lifecycle, selective queue reset, guest suspend, and checkpoint
quiescing.  Device configuration presents one scanout and no capability sets.
`events_clear` is implemented as a write-to-clear action and is never retained
as readable or migration state.  The device advertises only the EDID
device-specific feature; the EDID is derived from immutable virtual-monitor
configuration.  The sole accepted snapshot version 2 records that monitor
identity explicitly and rejects a destination configured with different
dimensions; obsolete version 1 records are rejected.  The device-specific
snapshot wraps the retained state in a bounded version record and applies
restore transactionally.

The transport-neutral
`virtio_gpu_2d_queue.c` boundary already validates descriptor ordering,
overflow and total request bounds, gathers fragmented readable commands,
requires complete writable response capacity before executing state changes,
and scatters the exact 24-byte, 408-byte, or 1056-byte response.  It never
publishes a partial used length.

Production presentation is an explicit opt-in.  With `display=true`, the GPU
claims the console registry's framebuffer-producer role and publishes its
converted scanout and cursor.  A separately configured
`fbuf,source=external,vga=off` instance consumes that image without owning or
overwriting the renderer.  The registry rejects a second producer, so device
ordering cannot silently replace the active display.  The device adds no
polling thread: the existing RFB refresh event pulls one atomic scanout image
through the registered renderer.

The independent protocol harness checks EDID framing, version, preferred-mode
fields, descriptor placement, padding, and checksum without importing the
implementation's protocol constants.  The display harness covers every
baseline byte order, independent strides, unaligned destinations, alpha
rounding, fully transparent cursors, and fully opaque cursors.  The queue
harness additionally proves fragmented response scatter and rejection of a
short response chain.  The Linux guest helper requires feature negotiation
and validates the DRM connector's EDID bytes, checksum, and exact configured
mode.  Release coverage requires both the default 1024-by-768 split-ring
monitor and a 1920-by-1080 packed-ring monitor; checkpoint coverage saves and
restores the latter identity.  The opt-in display lane connects an independent
RFB 3.8 raw-encoding client to the Unix listener and verifies fixed pixels
written by Linux at the first and last scanlines.  This keeps the normal
headless oracle deterministic while giving the presentation lane a direct
end-to-end proof.  Those live gates remain pending until the updated bhyve and
test package are installed and run.

Live Linux and 5BSD qualification, active checkpoint, repeated reset,
packed-ring qualification, and successful production-presentation evidence
remain required before this device is considered release-qualified.

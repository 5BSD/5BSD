# bhyve modern VirtIO balloon design

Status: implemented and registered; VM-free qualification passes, with live
Linux and 5BSD qualification pending installation of the new bhyve

Normative source: VirtIO 1.4 CS01 section 5.5 and the common requirements in
sections 2, 3, 4.1, and 6.

## Initial advertised surface

The default implementation is modern PCI only and exposes exactly two queues:
inflate queue 0 and deflate queue 1.  Its complete 16-byte VirtIO 1.4 device
configuration is:

- `num_pages`, little-endian 32-bit count of 4096-byte balloon pages desired
  by the host;
- `actual`, little-endian 32-bit count written by the driver;
- `free_page_hint_cmd_id`, zero unless free-page hinting is negotiated;
- `poison_val`, zero unless PAGE_POISON is negotiated, then a little-endian
  32-bit value selected by the driver before DRIVER_OK.

The device advertises `VIRTIO_BALLOON_F_MUST_TELL_HOST`.  Statistics are an
explicit `stats_interval=N` opt-in.  That mode adds queue 2, retains exactly
one driver-readable chain, atomically parses arbitrary-order little-endian
entries, and completes the retained chain from a monotonic timer to request
the next sample.  A selective reset of queue 2 revokes the retained descriptor
without completing it, and a reconfigured generation can immediately acquire
a replacement.  Queue generation fences reset.  Checkpoint pause completes a
retained descriptor before save, the current record preserves the last
validated sample, and restore never imports a live queue token because copied
split/packed completion identity is not queue ownership.
This matches the retained-buffer lifecycle exercised by the pinned Linux
driver and QEMU device model without copying their code.
`deflate_on_oom=true` separately advertises
`VIRTIO_BALLOON_F_DEFLATE_ON_OOM` while retaining the normal validated
deflate path.  `free_page_reporting=true` advertises
`VIRTIO_BALLOON_F_PAGE_REPORTING`, leaves queue 3 at size zero unless the
independent free-page-hint option is enabled, and exposes the standard writable reporting
queue at fixed index 4.  Each reported range is reverse-resolved through the
architecture-neutral guest-RAM boundary and opportunistically discarded
before synchronous acknowledgement.  Failed, unaligned, or unmappable
ranges remain safe no-ops because reporting is an optimization.
`page_poison=true` independently advertises `VIRTIO_BALLOON_F_PAGE_POISON`.
When it is combined with reporting, the device acknowledges valid reporting
chains without discard or backing replacement, preserving the guest's
mandated poison contents.  Reset clears the selected poison value and
versioned state preserves it.  `free_page_hinting=true` independently
advertises `VIRTIO_BALLOON_F_FREE_PAGE_HINT`, exposes queue 3, and starts
command round 2.  The queue accepts one little-endian readable command
followed by writable page ranges.  Mismatched command IDs are acknowledged
without modification.  Matching ranges are reverse-resolved and
opportunistically discarded through the architecture-neutral memory
boundary.  If that boundary cannot consume a range, the device publishes
STOP; the driver's STOP acknowledgement publishes DONE.  Linux's separate
command and writable-page buffers are accepted, as is a combined chain, while
pre-start pages and stale IDs are ignored.  Malformed command shape fails the
queue closed.  BAL1 version 6 preserves the command ID and active/requested
phase; obsolete versions are rejected rather than synthesizing
destination-local state.
MUST_TELL_HOST is required by the PCI host implementation because FreeBSD
`MADV_FREE` is a deferred discard hint: the guest must not reuse a ballooned
page until bhyve has detected the deflate request, cancelled that hint for the
native host page, and acknowledged the descriptor.

Common modern transport features such as indirect descriptors, event index,
notification data, queue reset, suspend, and packed rings are
negotiated independently by the common VirtIO layer.

## Host memory contract

Balloon PFNs always identify 4096-byte units, irrespective of the host or guest
base page size.  The device:

1. reads each PFN as an independent little-endian 32-bit value, including when
   its bytes cross an iovec boundary;
2. checks the left shift and full `[gpa, gpa + 4096)` range for overflow;
3. requires the range to map entirely to guest RAM, never MMIO, ROM, or a
   partially mapped range;
4. ignores an invalid PFN without affecting another PFN in the request;
5. discards only complete host-page-aligned runs, so a host with pages larger
   than 4096 bytes cannot discard a neighboring guest-owned balloon unit;
6. cancels the discard hint for the complete native page on deflation;
7. treats inflate-side discard failure as a missed reclamation opportunity,
   while an unsafe deflate-side cancellation failure sets
   `DEVICE_NEEDS_RESET`.

The production device accepts at most 256 PFNs (1024 bytes) in one request,
matching the pinned Linux and FreeBSD drivers.  This bounds work performed
under the device lock.  A larger otherwise well-formed request is completed
and sets `DEVICE_NEEDS_RESET`; it is never silently reported as successful.
The compatibility limit and its exact boundary have independent tests.

Inflation permits the host to discard the backing pages because the driver has
relinquished them before publishing the request.  Deflation uses the
architecture-neutral undiscard operation before completion so delayed host
reclamation cannot race guest reuse.  No host pointer, mapping cookie, file
descriptor, or native page-size value enters save-state.

The production discard operation belongs behind the common
`virtio_platform_ops` guest-memory boundary.  The PCI implementation validates
the complete GPA range, requires host-page alignment, maps only guest RAM, and
uses FreeBSD `MADV_FREE`; its matching undiscard operation maps the same
host-page-aligned RAM range and uses `MADV_WILLNEED`.  Translated-DMA and future
non-PCI transports may replace both operations without changing the balloon
parser.  The balloon
device must not call an amd64 VM API or assume a 4096-byte host page.  On a host
whose base page is larger than a balloon page, the initial implementation
safely declines individual discards until a complete aligned host-page run is
known to be inflated.

## Accounting and control

The guest owns `actual`; the host owns `num_pages`.  Both are bounded by the
configured RAM size expressed in 4096-byte units.  A host target update changes
`num_pages`, increments the configuration generation, and raises one
configuration interrupt.  Repeating the same target is idempotent.

The first control surface accepts a startup target only.  A later live control
API must use the same checked target setter; it must not mutate the config
structure directly.

Reset clears queue mappings and guest-reported `actual`, but retains the host
target.  Queue reset affects only the selected queue.  Suspend stops descriptor
acquisition after the current synchronous request and resume does not synthesize
requests.

Operational tracing is available through `balloon-request`,
`balloon-discard`, `balloon-undiscard`, `balloon-config`, and
`balloon-poison`, and `balloon-stats` probes in the
bhyve VirtIO DTrace provider.  Guest-controlled malformed requests use the
generic error probe rather than unbounded console logging.

## Save-state

The version-6 portable record contains flags, target and guest-reported actual
page counts, RAM identity, the exact validated 4096-byte-unit ownership
bitmap, the last validated statistics sample, and the negotiated poison value
in explicit little-endian fields.  It contains no host pointers, mapping
cookies, queue tokens, or native-page identities.  Restore rejects unknown
versions, nonzero reserved flags, invalid bitmap tail bits, values exceeding
destination RAM, changed RAM identity, unsupported poison state, and malformed
statistics.

Restoration compares source and destination ownership at complete native-host
page granularity.  It discards only destination host pages whose every
balloon unit is owned by the restored guest state, undiscards pages no longer
fully owned, and rolls back the successful prefix after a later host failure.
Counts, bitmap, statistics, and poison value publish only after reconstruction
succeeds.  An identical repeated restore performs no host-memory operation.
Ballooned page bytes remain part of ordinary VM memory state; the ownership
record controls only the validated host discard optimization.

## Required tests before advertisement

- independent byte layout for configuration and PFN arrays;
- empty, one-byte-short, non-multiple-of-four, fragmented, duplicate,
  out-of-range, overflow-adjacent, MMIO-hole, and maximum PFN requests;
- readable/writable descriptor direction and ordering failures;
- host page sizes of 4096, 16384, and 65536 in the discard-run model;
- discard failure, partial eligibility, and mixed valid/invalid PFNs;
- target bounds, idempotence, config generation, and interrupt fallback;
- full reset, every configured queue reset (including a retained statistics
  descriptor), suspend/resume, repeated restore, corrupt
  state, and destination RAM mismatch;
- Linux and FreeBSD inflate/deflate with observable resident-memory reduction;
- indirect descriptors, EVENT_IDX, packed/split, MSI-X/MSI, active checkpoint,
  and reset soak.

The device is registered because its parser, memory-discard abstraction,
accounting, negative tests, strict build, and sanitizer gates pass.  The
release profile now contains split, packed, reset, combined-device, and
checkpoint cases; those root-only cases remain qualification evidence to be
collected after installation and reboot.

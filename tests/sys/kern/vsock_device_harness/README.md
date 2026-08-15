# bhyve VirtIO device-level harnesses

Standalone unit harnesses for the bhyve virtio-vsock, virtio-input,
virtio-rng, virtio-console, virtio-9p, virtio-block, virtio-net, and
virtio-scsi backends, the shared split-ring parser, and the generic modern
VirtIO PCI transport.

It `#include`s the real device `.c` and mocks the virtio RX ring (to capture the
packets the device injects back toward the guest) and the host-socket syscalls
(via `ld --wrap`), so the op state machine can be driven with crafted guest
headers with no VM, no virtio bus, and no real sockets.

## Build & run

    ./run.sh

Requires a C compiler.  The device and modern-transport harnesses run under
AddressSanitizer and UndefinedBehaviorSanitizer for standalone iteration.

For an asynchronous caller, set `RESULT_FILE=/path/to/result`.  The harness
atomically publishes `RUNNING device harness pid=N workdir=PATH`, then exactly one terminal
record: `PASS device harness all tests passed` after every lane, or `FAIL
device harness exit=N` on an ordinary error or HUP/INT/TERM cleanup.  Treat
only the PASS record as success; a supervisor that must cancel a currently
running harness should terminate its worker process group and then read the
terminal record.

`run-snapshot-model.sh` accepts the same optional `RESULT_FILE` convention for
the checkpoint codec and manifest suite.  Its records are `RUNNING
virtio-snapshot-model pid=N`, `PASS virtio-snapshot-model cases=N`, or `FAIL
virtio-snapshot-model exit=N`.  It initializes the record before validating
options or the source-tree path, so a missing source tree or rejected option
cannot look like a still-running successful case.
Set `SANITIZERS=thread` to run the identical test set under ThreadSanitizer;
the validation record in `docs/bhyve-virtio-1.4-validation-review.md` records
both modes.

These harnesses are also wired into ATF/kyua (see this directory's Makefile,
which supplies the mock-header shadowing and `--wrap` linker flags the stock
`ATF_TESTS_C` build does not), so the same cases run as part of the kernel test
suite.  The standalone script also exercises transport policy, PCI identity
and capability layout, 64-bit feature negotiation, separately addressed
virtqueues, notification and ISR behavior, and the PCI configuration access
window, including the modern network, SCSI, console, and 9P device identities.
The entropy interrupt test combines the real virtio-rng callback with
the real legacy BAR notification and shared split-ring completion path; only
guest memory and the PCI/VMM boundary are mocked.

The VirtIO 1.4 requirements ledger is
`virtio-1.4-requirements.tsv`.  `validate-virtio-requirements.sh` rejects
advertised features without an implementation and positive test.  The current
reference catalog is `virtio-reference-corpus.tsv`.  Metadata validation is
always rootless; setting `VIRTIO_REFERENCE_ARTIFACT_DIR` for
`virtio-host-regression.sh` additionally requires exactly one local artifact
matching every pinned VirtIO, Intel, Linux, and QEMU SHA-256 and rejects
missing, duplicate, or unrecognized files.

`virtio_requirements_test` is deliberately a source-to-test traceability
audit: it compares the installed ledger fixtures with the matching production
sources, qualification manifest, and review record.  It therefore requires a
source-matched tree (normally `/usr/src`) in addition to the installed test
package; it reports that prerequisite explicitly instead of treating a missing
tree as a passing runtime-device test.

The current
1.4 milestone implements `VIRTIO_F_RING_RESET` for the bhyve net, block,
console, entropy, SCSI, input, and vsock devices.  The 9P device does not
advertise this optional feature because lib9p does not expose queue-local
request cancellation; reconnecting the whole device would incorrectly discard
session and fid state.  Every modern device also implements
`VIRTIO_F_NOTIFICATION_DATA`; the FreeBSD PCI and MMIO guest transports send
the full available index in the 32-bit notification.  Modern PCI devices also
implement `VIRTIO_F_NOTIF_CONFIG_DATA`: bhyve exposes the specification's
trivial queue-index identifier, while the FreeBSD guest stores and uses the
device-provided value independently of notification width.  Split and packed
rings share the same queue API and independent exhaustive models.  The
optional IOMMU and administration foundations remain gated from advertisement
until their production PCI composition and live qualification are complete.
Guest-visible VirtIO suspend now has a
common queue/interrupt/configuration lifecycle and a FreeBSD modern-PCI guest
handshake.  Virtio-net, block, entropy, and vsock are opted in: block and
checkpoint quiesce use reference-counted ownership, so restoring a checkpoint
cannot prematurely restart a still guest-suspended backend.  Vsock disables
all host admission, relay, provider, and retry events while either the guest
or checkpoint owns the common queue fence, and selectively rearms them only
after the fence opens.  Checkpoint pause/resume shares the common queue gate,
always takes backend serialization ownership, and propagates quiesce or
stable-storage failures instead of writing an inconsistent checkpoint.
Versioned modern common, PCI transport, and split queue state serialization is
implemented for net, block, entropy, and an idle userspace vsock device.
Block version 3 binds restore to a bounded backend identity: an explicit
`checkpoint_identity` is portable across hosts, while the default identity is
derived once from the already-open object and intentionally permits only a
same-host, same-object restore.  The guest-visible serial is not treated as a
storage identity.  Restore reconstructs independent checkpoint and
guest-suspend ownership before devices are resumed.  Active userspace vsock
sessions fail snapshot with
`EBUSY`, and the kernel backend fails with `EOPNOTSUPP`, because neither host
socket nor kernel AF_VSOCK connection state is serializable through the
provider ABI.  A clean snapshot-enabled bhyve build compiles and links, but the
option is still marked broken by the wider tree, so live running-device and
guest-suspended checkpoint/restore round trips remain release gates.  FreeBSD
virtio-rng is the first guest consumer of individual queue reset.  Its VM
acceptance test is
`../vsock_e2e/run-freebsd-vtrnd-reset.sh`.

Protocol expectations in the harness come from `virtio_1_4_spec.h` and
`virtio_1_4_wire.h`, which are literal transcriptions of the cited document
tables and layouts and may not include or derive from production VirtIO
headers.  Device tests include the real implementation before remapping its
protocol names to this independent oracle; structured request tests assemble
raw bytes using document offsets.  Values such as mock guest addresses,
payload patterns, fault-injection errors, counters, and implementation state
are test inputs rather than protocol expectations.  The explicit legacy
virtio-input PCI identity and historical virtio-vsock legacy identity are
separately documented bhyve compatibility extensions recorded in
`bhyve_virtio_compat.h`: VirtIO 1.4 assigns neither device a transitional ID,
so they are not presented as standard conformance values.  The input harness
checks the complete compatibility identity; Linux and 5BSD live lanes check
the vsock identity and bind the expected guest driver.

## Coverage

The requirements ledger is a scoped implementation ledger, not a claim that
every normative statement in the complete VirtIO 1.4 document is tested.
Its denominator is the rows in `virtio-1.4-requirements.tsv`: applicable
common transport rules, every feature this implementation advertises, and the
device types bhyve or the reviewed FreeBSD guest drivers implement.  Rows for
known optional exclusions make non-advertisement explicit, but the ledger does
not create one row per `MUST`, `SHOULD`, or `MAY` in unrelated device chapters.
Consequently, “all ledger entries validated” must not be reported as “100% of
VirtIO 1.4.”

To report the current denominator without copying a count that will become
stale:

    awk -F '\t' 'NR > 1 { total++; status[$4]++ }
        END {
            print "selected requirements:", total
            for (s in status)
                print s ":", status[s]
        }' virtio-1.4-requirements.tsv

Positive and negative columns identify semantic evidence, not just successful
execution.  A single ATF case may appear in both columns only when that case
contains both an accepted boundary and a rejected boundary or invariant check.
Stateful advertised features additionally require reset or concurrency
evidence in their dedicated ledger row or notes.  The validator proves that
referenced cases exist and are registered, and that protocol expectations are
independent of the implementation; it cannot prove that an assertion is
semantically sufficient.  That remains a review obligation.

Two structural guards run before the C harnesses.  The snapshot portability
guard rejects native-width or host-page-dependent state in every modern
VirtIO device wrapper and delegated codec.  The DMA-boundary guard rejects raw
guest-address mapping from device-private PCI code, pins the non-recursive
VirtIO-IOMMU provider exception to its reviewed callbacks, and requires
non-descriptor GPU backing accesses to use the common translator.  These
guards prevent a newly added device or state field from silently bypassing
the architecture-neutral checkpoint and ACCESS_PLATFORM contracts.

Coverage includes malformed direct and indirect descriptors; EVENT_IDX;
in-place iovec splitting (including packed virtio-scsi request/data
descriptors without losing the response tail);
virtio-console feature and configuration bounds, fragmented control messages,
invalid port IDs and queue directions, idempotent `DEVICE_ADD` lifecycle,
multi-descriptor data transfer, and host-side backpressure without data loss;
virtio-9p configuration bounds, request/response descriptor directions,
lib9p request rejection, synchronous flush completion, and stale completion
after reset; and the real lib9p threadpool topology that serializes dependent
fid operations within one connection;
virtio-block descriptor ordering, header/status placement, opcode-specific
layouts, offset overflow, discard flags and feature negotiation, and immediate
backend queue errors;
virtio-net RX/TX descriptor directions and bounds, undersized receive buffers,
merged-buffer accounting beyond 32 bits, zero TX used lengths, and
configuration-write bounds;
virtio-scsi request/control descriptor validation, response isolation,
accurate failure used lengths, invalid task-management functions,
bidirectional feature enforcement, bounded configuration hints, full-reset
completion versus selective-reset discard, and oversized payload rejection;
virtio-input configuration bounds, fresh zeroed query responses, absolute-axis
metadata, reset-state clearing, event/status queue directions, and whole-frame
delivery or drop;
virtio-rng short and invalid host reads, retained failed chains with reset
signaling, and bounded partial fills;
virtio-rng queue
notification through MSI/INTx delivery with MSI-X disabled; and vsock state,
credit, record-boundary, shutdown, timeout, resource-limit, and invalid-packet
cases.  SEQPACKET credit coverage includes an atomic record larger than current
credit: it remains queued, sends only one CREDIT_REQUEST across repeated
callbacks and RX-notification redispatch, keeps a reaper timestamp through a
liveness probe and credit update, and clears it after delivery.  Connection
setup coverage also rejects nonzero initial `fwd_cnt` values before opening a
host relay socket.  A discarded type-mismatched data packet is also credited
back at the reporting threshold so the sender cannot remain blocked on bytes
bhyve no longer holds.  Pending-control-reply coverage fills the bounded ring,
verifies overflow accounting without false credit advancement, drains the
retained FIFO, and confirms that the dropped credit update is retried.
Fault injection also forces SEQPACKET reassembly growth to fail and verifies
RST/connection cleanup without leaking either device-global byte budget.
Checkpoint tests cover per-device pause ownership and retry, interrupted and
zero-progress publication writes, strict manifest parsing, generation/path
validation, atomic replacement, failure before manifest rename, and a
directory-fsync error after rename.
Queue-reset coverage includes synchronous completion, asynchronous drain,
failure and stale-completion generations, frozen configuration and
notifications, reconfiguration with new queue addresses, per-device queue
isolation, backend quiescing, a full-device reset crossing an unlocked backend
reset callback, and reset-safe preservation or rejection of staged data.  The
transport state soak performs 4,096 mixed synchronous and asynchronous queue
reset/re-enable cycles, including stale completions and periodic full-device
resets.
See `../vsock_e2e/FRAMEWORK.md` for the complete
acceptance layers and the checklist for adding another device.

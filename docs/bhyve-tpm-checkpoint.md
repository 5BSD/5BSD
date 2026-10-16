# bhyve TPM checkpoint contract

Disk checkpoint, restore, and live migration of a TPM require explicit
`tpm.migration` configuration, a source `tpm.state_id`, and a
`tpm.migration_key_id`. They remain unqualified on real swtpm and guest
traffic. The implementation has a versioned
record for the CRB register image, PPI memory, and the three swtpm state
blobs. A complete checkpoint must contain all of these from the same paused
guest state. The `BHYTPM03` envelope identifies the swtpm backend and TPM 2.0,
fixes the order to permanent, volatile, then savestate, and bounds each blob
to the 512 KiB accepted by swtpm's non-CUSE `SET_STATEBLOB` handler. Permanent
and volatile blobs must be nonempty; savestate may be absent. The envelope
records the source `tpm.state_id`, a required nonzero 128-bit identifier
written as 32 lowercase hex digits in the VM configuration. Restore preflight
rejects a destination without an identifier or with the same identifier.
Operators must assign identifiers to genuinely separate storage instances:
the identifier is a configuration assertion, not proof of storage isolation.
The swtpm control channel must report a configured migration key; nonempty
state blobs must be encrypted under that key. Destination swtpm must have a
compatible migration key to import them. The key flags do not reveal or
verify the key material itself.

The control-channel ordering is important:

1. Pause the guest vCPUs and drain the CRB worker before copying guest memory.
2. Capture CRB and PPI state. While swtpm is **running**, get permanent,
   volatile, and savestate blobs, in that order. Getting savestate can release
   swtpm's storage lock.
3. If the source VM resumes, reacquire the swtpm storage lock before releasing
   the CRB fence. If the source is handed off to a destination, retain the
   guest fence until the checkpoint is committed and the source is stopped.
4. On the destination, validate the whole envelope, local register images,
   and guest/device topology before side effects. Drain the destination CRB
   worker, stop swtpm, set all blobs in the same order (including empty blobs
   to clear stale destination state), apply local
   state, initialize swtpm, then release the CRB fence only after the outer
   restore transaction commits.

Transport or protocol failures after a control command may mean it committed
without a reply. The transaction marks that state uncertain and keeps the CRB
fenced. A failed destination blob write likewise cannot be rolled back safely
within bhyve; the destination must not run. An incoming swtpm instance needs
independent state storage and compatible libtpms and migration-key policy.
Only the exact swtpm `TPM_RETRY` result (`0x800`) for savestate represents a
missing optional state blob. A missing permanent or volatile blob and all
other nonzero results abort capture.

The `BHYTPM03` callback is enrolled in device topology, save/restore, and
preflight validation. Disk checkpoint uses the same admission and encrypted
state codec as live migration. Restore checks for explicit opt-in, distinct
source and destination storage IDs, matching migration-key IDs, and an swtpm
control channel that reports a migration key. The IDs are operator assertions;
they do not prove independent storage or matching key material. Production
qualification still needs a real swtpm pair with separate state directories,
fault injection at source resume and handoff boundaries, and guest TPM traffic
through successful and failed disk restore and live migration. A partial
destination restore cannot safely roll persistent TPM state back. Keep its
guest stopped, discard the dedicated destination state directory, and start a
fresh swtpm instance before retrying. Never replay a disk checkpoint into the
source swtpm state directory.

Live qualification must verify the matching running `vmm` and bhyve build,
guest TPM traffic before and after checkpoint, a clean destination swtpm with
the same key material but a distinct state ID and directory, rejection of a
same-ID or wrong-key destination before guest execution, and fault injection
at each `GET_STATEBLOB`/`SET_STATEBLOB` and `INIT` boundary. Rootless codec and
transaction tests cover record validation and failure transitions but do not
prove swtpm's persistent-state behavior.

Protocol references: [swtpm control handler](https://github.com/stefanberger/swtpm/blob/master/src/swtpm/ctrlchannel.c),
[swtpm command layout](https://github.com/stefanberger/swtpm/blob/master/include/swtpm/tpm_ioctl.h),
and [QEMU's swtpm state transfer](https://github.com/qemu/qemu/blob/master/backends/tpm/tpm_emulator.c).

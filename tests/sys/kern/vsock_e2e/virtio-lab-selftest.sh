#!/bin/sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
LUA=${LUA:-/usr/libexec/flua}
lab="$here/virtio-lab.lua"
manifest="$here/virtio-lab.yaml"
case_wrapper="$here/virtio-lab-case.sh"
tree_root=$(CDPATH= cd -- "$here/../../../.." && pwd)
work=$(mktemp -d)
cleanup()
{
	trap - EXIT HUP INT TERM
	rm -rf "$work"
}

prepare_validator_tree()
{
	validator_tree=$1

	mkdir -p "$validator_tree/usr.sbin" "$validator_tree/contrib"
	ln -s "$tree_root/sys" "$validator_tree/sys"
	ln -s "$tree_root/tests" "$validator_tree/tests"
	ln -s "$tree_root/docs" "$validator_tree/docs"
	ln -s "$tree_root/lib" "$validator_tree/lib"
	ln -s "$tree_root/contrib/lib9p" "$validator_tree/contrib/lib9p"
	ln -s "$tree_root/usr.sbin/virtiofsd" \
	    "$validator_tree/usr.sbin/virtiofsd"
	cp -R "$tree_root/usr.sbin/bhyve" "$validator_tree/usr.sbin/bhyve"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if command -v python3 >/dev/null 2>&1; then
	python3 "$here/gnonvirtio.py" --self-test | grep -q '^SELFTEST PASS$'
	python3 "$here/gvirtio_features.py" --self-test | grep -q '^SELFTEST PASS$'
else
	# Python is a guest dependency, not a host-package dependency.  Alpine
	# runs this self-test after provisioning; retain a source contract on
	# hosts which intentionally do not install Python.
	grep -Fq 'def self_test():' "$here/gnonvirtio.py"
	grep -Fq 'def self_test():' "$here/gvirtio_features.py"
fi
sh -n "$here/run-alpine-auto.sh" "$here/run-5bsd-auto.sh"
grep -Fq 'audit_guest_virtio_features' "$here/run-alpine-auto.sh"
grep -Fq 'audit_5bsd_virtio_features' "$here/run-5bsd-auto.sh"
grep -Fq 'negotiated_features' "$here/run-5bsd-auto.sh"
grep -Fq 'run_nonvirtio_checkpoint_rejection' "$here/run-alpine-auto.sh"
grep -Fq 'run_nonvirtio_checkpoint_5bsd' "$here/run-5bsd-auto.sh"
grep -Fq 'run_virtio_checkpoint_5bsd' "$here/run-5bsd-auto.sh"
grep -Fq '["vmm-root"] = "../../vmm/run-vmm-root.sh"' "$lab"
grep -Fq 'VMM-POSTCONDITION no-leaked-vms' \
    "$tree_root/tests/sys/vmm/run-vmm-root.sh"
grep -Fq '/etc/waspnest-build-id' "$here/run-5bsd-auto.sh"
grep -Fq 'FIVEBSD_IMAGE_SHA256' "$here/run-5bsd-auto.sh"
grep -Fq 'test \"\$system\" = 5BSD' "$here/run-5bsd-auto.sh"
grep -Fq 'test \"\$product\" = 5bsd' "$here/run-5bsd-auto.sh"
[ "$(grep -c '^  - id: fivebsd-checkpoint-' "$manifest")" -eq 20 ]
grep -Fq 'fivebsd-checkpoint-combined-modern' "$manifest"
grep -Fq 'fivebsd-checkpoint-combined-packed-modern' "$manifest"
cat >"$work/incomplete-combination.yaml" <<'EOF'
---
version: 1
cases:
  - id: incomplete-combination
    executor: alpine-auto
    profiles: [checkpoint]
    env:
      CHECKPOINT_TEST: "yes"
      CHECKPOINT_COMBINATION: alpine-all-split
      DEVICES: "net"
EOF
if "$LUA" "$lab" plan --manifest "$work/incomplete-combination.yaml" \
    --profile checkpoint >"$work/incomplete-combination.out" 2>&1; then
	echo "incomplete complete-machine checkpoint unexpectedly passed" >&2
	exit 1
fi
grep -q 'must include vsock in DEVICES' "$work/incomplete-combination.out"
grep -Fq 'nonvirtio_xhci_pending_transfer' "$here/run-5bsd-auto.sh"
grep -Fq 'pending-transfer=$event' "$here/run-alpine-auto.sh"
grep -Fq 'before any guest-side framebuffer writer' "$here/run-alpine-auto.sh"
grep -Fq 'gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768' \
    "$here/run-alpine-auto.sh"
grep -Fq 'gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768' \
    "$here/run-5bsd-auto.sh"
grep -Fq 'pci0:0:21:0' "$here/freebsd-nonvirtio.sh"
grep -Fq '/tmp/freebsd-tpm2-check /dev/tpm0' "$here/run-5bsd-auto.sh"
grep -Fq 'nonvirtio_xhci_pending_transfer' "$here/run-5bsd-auto.sh"
grep -Fq 'nonvirtio_hda_open_stream' "$here/run-5bsd-auto.sh"
grep -Fq 'nonvirtio_hostbridge_exact_topology' "$here/run-5bsd-auto.sh"
grep -Fq 'nonvirtio-alpine-qemu-fwcfg-checkpoint' "$manifest"
grep -Fq 'nonvirtio-5bsd-qemu-fwcfg-checkpoint' "$manifest"
grep -Fq '/tmp/fwcfg-check active' "$here/run-alpine-auto.sh"
grep -Fq 'freebsd-fwcfg-check active' "$here/run-5bsd-auto.sh"
grep -Fq '86abc0f5' "$here/run-5bsd-auto.sh"

# Cancellation records a process identity before the runner can reparent its
# descendants.  The live cancellation probe below proves that the recorded
# tree is drained; retain this source contract as well because PID reuse is
# neither fast nor deterministic enough to force in a normal self-test.
grep -Fq 'process=$(ps -o lstart= -o command= -p "$pid" 2>/dev/null)' \
    "$case_wrapper"
grep -Fq '[ -n "$process" ] || return 1' "$case_wrapper"
grep -Fq '[ "${#digest}" -eq 64 ] || return 1' "$case_wrapper"
! grep -Fq 'cksum' "$case_wrapper"
# Cancellation must bound the timeout wrapper itself as well as helpers that
# it may reparent.  Leaving the direct child outside the fingerprinted target
# set would make the final wait unbounded when that process ignores TERM.
grep -Fq 'direct_record=$(process_record "$child") || direct_record=' \
    "$case_wrapper"
grep -Fq 'targets="$direct_record$descendants"' "$case_wrapper"
grep -Fq 'for record in $targets; do' "$case_wrapper"
grep -Fq '[ -n "$direct_record" ] || kill -KILL "$child"' \
    "$case_wrapper"

# The manager records identities for daemon(8)'s supervisor and child before
# it may adopt or signal them.  A PID/PPID relationship alone can be reused,
# so malformed or mismatched records are stale/busy rather than cancellable.
grep -Fq 'local function process_fingerprint(pid)' "$lab"
grep -Fq ' -o lstart= -o command= 2>/dev/null", "r")' "$lab"
grep -Fq 'identity == nil or identity == "" or not closed' "$lab"
grep -Fq 'A vanished process must not acquire' "$lab"
grep -Fq 'local function process_fingerprint_matches(path, pid)' "$lab"
grep -Fq 'process_fingerprint_matches(status_path .. ".pid", supervisor)' \
    "$lab"
grep -Fq 'process_fingerprint_matches(status_path .. ".child", child)' \
    "$lab"
# A scan-time match alone is insufficient: a PID can be recycled before the
# later kill(2).  Cancellation must retain immutable fingerprints from the
# trusted scan and revalidate both members of the process tree immediately
# before signalling the child, without rereading mutable PID records.
grep -Fq 'local function supervised_case_identity(status_path)' "$lab"
grep -Fq 'process_fingerprint_value_matches(identity.supervisor_fingerprint,' \
    "$lab"
grep -Fq 'process_fingerprint_value_matches(identity.child_fingerprint,' \
    "$lab"
grep -Fq 'not reread the mutable run directory here' "$lab"
grep -Fq 'two bounded status scans' "$lab"
grep -Fq 'supervisor_pending .. ".fingerprint"' "$lab"
grep -Fq "daemon(8)'s pre-exec env(1) child" "$lab"

# The Unix control connector and AF_VSOCK connector intentionally report
# their retryable not-yet-listening outcome with different statuses.  Keep
# the ordinary data connector synchronized with the lifecycle connector.
grep -q '_retry_status=3' "$here/run-linux.sh"
grep -q '_retry_status=4' "$here/run-linux.sh"
grep -q '\[ "$_rc" -ne "$_retry_status" \]' "$here/run-linux.sh"

# A reset can invalidate a 9P or virtio-fs superblock before userspace sees
# the mount-table update.  The lifecycle harness must detach that stale mount
# and prove it is gone before rebind; a second EINVAL is acceptable only after
# that proof, never as a way to skip fresh device attachment.
grep -q '^guest_unmount_for_rebind()' "$here/run-alpine-auto.sh"
grep -Fq 'lazy_output=\$(LC_ALL=C umount -l' \
    "$here/run-alpine-auto.sh"
grep -q 'bound virtio-blk device is not openable' "$here/gblock.py"
grep -q 'virtio-scsi device is not openable' "$here/gscsi.py"
# Discovery alone is not a rebind completion condition.  Both storage
# verifiers must reject a regular file at a transient or maliciously stale
# /dev path before opening it for their real data-path operation.
grep -q 'require_block_device=True' "$here/gblock.py"
grep -q 'require_block_device=True' "$here/gscsi.py"
grep -q 'stat.S_ISBLK(node.st_mode)' "$here/gblock.py"
grep -q 'stat.S_ISBLK(node.st_mode)' "$here/gscsi.py"
grep -q "! grep -qs ' \$mountpoint ' /proc/mounts" \
    "$here/run-alpine-auto.sh"

# A review catalog is an input authority boundary.  A readable directory used
# to reach awk(1) and produce a misleading empty-catalog diagnostic; reject it
# before any parser runs so an accidental positional argument cannot look like
# a partial validation result.
private_validator=$tree_root/tests/sys/kern/vsock_device_harness/validate-virtio-nonstandard-interfaces.sh
grep -Fq '[ ! -f "$catalog" ] || [ ! -r "$catalog" ]' "$private_validator"
device_runner=$tree_root/tests/sys/kern/vsock_device_harness/run.sh
grep -Fq 'child = fork();' "$device_runner"
grep -Fq 'waitpid(child, &status, 0)' "$device_runner"
grep -Fq '#include <stdbool.h>' \
    "$tree_root/tests/sys/kern/vsock_device_harness/console_owner_test.c"
if sh "$private_validator" "$tree_root" >"$work/nonregular-catalog.out" 2>&1; then
	echo "non-regular private-interface catalog was accepted" >&2
	exit 1
fi
grep -Fq 'catalog is not a readable regular file' \
    "$work/nonregular-catalog.out"

# The two-VM kernel-vsock executor owns both bhyve processes and may create a
# bridge.  A signal must run cleanup and terminate; a combined cleanup trap
# would return into the scheduler after dismantling those resources.
multi_vsock_runner=$here/run-alpine-multi-vsock.sh
grep -Fq "trap 'cleanup \$?' EXIT" "$multi_vsock_runner"
grep -Fq "trap 'cleanup 129' HUP" "$multi_vsock_runner"
grep -Fq "trap 'cleanup 130' INT" "$multi_vsock_runner"
grep -Fq "trap 'cleanup 143' TERM" "$multi_vsock_runner"
! grep -Fq 'trap cleanup EXIT INT TERM HUP' "$multi_vsock_runner"
for terminal_runner in \
    "$here/build-vmm-module.sh" \
    "$here/build-5bsd-virtio-modules.sh" \
    "$here/host-tools-selftest.sh" \
    "$here/run-5bsd-auto.sh" \
    "$tree_root/tests/sys/kern/vsock_device_harness/validate-bhyve-build-modes.sh"; do
	grep -Fq "trap 'cleanup \$?' EXIT" "$terminal_runner" ||
	    grep -Fq "trap 'cleanup_all \$?' EXIT" "$terminal_runner"
	grep -Fq "trap 'cleanup 129' HUP" "$terminal_runner" ||
	    grep -Fq "trap 'cleanup_all 129' HUP" "$terminal_runner"
	grep -Fq "trap 'cleanup 130' INT" "$terminal_runner" ||
	    grep -Fq "trap 'cleanup_all 130' INT" "$terminal_runner"
	grep -Fq "trap 'cleanup 143' TERM" "$terminal_runner" ||
	    grep -Fq "trap 'cleanup_all 143' TERM" "$terminal_runner"
done

# sysfs bind and unbind writes complete the kernel driver's attach/detach
# operation synchronously.  Device-node publication is settled separately;
# do not reintroduce a sleep-based poll for the driver symlink itself.
grep -q 'synchronous kernel boundary' "$here/run-alpine-auto.sh"
grep -q 'assert_unbound()' "$here/run-alpine-auto.sh"
grep -q 'assert_bound()' "$here/run-alpine-auto.sh"
! grep -q 'while \[ -L \\"/sys/bus/pci/devices/\\\$bdf/driver\\" \]' \
    "$here/run-alpine-auto.sh"
! grep -q 'while \[ ! -L \\"/sys/bus/pci/devices/\\\$bdf/driver\\" \]' \
    "$here/run-alpine-auto.sh"

# The detached daemon(8) process model leaves the lab manager without a
# waitpid(2)-eligible child.  Its sole one-second status-file scan is therefore
# a documented, bounded supervisor wait, never a guest-I/O retry mechanism.
# Keep that distinction mechanically visible: new sleep-based device waits
# belong on an event/callback boundary instead.
[ "$(grep -Fc 'os.execute("/bin/sleep 1")' "$lab")" -eq 1 ]
grep -Fq 'the only periodic' "$lab"
grep -Fq 'not a device retry' "$lab"

# Every declared guest qualification, including the one associated with an
# exercised feature, must remain reachable through the complete qualification
# graph.  Repointing it at a VM-free case is structurally valid TSV, but the
# generic planned-qualification gate must reject it before the narrower
# exercised-evidence check is reached.
activation_validator="$here/../vsock_device_harness/validate-virtio-requirements.sh"
activation_ledger="$work/activation.tsv"
cp "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    "$activation_ledger"
awk -F '\t' 'BEGIN { OFS="\t" }
NR == 1 { print; next }
$1 == "NET-MULTIQUEUE" { $8 = "vmfree-host-tools" }
{ print }' "$activation_ledger" >"$activation_ledger.rewritten"
mv "$activation_ledger.rewritten" "$activation_ledger"
if SRCTOP="$tree_root" sh "$activation_validator" '' '' "$tree_root" \
    "$activation_ledger" >"$work/activation.out" 2>&1; then
	echo "qualification ledger accepted a smoke-only exercised Linux case" >&2
	exit 1
fi
grep -Fq \
    'planned linux qualification is outside full-qualification: vmfree-host-tools' \
    "$work/activation.out"

# Planned evidence must be just as reachable as exercised evidence.  This
# protects the deferred qualification backlog: a future promotion must not
# discover that its ledger case was only ever reachable from a VM-free smoke
# profile, nor accidentally schedule the Linux claim through a 5BSD runner.
cp "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    "$activation_ledger"
awk -F '\t' 'BEGIN { OFS="\t" }
NR == 1 { print; next }
$1 == "PMEM-ASYNC-WORKER" { $8 = "vmfree-host-tools" }
{ print }' "$activation_ledger" >"$activation_ledger.rewritten"
mv "$activation_ledger.rewritten" "$activation_ledger"
if SRCTOP="$tree_root" sh "$activation_validator" '' '' "$tree_root" \
    "$activation_ledger" >"$work/pending-activation.out" 2>&1; then
	echo "qualification ledger accepted a smoke-only pending Linux case" >&2
	exit 1
fi
grep -Fq \
    'planned linux qualification is outside full-qualification: vmfree-host-tools' \
    "$work/pending-activation.out"

cp "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    "$activation_ledger"
awk -F '\t' 'BEGIN { OFS="\t" }
NR == 1 { print; next }
$1 == "PMEM-ASYNC-WORKER" { $8 = "fivebsd-virtio" }
{ print }' "$activation_ledger" >"$activation_ledger.rewritten"
mv "$activation_ledger.rewritten" "$activation_ledger"
if SRCTOP="$tree_root" sh "$activation_validator" '' '' "$tree_root" \
    "$activation_ledger" >"$work/wrong-guest-activation.out" 2>&1; then
	echo "qualification ledger accepted a Linux claim through a 5BSD executor" >&2
	exit 1
fi
grep -Fq \
    'planned linux qualification uses wrong executor fivebsd-auto: fivebsd-virtio' \
    "$work/wrong-guest-activation.out"

# Every packed device gets an individual ledger row.  Removing virtio-fs's
# row would still leave the generic RING_PACKED requirement represented by
# other devices, so make the per-device source-to-ledger rule fail closed.
cp "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    "$activation_ledger"
awk -F '\t' 'BEGIN { OFS="\t" }
NR == 1 { print; next }
$1 == "FS-PACKED" { $7 = "-" }
{ print }' "$activation_ledger" >"$activation_ledger.rewritten"
mv "$activation_ledger.rewritten" "$activation_ledger"
if SRCTOP="$tree_root" sh "$activation_validator" '' '' "$tree_root" \
    "$activation_ledger" >"$work/missing-packed-device-row.out" 2>&1; then
	echo "qualification ledger accepted a packed device without its anchor" >&2
	exit 1
fi
grep -Fq \
    'packed opt-in vtfs lacks a device-specific ledger row' \
    "$work/missing-packed-device-row.out"

# The packed-device list is an allow-list, rather than merely a convenient
# enumeration of today's models.  Give the validator an isolated source-tree
# overlay containing an otherwise unledgered producer: a future PCI model
# cannot advertise RING_PACKED and inherit another device's activation row.
packed_tree="$work/packed-source-tree"
prepare_validator_tree "$packed_tree"
cat >"$packed_tree/usr.sbin/bhyve/pci_virtio_unledgered.c" <<'EOF'
/* Deliberately minimal test-only packed producer. */
static bool unledgered_packed = get_config_bool_node_default(nvl, "packed", false);
static const unsigned long unledgered_feature = VIRTIO_F_RING_PACKED;
EOF
if SRCTOP="$packed_tree" sh "$activation_validator" '' '' "$packed_tree" \
    "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    >"$work/unledgered-packed-producer.out" 2>&1; then
	echo "qualification ledger accepted an unledgered packed producer" >&2
	exit 1
fi
grep -Fq \
    'unledgered packed producer: pci_virtio_unledgered.c' \
    "$work/unledgered-packed-producer.out"

# Snapshot validation is not optional framework decoration.  Remove one
# production registration in an isolated overlay and require the source audit
# to reject the otherwise normal-looking device before a checkpoint runner can
# treat it as save-only.
snapshot_tree="$work/snapshot-source-tree"
prepare_validator_tree "$snapshot_tree"
awk '!/^[[:space:]]*\.pe_snapshot_validate[[:space:]]*=/' \
    "$snapshot_tree/usr.sbin/bhyve/pci_virtio_rnd.c" \
    >"$snapshot_tree/usr.sbin/bhyve/pci_virtio_rnd.c.rewritten"
mv "$snapshot_tree/usr.sbin/bhyve/pci_virtio_rnd.c.rewritten" \
    "$snapshot_tree/usr.sbin/bhyve/pci_virtio_rnd.c"
if SRCTOP="$snapshot_tree" sh "$activation_validator" '' '' "$snapshot_tree" \
    "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    >"$work/missing-snapshot-registration.out" 2>&1; then
	echo "qualification ledger accepted a save-only PCI VirtIO model" >&2
	exit 1
fi
grep -Fq \
    'snapshot registration missing pe_snapshot_validate: pci_virtio_rnd.c' \
    "$work/missing-snapshot-registration.out"

# Modern transport state must remain portable even though the retained legacy
# checkpoint record intentionally uses native-width helpers.  Mutate only the
# modern common-state function in an isolated source overlay and prove the
# requirements audit names that precise portability regression.
portable_snapshot_tree="$work/portable-snapshot-source-tree"
prepare_validator_tree "$portable_snapshot_tree"
awk '
/^vi_pci_snapshot_softc_modern\(/ { target = 1 }
target && /^\{/ {
	print
	print "\tSNAPSHOT_VAR_OR_LEAVE(portability_probe, meta, ret, done);"
	target = 0
	next
}
{ print }
' "$portable_snapshot_tree/usr.sbin/bhyve/virtio.c" \
    >"$portable_snapshot_tree/usr.sbin/bhyve/virtio.c.rewritten"
mv "$portable_snapshot_tree/usr.sbin/bhyve/virtio.c.rewritten" \
    "$portable_snapshot_tree/usr.sbin/bhyve/virtio.c"
if SRCTOP="$portable_snapshot_tree" sh "$activation_validator" '' '' \
    "$portable_snapshot_tree" \
    "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    >"$work/native-width-modern-snapshot.out" 2>&1; then
	echo "qualification audit accepted native-width modern snapshot state" >&2
	exit 1
fi
if ! grep -Fq \
    'modern common snapshot uses native-width helper:' \
    "$work/native-width-modern-snapshot.out"; then
	cat "$work/native-width-modern-snapshot.out" >&2
	echo "native-width modern snapshot mutation failed for the wrong reason" >&2
	exit 1
fi
grep -Fq 'vi_pci_snapshot_softc_modern:' \
    "$work/native-width-modern-snapshot.out"

cp "$here/../vsock_device_harness/virtio-feature-activation.tsv" \
    "$activation_ledger"
awk -F '\t' 'BEGIN { OFS="\t" }
NR == 1 { print; next }
$1 == "FIVEBSD-BALLOON-REQUEST-FAILURE" { $9 = "balloon-modern" }
{ print }' "$activation_ledger" >"$activation_ledger.rewritten"
mv "$activation_ledger.rewritten" "$activation_ledger"
if SRCTOP="$tree_root" sh "$activation_validator" '' '' "$tree_root" \
    "$activation_ledger" >"$work/wrong-fivebsd-activation.out" 2>&1; then
	echo "qualification ledger accepted a 5BSD claim through a Linux executor" >&2
	exit 1
fi
grep -Fq \
    'planned fivebsd qualification uses wrong executor alpine-auto: balloon-modern' \
    "$work/wrong-fivebsd-activation.out"

"$LUA" "$lab" host-status --bridge vltest0 >"$work/host-status"
grep -q '^bridge=vltest0$' "$work/host-status"
grep -q '^exists=no$' "$work/host-status"
grep -q '^managed=no$' "$work/host-status"

if "$LUA" "$lab" host-prepare --bridge vltest0 \
    >"$work/host-prepare-missing.out" 2>&1; then
	echo "host-prepare without an uplink unexpectedly passed" >&2
	exit 1
fi
grep -q 'host-prepare requires --uplink' "$work/host-prepare-missing.out"

if "$LUA" "$lab" host-status --bridge '../bad' \
    >"$work/host-invalid.out" 2>&1; then
	echo "invalid bridge name unexpectedly passed" >&2
	exit 1
fi
grep -q 'bridge must be a valid interface name' "$work/host-invalid.out"

if "$LUA" "$lab" run --manifest "$manifest" --profile vmfree \
    --prepare-host --workdir "$work/prepare-missing" \
    >"$work/prepare-missing.out" 2>&1; then
	echo "run --prepare-host without an uplink unexpectedly passed" >&2
	exit 1
fi
grep -q -- '--prepare-host requires --uplink' "$work/prepare-missing.out"

# Nested VMX must reject an incomplete immutable L1/L2 corpus before the
# root-only host regression gate can consume any time or mutate host state.
if "$LUA" "$lab" run --manifest "$manifest" --profile nested \
    --workdir "$work/nested-missing-input" \
    >"$work/nested-missing-input.out" 2>&1; then
	echo "nested run without its L1/L2 corpus unexpectedly passed" >&2
	exit 1
fi
grep -q -- 'nested-vmx-live requires --set NESTED_L1_RUNNER=/absolute/path' \
    "$work/nested-missing-input.out"

if "$LUA" "$lab" plan --manifest "$manifest" --prepare-host \
    >"$work/prepare-command.out" 2>&1; then
	echo "plan --prepare-host unexpectedly passed" >&2
	exit 1
fi
grep -q -- '--prepare-host is valid only with run' "$work/prepare-command.out"

# Host preparation publishes a durable ownership record after each bridge
# mutation.  That write must be fallible at this layer: the generic helper
# terminates on I/O failure and would bypass the local rollback callback.
# Also keep cleanup from destroying a lab-created bridge when the configured
# uplink was attached by someone else.
host_writer=$(sed -n '/^local function write_host_state/,/^local function read_host_state/p' "$lab")
! printf '%s\n' "$host_writer" | grep -Fq 'write_file('
printf '%s\n' "$host_writer" | grep -Fq 'cannot write host state file'
grep -Fq 'mutation rolled back' "$lab"
grep -Fq 'if member ~= state.uplink or not state.member_added then' "$lab"

"$LUA" "$lab" plan --manifest "$manifest" --profile smoke >"$work/smoke"
"$LUA" "$lab" plan --manifest "$manifest" --profile checkpoint \
    >"$work/checkpoint"
"$LUA" "$lab" --help >"$work/help" 2>&1
grep -q -- '--cid-lease-dir path' "$work/help"
# An unrecognised verb is never a successful empty run.  Keep this explicit:
# operators commonly paste a profile name here, while the lab accepts only
# plan, coverage, run, status, cancel, and host lifecycle verbs.
if "$LUA" "$lab" selftest >"$work/unknown-command.out" 2>&1; then
	echo "unknown virtio-lab command unexpectedly passed" >&2
	exit 1
fi
grep -q '^usage: virtio-lab.lua ' "$work/unknown-command.out"
grep -q 'mkdir(2) gives this' "$lab"
grep -q 'explicit CID allocation is not remapped' "$lab"
grep -q 'resource lease directory must be caller-owned mode 0700' "$lab"
grep -q 'release_case_resources(running.resource_allocation)' "$lab"
[ "$(grep -c '^cases=18$' "$work/smoke")" -eq 1 ]

# The standalone checkpoint profile is intentionally broader than the small
# four-case historical smoke used while checkpoint support was first brought
# up.  Keep its complete device/ring/back-end matrix directly enumerated here:
# qualification composition counts alone would not identify a case silently
# removed from the checkpoint profile while another profile still contained
# the device.
[ "$(grep -c '^cases=67$' "$work/checkpoint")" -eq 1 ]
grep -Fq '9p:*|fs:*|gpu:*' "$tree_root/tests/sys/kern/vsock_e2e/run-alpine-auto.sh"
tab=$(printf '\t')
for checkpoint_case in \
    checkpoint-net-packed-modern \
    checkpoint-iommu-combined-packed-modern \
    checkpoint-balloon-packed-modern \
    checkpoint-rtc-alarm-packed-modern \
    checkpoint-gpu-blob-iommu-modern \
    checkpoint-mem-packed-modern \
    checkpoint-pmem-packed-modern \
    checkpoint-sound-packed-modern \
    checkpoint-block-packed-modern \
    checkpoint-scsi-packed-modern \
    checkpoint-vsock-kernel-multi \
    checkpoint-console-packed-modern \
    checkpoint-input-packed-modern \
    checkpoint-9p-packed-modern \
    checkpoint-fs-active-packed-modern \
    checkpoint-combined-modern \
    checkpoint-combined-packed-modern \
    fivebsd-checkpoint-combined-modern \
    fivebsd-checkpoint-combined-packed-modern; do
	grep -q "^${checkpoint_case}${tab}" "$work/checkpoint"
done

# CID leases are process-independent: an occupied generated CID advances by
# one reviewed allocation lane, whereas an operator-supplied CID fails rather
# than silently changing the requested VM identity.  Use the scheduler probe
# so this remains a rootless orchestration test.
mkdir "$work/cid-leases"
chmod 700 "$work/cid-leases"
mkdir "$work/cid-leases/1004" "$work/cid-leases/tcp-10004"
printf '%s\n' foreign >"$work/cid-leases/1004/owner"
printf '%s\n' foreign >"$work/cid-leases/tcp-10004/owner"
cat >"$work/cid-lease.yaml" <<'EOF'
---
version: 1
defaults:
  timeout: 20
  env:
    DEVICES: vsock
cases:
  - id: generated-cid
    executor: orchestrator-probe
    profiles: [smoke]
EOF
mkdir "$work/cid-lease-target"
chmod 700 "$work/cid-lease-target"
ln -s "$work/cid-lease-target" "$work/cid-lease-link"
if "$LUA" "$lab" run --manifest "$work/cid-lease.yaml" --profile smoke \
    --cid-lease-dir "$work/cid-lease-link" --workdir "$work/cid-link-run" \
    >"$work/cid-link.out" 2>&1; then
	echo "symlinked CID lease directory unexpectedly passed" >&2
	exit 1
fi
grep -q 'resource lease directory must be caller-owned mode 0700' "$work/cid-link.out"
[ ! -e "$work/cid-link-run/manager.lock" ]
mkdir "$work/cancel-target"
chmod 700 "$work/cancel-target"
ln -s "$work/cancel-target" "$work/cancel-link"
if "$LUA" "$lab" cancel --workdir "$work/cancel-link" \
    >"$work/cancel-link.out" 2>&1; then
	echo "symlinked cancellation directory unexpectedly passed" >&2
	exit 1
fi
grep -q 'cancel requires root or a caller-owned mode-0700 run directory' \
    "$work/cancel-link.out"
"$LUA" "$lab" run --manifest "$work/cid-lease.yaml" --profile smoke \
    --cid-lease-dir "$work/cid-leases" --workdir "$work/cid-run" \
    >"$work/cid-run.out"
grep -q '^passed=1$' "$work/cid-run.out"
grep -q 'cid=1008 .*console=10008' \
    "$work/cid-run/logs/generated-cid.attempt1.log"
[ -d "$work/cid-leases/1004" ]
[ -d "$work/cid-leases/tcp-10004" ]
[ ! -e "$work/cid-leases/1008" ]
[ ! -e "$work/cid-leases/tcp-10008" ]

# Three independently supervised VM-shaped cases must overlap, and collision
# remapping must keep both their CIDs and TCP consoles distinct while foreign
# leases remain untouched.
cat >"$work/coexist.yaml" <<'EOF'
---
version: 1
defaults:
  timeout: 20
  env:
    DEVICES: vsock
cases:
  - id: coexist-one
    executor: orchestrator-probe
    profiles: [coexist]
    env: { LAB_PROBE_NAME: one, LAB_PROBE_SLEEP: "3" }
  - id: coexist-two
    executor: orchestrator-probe
    profiles: [coexist]
    env: { LAB_PROBE_NAME: two, LAB_PROBE_SLEEP: "3" }
  - id: coexist-three
    executor: orchestrator-probe
    profiles: [coexist]
    env: { LAB_PROBE_NAME: three, LAB_PROBE_SLEEP: "3" }
EOF
"$LUA" "$lab" run --manifest "$work/coexist.yaml" --profile coexist \
    --jobs 3 --cid-lease-dir "$work/cid-leases" \
    --workdir "$work/coexist-run" >"$work/coexist.out"
first_pass=$(awk -F '\t' '$2 == "PASS" { print NR; exit }' \
    "$work/coexist-run/events.tsv")
[ "$(awk -F '\t' -v limit="$first_pass" \
    'NR < limit && $2 == "START" { n++ } END { print n + 0 }' \
    "$work/coexist-run/events.tsv")" -eq 3 ]
[ "$(awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^cid=/) { sub(/^cid=/, "", $i); print $i } }' \
    "$work/coexist-run/logs/"*.log | sort -u | wc -l)" -eq 3 ]
[ "$(awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^console=/) { sub(/^console=/, "", $i); print $i } }' \
    "$work/coexist-run/logs/"*.log | sort -u | wc -l)" -eq 3 ]
[ -d "$work/cid-leases/1004" ]
[ -d "$work/cid-leases/tcp-10004" ]
[ "$(find "$work/cid-leases" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 2 ]
[ ! -e "$work/cid-run/manager.lock" ]
# Simulate an interrupted manager: the case has a terminal failure status,
# but its own CID and console-port leases were not released.  Resume must
# reclaim exactly those leases after proving no supervisor remains; otherwise
# the allocator would silently advance from 1008 to 1012.
mkdir "$work/cid-leases/1008" "$work/cid-leases/tcp-10008"
printf '%s\t%s\n' "$work/cid-run" generated-cid > \
    "$work/cid-leases/1008/owner"
printf '%s\t%s\n' "$work/cid-run" generated-cid > \
    "$work/cid-leases/tcp-10008/owner"
printf '1\n' > "$work/cid-run/status/generated-cid"
"$LUA" "$lab" run --manifest "$work/cid-lease.yaml" --profile smoke \
    --cid-lease-dir "$work/cid-leases" --workdir "$work/cid-run" --resume \
    >"$work/cid-resume-stale-lease.out"
grep -q '^passed=1$' "$work/cid-resume-stale-lease.out"
grep -q 'cid=1008 .*console=10008' \
    "$work/cid-run/logs/generated-cid.attempt2.log"
[ ! -e "$work/cid-leases/1008" ]
[ ! -e "$work/cid-leases/tcp-10008" ]
# A manager can also be interrupted just after recording a successful case.
# Resume must reclaim that completed case's lease rather than preserving an
# allocation which no live process owns.
mkdir "$work/cid-leases/1008" "$work/cid-leases/tcp-10008"
printf '%s\t%s\n' "$work/cid-run" generated-cid > \
    "$work/cid-leases/1008/owner"
printf '%s\t%s\n' "$work/cid-run" generated-cid > \
    "$work/cid-leases/tcp-10008/owner"
"$LUA" "$lab" run --manifest "$work/cid-lease.yaml" --profile smoke \
    --cid-lease-dir "$work/cid-leases" --workdir "$work/cid-run" --resume \
    >"$work/cid-resume-success-lease.out"
grep -q '^passed=1$' "$work/cid-resume-success-lease.out"
[ ! -e "$work/cid-leases/1008" ]
[ ! -e "$work/cid-leases/tcp-10008" ]
mkdir "$work/cid-run/manager.lock"
printf '%s\n' "$$" >"$work/cid-run/manager.lock/owner"
if "$LUA" "$lab" run --manifest "$work/cid-lease.yaml" --profile smoke \
    --cid-lease-dir "$work/cid-leases" --workdir "$work/cid-run" --resume \
    >"$work/cid-manager-busy.out" 2>&1; then
	echo "concurrent run-manager unexpectedly passed" >&2
	exit 1
fi
grep -q 'run directory is already managed by PID' "$work/cid-manager-busy.out"
rm "$work/cid-run/manager.lock/owner"
rmdir "$work/cid-run/manager.lock"
mkdir "$work/cid-run/manager.lock"
printf '%s\n' 99999999 >"$work/cid-run/manager.lock/owner"
"$LUA" "$lab" run --manifest "$work/cid-lease.yaml" --profile smoke \
    --cid-lease-dir "$work/cid-leases" --workdir "$work/cid-run" --resume \
    >"$work/cid-manager-stale.out"
grep -q '^passed=1$' "$work/cid-manager-stale.out"
[ ! -e "$work/cid-run/manager.lock" ]
mkdir "$work/cid-leases/2000"
printf '%s\n' foreign >"$work/cid-leases/2000/owner"
cat >"$work/cid-explicit.yaml" <<'EOF'
---
version: 1
defaults:
  timeout: 20
  env:
    DEVICES: vsock
    CID: "2000"
cases:
  - id: explicit-cid
    executor: orchestrator-probe
    profiles: [smoke]
EOF
if "$LUA" "$lab" run --manifest "$work/cid-explicit.yaml" \
    --profile smoke --cid-lease-dir "$work/cid-leases" \
    --workdir "$work/cid-explicit-run" >"$work/cid-explicit.out" 2>&1; then
	echo "explicit occupied CID unexpectedly passed" >&2
	exit 1
fi
grep -q 'explicit CID allocation is not remapped' "$work/cid-explicit.out"

cat >"$work/port-explicit.yaml" <<'EOF'
---
version: 1
defaults:
  timeout: 20
  env:
    DEVICES: vsock
    CID: "3000"
    CONSOLE_PORT: "10004"
cases:
  - id: explicit-port
    executor: orchestrator-probe
    profiles: [smoke]
EOF
if "$LUA" "$lab" run --manifest "$work/port-explicit.yaml" \
    --profile smoke --cid-lease-dir "$work/cid-leases" \
    --workdir "$work/port-explicit-run" >"$work/port-explicit.out" 2>&1; then
	echo "explicit occupied TCP port unexpectedly passed" >&2
	exit 1
fi
grep -q 'explicit TCP port allocation is not remapped' \
    "$work/port-explicit.out"
[ ! -e "$work/cid-leases/3000" ]
grep -Fq 'case.executor == "alpine-multi-vsock"' "$lab"
grep -Fq 'case.executor == "fivebsd-auto"' "$lab"
[ -x "$here/build-5bsd-virtio-modules.sh" ]
grep -q '^SCRIPTS+=.*build-5bsd-virtio-modules.sh$' "$here/Makefile"
[ -x "$here/build-vmm-module.sh" ]
grep -q '^SCRIPTS+=.*build-vmm-module.sh$' "$here/Makefile"
[ "$(grep -c '^vmfree-device	' "$work/smoke")" -eq 1 ]
[ "$(grep -c '^fivebsd-module-build	' "$work/smoke")" -eq 1 ]
grep -q '^cases=18$' "$work/smoke"
grep -q '^pmem-modern	' "$work/smoke"

"$LUA" "$lab" plan --manifest "$manifest" --profile checkpoint \
    --case checkpoint-rtc-alarm-packed-modern \
    --case checkpoint-balloon-packed-modern \
    --case checkpoint-rtc-alarm-modern \
    --case checkpoint-balloon-modern >"$work/focused-checkpoint"
grep -q '^cases=4$' "$work/focused-checkpoint"
[ "$(grep -c '^checkpoint-.*-modern	' "$work/focused-checkpoint")" -eq 4 ]
[ "$(sed -n '1s/	.*//p' "$work/focused-checkpoint")" = \
    checkpoint-balloon-modern ]
[ "$(sed -n '2s/	.*//p' "$work/focused-checkpoint")" = \
    checkpoint-balloon-packed-modern ]
[ "$(sed -n '3s/	.*//p' "$work/focused-checkpoint")" = \
    checkpoint-rtc-alarm-modern ]
[ "$(sed -n '4s/	.*//p' "$work/focused-checkpoint")" = \
    checkpoint-rtc-alarm-packed-modern ]
! grep -q '^COVERED	' "$work/focused-checkpoint"

if "$LUA" "$lab" plan --manifest "$manifest" --profile checkpoint \
    --case no-such-case >"$work/unknown-case.out" 2>&1; then
	echo "unknown case selection unexpectedly passed" >&2
	exit 1
fi
grep -q 'unknown --case id: no-such-case' "$work/unknown-case.out"

if "$LUA" "$lab" plan --manifest "$manifest" --profile smoke \
    --case checkpoint-balloon-modern >"$work/outside-profile.out" 2>&1; then
	echo "out-of-profile case selection unexpectedly passed" >&2
	exit 1
fi
grep -q -- '--case checkpoint-balloon-modern is not in profile smoke' \
    "$work/outside-profile.out"

if "$LUA" "$lab" plan --manifest "$manifest" --profile checkpoint \
    --case checkpoint-balloon-modern --case checkpoint-balloon-modern \
    >"$work/duplicate-case.out" 2>&1; then
	echo "duplicate case selection unexpectedly passed" >&2
	exit 1
fi
grep -q 'duplicate --case id: checkpoint-balloon-modern' \
    "$work/duplicate-case.out"

if "$LUA" "$lab" coverage --manifest "$manifest" --profile checkpoint \
    --case checkpoint-balloon-modern >"$work/filtered-coverage.out" 2>&1; then
	echo "filtered coverage unexpectedly passed" >&2
	exit 1
fi
grep -q -- '--case is not valid with coverage' "$work/filtered-coverage.out"

"$LUA" "$lab" coverage --manifest "$manifest" --profile release \
    >"$work/release"
grep -q '^SCOPE	declarative-profile; runtime results are not implied$' \
    "$work/release"
[ "$(grep -c '^COVERED	' "$work/release")" -eq 93 ]
grep -q '^COVERED	pmem-ring-formats$' "$work/release"
grep -q '^COVERED	pmem-capacity-boundaries$' "$work/release"
awk '
    /- id: checkpoint-devices$/ { in_contract = 1; next }
    in_contract && /- id:/ { exit }
    in_contract && /values:/ && /fs/ { found = 1 }
    END { exit found ? 0 : 1 }
' "$manifest"
awk '
    /- id: reset-devices$/ { in_contract = 1; next }
    in_contract && /- id:/ { exit }
    in_contract && /values:/ && /fs/ { found = 1 }
    END { exit found ? 0 : 1 }
' "$manifest"
grep -q '^COVERED	fivebsd-balloon-deflate-on-oom$' "$work/release"
grep -q '^COVERED	fivebsd-balloon-page-poison$' "$work/release"
grep -q '^COVERED	fivebsd-block-write-zeroes-toggle$' "$work/release"
grep -q '^COVERED	fivebsd-ninep-testing$' "$work/release"
grep -q '^COVERED	fivebsd-ninep-ring-formats$' "$work/release"
grep -q '^COVERED	iommu-reset-lifecycle$' "$work/release"
grep -q '^COVERED	iommu-endpoint-devices$' "$work/release"
grep -q '^COVERED	checkpoint-restore-compatibility-rejection$' \
    "$work/release"
grep -q '^COVERED	gpu-blob-reset-lifecycle$' "$work/release"
grep -q '^COVERED	rtc-alarm-reset-lifecycle$' "$work/release"
! grep -q '^MISSING	' "$work/release"

"$LUA" "$lab" plan --manifest "$manifest" --profile audio >"$work/audio"
grep -q '^cases=4$' "$work/audio"
[ "$(grep -c '^host-regression	' "$work/audio")" -eq 1 ]
[ "$(grep -c '^fivebsd-module-build	' "$work/audio")" -eq 1 ]
[ "$(grep -c '^sound-oss-.*-modern	' "$work/audio")" -eq 1 ]
[ "$(grep -c '^sound-oss-modern	' "$work/audio")" -eq 1 ]
[ "$(grep -c '	audio	sound	modern	' "$work/audio")" -eq 2 ]
grep -q '^COVERED	sound-host-audio-backends$' "$work/audio"
grep -q '^COVERED	sound-host-audio-ring-formats$' "$work/audio"
! grep -q '^MISSING	' "$work/audio"

"$LUA" "$lab" plan --manifest "$manifest" --profile audio-qualification \
    >"$work/audio-qualification"
grep -q '^cases=6$' "$work/audio-qualification"
[ "$(grep -c '^host-regression	' "$work/audio-qualification")" -eq 1 ]
[ "$(grep -c '^fivebsd-module-build	' "$work/audio-qualification")" -eq 1 ]
[ "$(grep -c '^sound-oss-modern	' "$work/audio-qualification")" -eq 1 ]
[ "$(grep -c '^sound-oss-packed-modern	' \
    "$work/audio-qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-sound-oss-modern	' \
    "$work/audio-qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-sound-oss-packed-modern	' \
    "$work/audio-qualification")" -eq 1 ]
grep -q '^COVERED	sound-host-audio-checkpoint-ring-formats$' \
    "$work/audio-qualification"
! grep -q '^MISSING	' "$work/audio-qualification"

"$LUA" "$lab" coverage --manifest "$manifest" --profile soak \
    >"$work/soak"
[ "$(grep -c '^COVERED	' "$work/soak")" -eq 11 ]
! grep -q '^MISSING	' "$work/soak"

# Soak is release evidence, not an open-ended ad hoc loop.  Keep the
# independent endurance lanes present in the scheduler: both host-vsock
# providers, the ordinary device fabric, provisional devices, and the
# translated-DMA fabric.  The bounded `soak-smoke` screen below deliberately
# has the same lanes with smaller iteration counts.
"$LUA" "$lab" plan --manifest "$manifest" --profile soak \
    >"$work/soak-plan"
grep -q '^cases=7$' "$work/soak-plan"
for soak_case in \
    soak-vsock-userspace \
    soak-vsock-kernel \
    soak-reset-devices \
    soak-reset-optional-devices \
    soak-reset-iommu-fabric; do
	grep -q "^${soak_case}${tab}" "$work/soak-plan"
done

"$LUA" "$lab" plan --manifest "$manifest" --profile soak-smoke \
    >"$work/soak-smoke-plan"
grep -q '^cases=7$' "$work/soak-smoke-plan"
"$LUA" "$lab" coverage --manifest "$manifest" --profile soak-smoke \
    >"$work/soak-smoke"
[ "$(grep -c '^COVERED	' "$work/soak-smoke")" -eq 10 ]
! grep -q '^MISSING	' "$work/soak-smoke"

"$LUA" "$lab" plan --manifest "$manifest" --profile qualification \
    --fivebsd-image /tmp/disposable-5bsd.img >"$work/qualification"
grep -q '^cases=227$' "$work/qualification"
[ "$(grep -c '^kernel-contract-root	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^vmm-root	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^host-regression	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^fivebsd-module-build	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^fivebsd-block-write-zeroes	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-net-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^pmem-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^pmem-packed-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-pmem-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-pmem-packed-modern	' \
    "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-sound-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-sound-packed-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^rtc-alarm-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^rtc-alarm-packed-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-rtc-alarm-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-rtc-alarm-packed-modern	' \
    "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-gpu-blob-modern	' \
    "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-gpu-blob-packed-modern	' \
    "$work/qualification")" -eq 1 ]
[ "$(grep -c '^iommu-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^iommu-packed-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^iommu-combined-packed-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-iommu-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-iommu-packed-modern	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-iommu-combined-packed-modern	' \
    "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-fs-active-modern	' \
    "$work/qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-fs-active-packed-modern	' \
    "$work/qualification")" -eq 1 ]
[ "$(grep -c '^soak-vsock-userspace	' "$work/qualification")" -eq 1 ]
[ "$(grep -c '^COVERED	' "$work/qualification")" -eq 155 ]
grep -q '^COVERED	gpu-blob-checkpoint-lifecycle$' "$work/qualification"
grep -q '^COVERED	gpu-presentation-checkpoint-lifecycle$' "$work/qualification"
grep -q '^COVERED	checkpoint-balloon-deflate-on-oom$' "$work/qualification"
grep -q '^COVERED	checkpoint-balloon-free-page-hinting$' "$work/qualification"
grep -q '^COVERED	checkpoint-balloon-free-page-reporting$' "$work/qualification"
grep -q '^COVERED	checkpoint-balloon-page-poison$' "$work/qualification"
grep -q '^COVERED	checkpoint-iommu-endpoint-devices$' "$work/qualification"
grep -q '^COVERED	rtc-alarm-checkpoint-lifecycle$' "$work/qualification"
grep -q '^COVERED	checkpoint-block-discard$' "$work/qualification"
grep -q '^COVERED	checkpoint-block-readonly$' "$work/qualification"
grep -q '^COVERED	checkpoint-scsi-events$' "$work/qualification"
grep -q '^COVERED	checkpoint-console-port-counts$' "$work/qualification"
grep -q '^COVERED	checkpoint-input-device-counts$' "$work/qualification"
grep -q '^COVERED	fs-checkpoint-queue-boundaries$' "$work/qualification"
grep -q '^COVERED	checkpoint-vsock-backends$' "$work/qualification"
grep -q '^COVERED	checkpoint-vsock-multi-provider$' "$work/qualification"
grep -q '^COVERED	checkpoint-pmem-active-io$' "$work/qualification"
grep -q '^COVERED	checkpoint-pmem-backend-rejection$' \
    "$work/qualification"
grep -q '^COVERED	checkpoint-pmem-repeated-restore$' \
    "$work/qualification"
grep -q '^COVERED	checkpoint-net-multiqueue$' "$work/qualification"
grep -q '^COVERED	checkpoint-block-multiqueue$' "$work/qualification"
grep -q '^COVERED	checkpoint-scsi-multiqueue$' "$work/qualification"
grep -q '^COVERED	checkpoint-restore-compatibility-rejection$' \
    "$work/qualification"
grep -q '^COVERED	checkpoint-restore-feature-rejection$' \
    "$work/qualification"
grep -q '^COVERED	fivebsd-ninep-testing$' "$work/qualification"
grep -q '^COVERED	nonvirtio-alpine-checkpoint-devices$' \
    "$work/qualification"
grep -q '^COVERED	nonvirtio-fivebsd-checkpoint-devices$' \
    "$work/qualification"
! grep -q '^MISSING	' "$work/qualification"

"$LUA" "$lab" plan --manifest "$manifest" --profile vmm-root \
    >"$work/vmm-root-plan"
grep -q '^cases=1$' "$work/vmm-root-plan"
grep -q '^vmm-root	vmm-root	1800	compiler,vmm-module	' \
    "$work/vmm-root-plan"

"$LUA" "$lab" plan --manifest "$manifest" --profile kernel-root \
    >"$work/kernel-root-plan"
grep -q '^cases=1$' "$work/kernel-root-plan"
grep -q '^kernel-contract-root	kernel-contract-root	300	compiler,kernel-module	' \
    "$work/kernel-root-plan"

"$LUA" "$lab" plan --manifest "$manifest" --profile vmfree \
    >"$work/vmfree-plan"
grep -q '^vmfree-nested-vmx-model	nested-vmx-model	' "$work/vmfree-plan"
grep -q '^vmfree-nested-vmx-model-sanitized	nested-vmx-model	' \
    "$work/vmfree-plan"

# VM-free nested-model cases must remain VM-free even when this scheduler is
# started by root.  The direct model runner has a manual diagnostic opt-in,
# but neither defaults nor a reviewed lab case may pass it through.
sed '/VM_FREE_GATES: "no"/a\
    VMX_NESTED_MODEL_LIVE_ATF: "yes"' \
    "$manifest" >"$work/implicit-live-default.yaml"
if "$LUA" "$lab" plan --manifest "$work/implicit-live-default.yaml" \
    --profile vmfree >"$work/implicit-live-default.out" 2>&1; then
	echo "lab accepted a VM-free nested live-test default" >&2
	exit 1
fi
grep -q 'defaults.env must not set VMX_NESTED_MODEL_LIVE_ATF' \
    "$work/implicit-live-default.out"
sed '/- id: vmfree-nested-vmx-model$/a\
    env: { VMX_NESTED_MODEL_LIVE_ATF: "yes" }' \
    "$manifest" >"$work/implicit-live-case.yaml"
if "$LUA" "$lab" plan --manifest "$work/implicit-live-case.yaml" \
    --profile vmfree >"$work/implicit-live-case.out" 2>&1; then
	echo "lab accepted a VM-free nested live-test case override" >&2
	exit 1
fi
grep -q 'VM-free nested model may not set VMX_NESTED_MODEL_LIVE_ATF' \
    "$work/implicit-live-case.out"

"$LUA" "$lab" plan --manifest "$manifest" --profile smoke \
    >"$work/smoke-plan"
grep -q '^vmfree-nested-vmx-model	nested-vmx-model	' "$work/smoke-plan"
grep -q '^vmfree-nested-vmx-model-sanitized	nested-vmx-model	' \
    "$work/smoke-plan"

"$LUA" "$lab" plan --manifest "$manifest" --profile intel-qualification \
    --fivebsd-image /tmp/disposable-5bsd.img >"$work/intel-qualification"
grep -q '^cases=231$' "$work/intel-qualification"
[ "$(grep -c '^kernel-contract-root	' "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^vmm-root	' "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^host-regression	' "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^fivebsd-module-build	' "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^vmm-module-build	' "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^vmfree-nested-vmx-model	' "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^vmfree-nested-vmx-model-sanitized	' \
    "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^nested-vmx-live	' "$work/intel-qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-net-modern	' \
    "$work/intel-qualification")" -eq 1 ]

"$LUA" "$lab" plan --manifest "$manifest" --profile full-qualification \
    --fivebsd-image /tmp/disposable-5bsd.img >"$work/full-qualification"
grep -q '^cases=235$' "$work/full-qualification"
[ "$(grep -c '^kernel-contract-root	' "$work/full-qualification")" -eq 1 ]
[ "$(grep -c '^vmm-root	' "$work/full-qualification")" -eq 1 ]
[ "$(grep -c '^nonvirtio-' "$work/full-qualification")" -eq 54 ]
[ "$(grep -c '^nested-vmx-live	' "$work/full-qualification")" -eq 1 ]
[ "$(grep -c '^sound-oss-modern	' "$work/full-qualification")" -eq 1 ]
[ "$(grep -c '^sound-oss-packed-modern	' \
    "$work/full-qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-sound-oss-modern	' \
    "$work/full-qualification")" -eq 1 ]
[ "$(grep -c '^checkpoint-sound-oss-packed-modern	' \
    "$work/full-qualification")" -eq 1 ]
! grep -q '^MISSING	' "$work/full-qualification"

"$LUA" "$lab" coverage --manifest "$manifest" \
    --profile full-qualification \
    --fivebsd-image /tmp/disposable-5bsd.img \
    >"$work/full-qualification-coverage"
grep -q '^COVERED	nested-vmx-live-gate$' \
    "$work/full-qualification-coverage"
! grep -q '^MISSING	' "$work/full-qualification-coverage"

"$LUA" "$lab" plan --manifest "$manifest" --profile nested-default \
    >"$work/nested-default"
grep -q '^cases=5$' "$work/nested-default"
[ "$(grep -c '^host-regression	' "$work/nested-default")" -eq 1 ]
[ "$(grep -c '^vmm-module-build	' "$work/nested-default")" -eq 1 ]
[ "$(grep -c '^nested-vmx-default-policy-live	' \
    "$work/nested-default")" -eq 1 ]
"$LUA" "$lab" coverage --manifest "$manifest" \
    --profile nested-default >"$work/nested-default-coverage"
grep -q '^COVERED	nested-vmx-default-policy-live-gate$' \
    "$work/nested-default-coverage"
! grep -q '^MISSING	' "$work/nested-default-coverage"

"$LUA" "$lab" plan --manifest "$manifest" --profile release \
    --fivebsd-image /tmp/disposable-5bsd.img >"$work/release-plan"
grep -q '^fivebsd-virtio	fivebsd-auto	' "$work/release-plan"
grep -q '^fivebsd-net-modern-q1	fivebsd-auto	' "$work/release-plan"
grep -q '^fivebsd-net-modern-q2	fivebsd-auto	' "$work/release-plan"
grep -q '^fivebsd-net-packed-modern-q2	fivebsd-auto	' "$work/release-plan"
grep -q '^fivebsd-block-write-zeroes	fivebsd-auto	' "$work/release-plan"
grep -q '^fivebsd-scsi-packed-modern-q2	fivebsd-auto	' "$work/release-plan"
grep -q '^fivebsd-modern-common-lifecycle	fivebsd-auto	' "$work/release-plan"
grep -q 'PASS host-net-mq-data queue_pairs=' "$here/run-alpine-auto.sh"
grep -q 'PASS  host_net_mq_data queues=' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_net_packed_layout' "$here/run-5bsd-auto.sh"
grep -q 'PASS host-packed-layout device=' "$here/run-alpine-auto.sh"
# Keep one assertion per device in the post-rebind packed-layout sweep.  A
# duplicate does not alter guest behavior, but it hides omissions in what is
# intended to be a direct device-to-proof inventory.
awk '
    $0 == "\tverify_packed_layout \"$run_mem_device\" \"$MEM_PACKED\" vtmem" {
        count++
    }
    END { exit(count == 1 ? 0 : 1) }
' "$here/run-alpine-auto.sh"
grep -q 'virtio reset-soak virtiofsd fd growth' \
    "$here/run-alpine-auto.sh"
grep -q 'virtiofsd_peak_rss_kb=' "$here/run-alpine-auto.sh"
grep -q 'sound-checkpoint-active' "$here/gsnd.py"
grep -q 'start_checkpoint_workloads' "$here/run-alpine-auto.sh"
grep -q 'active-checkpoint-network-traffic' "$here/gcheckpoint.py"
grep -q 'active-checkpoint-rng-io' "$here/gcheckpoint.py"
grep -q 'active-checkpoint-block-io' "$here/gcheckpoint.py"
grep -q 'active-checkpoint-scsi-io' "$here/gcheckpoint.py"
grep -q 'active-checkpoint-pmem-io' "$here/gcheckpoint.py"
grep -q 'os.O_NONBLOCK' "$here/gcheckpoint.py"
grep -q 'poller.poll(250)' "$here/gcheckpoint.py"
grep -q 'kill -KILL' "$here/run-alpine-auto.sh"
grep -q 'PASS  host_balloon_packed_layout' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_scsi_packed_layout_and_data' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_scsi_report_luns lun=' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_notification_data device=vtblk' "$here/run-5bsd-auto.sh"
grep -q 'guest_check block_discard_data' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_block_discard_request type=11' "$here/run-5bsd-auto.sh"
grep -q 'guest_check block_readonly_data' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_block_readonly bytes=8388608' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_scsi_events add,change,remove' "$here/run-5bsd-auto.sh"
grep -q 'guest_check block_wce_transition' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_block_wce_transition modes=0,1' "$here/run-5bsd-auto.sh"
grep -q -- '--set "NESTED_L1_RUNNER=$NESTED_L1_RUNNER"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "NESTED_L1_IMAGE=$NESTED_L1_IMAGE"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "NESTED_LINUX_L2_IMAGE=$NESTED_LINUX_L2_IMAGE"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "NESTED_FIVEBSD_L2_IMAGE=$NESTED_FIVEBSD_L2_IMAGE"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "NESTED_LIVE_TIMEOUT=$NESTED_LIVE_TIMEOUT"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "NESTED_SNAPSHOT_SESSION_TIMEOUT=$NESTED_SNAPSHOT_SESSION_TIMEOUT"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "NESTED_SNAPSHOT_SESSION_TEST=$NESTED_SNAPSHOT_SESSION_TEST"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "NESTED_STARTUP_STAGING_TEST=$NESTED_STARTUP_STAGING_TEST"' \
    "$here/run-waspnest-qualification.sh"

# The qualification front end must forward every reviewed nested control
# input, not merely mention it in the script.  PLAN_ONLY keeps this a
# rootless argument-contract test and avoids launching the nested profile.
env PROFILE=nested PLAN_ONLY=yes JOBS=1 WORKDIR="$work/nested-plan" \
    NESTED_L1_RUNNER=/tmp/l1-runner \
    NESTED_L1_IMAGE=/tmp/l1.img \
    NESTED_LINUX_L2_IMAGE=/tmp/linux-l2.img \
    NESTED_FIVEBSD_L2_IMAGE=/tmp/fivebsd-l2.img \
    NESTED_LIVE_TIMEOUT=19 NESTED_SNAPSHOT_SESSION_TIMEOUT=17 \
    NESTED_SNAPSHOT_SESSION_TEST=/tmp/snapshot-live-test \
    NESTED_STARTUP_STAGING_TEST=/tmp/staging-live-test \
    sh "$here/run-waspnest-qualification.sh" >"$work/nested-plan.out"
for nested_argument in \
    NESTED_LIVE_TIMEOUT=19 \
    NESTED_SNAPSHOT_SESSION_TIMEOUT=17 \
    NESTED_SNAPSHOT_SESSION_TEST=/tmp/snapshot-live-test \
    NESTED_STARTUP_STAGING_TEST=/tmp/staging-live-test; do
	awk -v wanted="$nested_argument" '
	$1 == "argument" && $2 == "--set" {
		if (getline > 0 && $1 == "argument" && $2 == wanted)
			found = 1
	}
	END { exit(found ? 0 : 1) }
	' "$work/nested-plan.out"
done
if env PROFILE=nested PLAN_ONLY=yes JOBS=1 WORKDIR="$work/nested-bad-timeout" \
    NESTED_L1_RUNNER=/tmp/l1-runner \
    NESTED_L1_IMAGE=/tmp/l1.img \
    NESTED_LINUX_L2_IMAGE=/tmp/linux-l2.img \
    NESTED_FIVEBSD_L2_IMAGE=/tmp/fivebsd-l2.img \
    NESTED_SNAPSHOT_SESSION_TIMEOUT=invalid \
    sh "$here/run-waspnest-qualification.sh" >"$work/nested-bad-timeout.out" 2>&1; then
	echo "qualification wrapper accepted an invalid preflight timeout" >&2
	exit 1
fi
grep -Fqx 'NESTED_SNAPSHOT_SESSION_TIMEOUT must be a positive integer' \
    "$work/nested-bad-timeout.out"
grep -q 'nested|nested-default|intel-qualification' \
    "$here/run-waspnest-qualification.sh"
grep -q 'VIRTIO_REFERENCE_ARTIFACT_DIR' \
    "$here/run-waspnest-qualification.sh"
grep -q 'validate-virtio-reference-corpus.sh' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '"$REFERENCE_CATALOG" --waspnest' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "SOUND_PLAY=$SOUND_PLAY"' \
    "$here/run-waspnest-qualification.sh"
grep -q -- '--set "SOUND_RECORD=$SOUND_RECORD"' \
    "$here/run-waspnest-qualification.sh"
env PLAN_ONLY=yes PROFILE=nested JOBS=1 WORKDIR="$work/nested-plan" \
    NESTED_L1_RUNNER=/tmp/l1-runner \
    NESTED_L1_IMAGE=/tmp/l1.img \
    NESTED_LINUX_L2_IMAGE=/tmp/linux-l2.img \
    NESTED_FIVEBSD_L2_IMAGE=/tmp/fivebsd-l2.img \
    sh "$here/run-waspnest-qualification.sh" >"$work/nested-wrapper-plan"
grep -q '^qualification-plan profile=nested$' "$work/nested-wrapper-plan"
grep -q '^nested-vmx-live[[:space:]]nested-vmx-live[[:space:]]' \
    "$work/nested-wrapper-plan"
grep -q '^cases=' "$work/nested-wrapper-plan"
! grep -q -- '--prepare-host\|--bridge\|--uplink\|--iso\|--fivebsd-image' \
    "$work/nested-wrapper-plan"

env PLAN_ONLY=yes PROFILE=nonvirtio JOBS=1 \
	    WORKDIR="$work/nonvirtio-plan" UPLINK=re0 \
	    ISO=/tmp/alpine.iso FIVEBSD_IMAGE=/tmp/5bsd.img \
	    FIVEBSD_IMAGE_SHA256=0000000000000000000000000000000000000000000000000000000000000000 \
	    FIVEBSD_BUILD_ID=selftest \
    NONVIRTIO_TPM_PATH=/tmp/swtpm.sock NONVIRTIO_PASSTHRU=ppt0 \
    NONVIRTIO_PASSTHRU_LINUX_ASSERT='test -d /sys/bus/pci/devices/0000:00:15.0' \
    NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT='pciconf -l pci0:21:0' \
    sh "$here/run-waspnest-qualification.sh" >"$work/nonvirtio-plan.out"
grep -q '^qualification-plan profile=nonvirtio$' "$work/nonvirtio-plan.out"
grep -q '^cases=54$' "$work/nonvirtio-plan.out"
for nonvirtio_argument in \
    NONVIRTIO_TPM_PATH=/tmp/swtpm.sock \
    NONVIRTIO_PASSTHRU=ppt0 \
    'NONVIRTIO_PASSTHRU_LINUX_ASSERT=test -d /sys/bus/pci/devices/0000:00:15.0' \
    'NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT=pciconf -l pci0:21:0'; do
	awk -v wanted="$nonvirtio_argument" '
	$1 == "argument" && $2 == "--set" {
		if (getline > 0 && $1 == "argument" && substr($0, index($0, $2)) == wanted)
			found = 1
	}
	END { exit(found ? 0 : 1) }
	' "$work/nonvirtio-plan.out"
done
# The optional authenticated corpus is a preflight boundary, including for a
# plan-only nested invocation.  A bad path must fail before the wrapper can
# claim that it merely planned a root-free profile.
if env PLAN_ONLY=yes PROFILE=nested JOBS=1 \
    WORKDIR="$work/nested-artifact-plan" \
    VIRTIO_REFERENCE_ARTIFACT_DIR="$work/missing-reference-artifacts" \
    NESTED_L1_RUNNER=/tmp/l1-runner \
    NESTED_L1_IMAGE=/tmp/l1.img \
    NESTED_LINUX_L2_IMAGE=/tmp/linux-l2.img \
    NESTED_FIVEBSD_L2_IMAGE=/tmp/freebsd-l2.img \
    sh "$here/run-waspnest-qualification.sh" \
    >"$work/nested-artifact-plan.out" 2>&1; then
	echo "qualification wrapper accepted a missing reference artifact cache" >&2
	exit 1
fi
grep -q 'reference artifact directory is invalid' \
    "$work/nested-artifact-plan.out"
if env PLAN_ONLY=yes PROFILE=release JOBS=1 \
    sh "$here/run-waspnest-qualification.sh" >"$work/release-wrapper-plan" \
    2>&1; then
	echo "release wrapper plan accepted missing required inputs" >&2
	exit 1
fi
grep -q 'set UPLINK to the host network interface' \
    "$work/release-wrapper-plan"
grep -q 'dev\.\\\$pname\.\\\$punit\.negotiated_features' \
    "$here/run-5bsd-auto.sh"
! grep -q 'dev\.vtblk\.\\\$unit\.negotiated_features' \
    "$here/run-5bsd-auto.sh"
grep -q 'guest_check rng_selective_queue_reset' "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_console_bidirectional port=' "$here/run-5bsd-auto.sh"
grep -q 'guest_check ninep_mount_ownership_and_rebind' \
    "$here/run-5bsd-auto.sh"
grep -q 'PASS  host_ninep_export_confinement' "$here/run-5bsd-auto.sh"
grep -q '9P export escape create unexpectedly succeeded' \
    "$here/run-alpine-auto.sh"

if "$LUA" "$lab" run --manifest "$manifest" --profile release \
    --iso "$work/missing-alpine.iso" \
    --fivebsd-image "$work/missing-5bsd.img" \
    --workdir "$work/missing-input-run" \
    >"$work/missing-input.out" 2>&1; then
	echo "run accepted missing VM input files" >&2
	exit 1
fi
grep -q -- '--iso must name a readable regular file:' \
    "$work/missing-input.out"

cat >"$work/incomplete.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 10, env: { DEVICES: net, NET_QUEUES: "1" } }
coverage:
  - id: queue-boundary
    profiles: [release]
    variable: NET_QUEUES
    values: ["1", "8"]
cases:
  - id: one
    executor: host-selftest
    profiles: [release]
EOF
if "$LUA" "$lab" coverage --manifest "$work/incomplete.yaml" \
    --profile release >"$work/incomplete.out" 2>&1; then
	echo "incomplete coverage unexpectedly passed" >&2
	exit 1
fi
grep -q '^MISSING	queue-boundary	8$' "$work/incomplete.out"

cat >"$work/duplicate.yaml" <<'EOF'
---
version: 1
cases:
  - { id: duplicate, executor: host-selftest, profiles: [smoke] }
  - { id: duplicate, executor: host-selftest, profiles: [smoke] }
EOF
if "$LUA" "$lab" plan --manifest "$work/duplicate.yaml" \
    --profile smoke >"$work/duplicate.out" 2>&1; then
	echo "duplicate case unexpectedly passed" >&2
	exit 1
fi
grep -q 'duplicate case id: duplicate' "$work/duplicate.out"

cat >"$work/duplicate-key.yaml" <<'EOF'
---
version: 1
cases:
  - id: duplicate-key
    executor: host-selftest
    executor: orchestrator-probe
    profiles: [smoke]
EOF
if "$LUA" "$lab" plan --manifest "$work/duplicate-key.yaml" \
    --profile smoke >"$work/duplicate-key.out" 2>&1; then
	echo "duplicate mapping key unexpectedly passed" >&2
	exit 1
fi
grep -q 'duplicate mapping key: executor' "$work/duplicate-key.out"

cat >"$work/profile-cycle.yaml" <<'EOF'
---
version: 1
profile_groups:
  all: [inner]
  inner: [all]
cases:
  - { id: cycle, executor: host-selftest, profiles: [all] }
EOF
if "$LUA" "$lab" plan --manifest "$work/profile-cycle.yaml" \
    --profile all >"$work/profile-cycle.out" 2>&1; then
	echo "cyclic profile group unexpectedly passed" >&2
	exit 1
fi
grep -q 'profile group cycle' "$work/profile-cycle.out"

cat >"$work/invalid-env.yaml" <<'EOF'
---
version: 1
cases:
  - id: invalid
    executor: host-selftest
    profiles: [smoke]
    env: { "BAD-NAME": value }
EOF
if "$LUA" "$lab" plan --manifest "$work/invalid-env.yaml" \
    --profile smoke >"$work/invalid-env.out" 2>&1; then
	echo "invalid environment name unexpectedly passed" >&2
	exit 1
fi
grep -q 'invalid environment name' "$work/invalid-env.out"

cat >"$work/invalid-default-env.yaml" <<'EOF'
---
version: 1
defaults: { env: { "BAD-NAME": value } }
cases:
  - id: invalid-default
    executor: host-selftest
    profiles: [smoke]
EOF
if "$LUA" "$lab" plan --manifest "$work/invalid-default-env.yaml" \
    --profile smoke >"$work/invalid-default-env.out" 2>&1; then
	echo "invalid default environment unexpectedly passed" >&2
	exit 1
fi
grep -q 'invalid environment name in defaults.env' \
    "$work/invalid-default-env.out"

cat >"$work/mislabeled-packed.yaml" <<'EOF'
---
version: 1
cases:
  - id: checkpoint-gpu-modern
    executor: host-selftest
    profiles: [checkpoint]
    env: { DEVICES: gpu, GPU_PACKED: "yes" }
EOF
if "$LUA" "$lab" plan --manifest "$work/mislabeled-packed.yaml" \
    --profile checkpoint >"$work/mislabeled-packed.out" 2>&1; then
	echo "mislabeled checkpoint ring format unexpectedly passed" >&2
	exit 1
fi
grep -q 'checkpoint-gpu-modern must set GPU_PACKED=no' \
    "$work/mislabeled-packed.out"

cat >"$work/missing-packed-trace.yaml" <<'EOF'
---
version: 1
cases:
  - id: gpu-packed-modern
    executor: alpine-auto
    profiles: [release]
    env:
      DEVICES: gpu
      TRANSPORTS: modern
      GPU_PACKED: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/missing-packed-trace.yaml" \
    --profile release >"$work/missing-packed-trace.out" 2>&1; then
	echo "packed case without host ring evidence unexpectedly passed" >&2
	exit 1
fi
grep -q 'gpu-packed-modern must require packed host ring evidence from vtgpu' \
    "$work/missing-packed-trace.out"

# The IOMMU is an implicit fabric device, so it is not named by a single
# DEVICES value.  Keep a separate negative fixture: otherwise the generic
# per-device packed check above could pass while an endpoint case claimed a
# packed IOMMU with no host-side vtiommu evidence.
cat >"$work/missing-iommu-packed-trace.yaml" <<'EOF'
---
version: 1
cases:
  - id: iommu-packed-modern
    executor: alpine-auto
    profiles: [release]
    env:
      DEVICES: net
      TRANSPORTS: modern
      VIRTIO_IOMMU: "yes"
      IOMMU_PACKED: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/missing-iommu-packed-trace.yaml" \
    --profile release >"$work/missing-iommu-packed-trace.out" 2>&1; then
	echo "packed IOMMU case without host ring evidence unexpectedly passed" >&2
	exit 1
fi
grep -q 'iommu-packed-modern must require packed host ring evidence from vtiommu' \
    "$work/missing-iommu-packed-trace.out"

cat >"$work/inactive-balloon-checkpoint.yaml" <<'EOF'
---
version: 1
cases:
  - id: checkpoint-balloon-modern
    executor: alpine-auto
    profiles: [checkpoint]
    env:
      DEVICES: balloon
      TRANSPORTS: modern
      BALLOON_PACKED: "no"
      CHECKPOINT_TEST: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/inactive-balloon-checkpoint.yaml" \
    --profile checkpoint >"$work/inactive-balloon-checkpoint.out" 2>&1; then
	echo "inactive balloon checkpoint unexpectedly passed" >&2
	exit 1
fi
grep -q 'checkpoint-balloon-modern must enable BALLOON_STATS_INTERVAL' \
    "$work/inactive-balloon-checkpoint.out"

cat >"$work/masked-balloon-reporting.yaml" <<'EOF'
---
version: 1
cases:
  - id: balloon-free-page-reporting-modern
    executor: alpine-auto
    profiles: [release]
    env:
      DEVICES: balloon
      TRANSPORTS: modern
      BALLOON_FREE_PAGE_REPORTING: "yes"
      BALLOON_PAGE_POISON: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/masked-balloon-reporting.yaml" \
    --profile release >"$work/masked-balloon-reporting.out" 2>&1; then
	echo "poison-masked balloon reporting unexpectedly passed" >&2
	exit 1
fi
grep -q 'balloon-free-page-reporting-modern must enable reporting with PAGE_POISON=no' \
    "$work/masked-balloon-reporting.out"

cat >"$work/inactive-mem-checkpoint.yaml" <<'EOF'
---
version: 1
cases:
  - id: checkpoint-mem-modern
    executor: alpine-auto
    profiles: [checkpoint]
    env:
      DEVICES: mem
      TRANSPORTS: modern
      MEM_PACKED: "no"
      CHECKPOINT_TEST: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/inactive-mem-checkpoint.yaml" \
    --profile checkpoint >"$work/inactive-mem-checkpoint.out" 2>&1; then
	echo "inactive memory checkpoint unexpectedly passed" >&2
	exit 1
fi
grep -q 'checkpoint-mem-modern must enable CHECKPOINT_ACTIVE_MEM' \
    "$work/inactive-mem-checkpoint.out"

cat >"$work/inactive-9p-checkpoint.yaml" <<'EOF'
---
version: 1
cases:
  - id: checkpoint-9p-packed-modern
    executor: alpine-auto
    profiles: [checkpoint]
    env:
      DEVICES: 9p
      TRANSPORTS: modern
      NINEP_PACKED: "yes"
      VERIFY_DEVICE_RING_NAME: vt9p
      VERIFY_DEVICE_RING_LAYOUT: packed
      CHECKPOINT_TEST: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/inactive-9p-checkpoint.yaml" \
    --profile checkpoint >"$work/inactive-9p-checkpoint.out" 2>&1; then
	echo "inactive 9P checkpoint unexpectedly passed" >&2
	exit 1
fi
grep -q 'checkpoint-9p-packed-modern must enable CHECKPOINT_ACTIVE_9P_REJECT' \
    "$work/inactive-9p-checkpoint.out"

cat >"$work/inactive-fs-checkpoint.yaml" <<'EOF'
---
version: 1
cases:
  - id: checkpoint-fs-active-modern
    executor: alpine-auto
    profiles: [checkpoint]
    env:
      DEVICES: fs
      TRANSPORTS: modern
      FS_PACKED: "no"
      FS_QUEUES: "2"
      CHECKPOINT_TEST: "yes"
      CHECKPOINT_ACTIVE_FS: "no"
      CHECKPOINT_REPEAT_FS_RESTORE: "no"
EOF
if "$LUA" "$lab" plan --manifest "$work/inactive-fs-checkpoint.yaml" \
    --profile checkpoint >"$work/inactive-fs-checkpoint.out" 2>&1; then
	echo "inactive virtio-fs checkpoint unexpectedly passed" >&2
	exit 1
fi
grep -q 'checkpoint-fs-active-modern must retain active virtio-fs state' \
    "$work/inactive-fs-checkpoint.out"

cat >"$work/active-fs-idle-checkpoint.yaml" <<'EOF'
---
version: 1
cases:
  - id: checkpoint-fs-idle-modern
    executor: alpine-auto
    profiles: [checkpoint]
    env:
      DEVICES: fs
      TRANSPORTS: modern
      FS_PACKED: "no"
      FS_QUEUES: "2"
      CHECKPOINT_TEST: "yes"
      CHECKPOINT_ACTIVE_FS: "yes"
      CHECKPOINT_REPEAT_FS_RESTORE: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/active-fs-idle-checkpoint.yaml" \
    --profile checkpoint >"$work/active-fs-idle-checkpoint.out" 2>&1; then
	echo "active virtio-fs idle checkpoint unexpectedly passed" >&2
	exit 1
fi
grep -q 'checkpoint-fs-idle-modern must remain an idle virtio-fs checkpoint lane' \
    "$work/active-fs-idle-checkpoint.out"

cat >"$work/untraced-iommu.yaml" <<'EOF'
---
version: 1
cases:
  - id: iommu-modern
    executor: alpine-auto
    profiles: [release]
    env:
      DEVICES: "net block"
      TRANSPORTS: modern
      VIRTIO_IOMMU: "yes"
EOF
if "$LUA" "$lab" plan --manifest "$work/untraced-iommu.yaml" \
    --profile release >"$work/untraced-iommu.out" 2>&1; then
	echo "IOMMU case without translated-DMA trace unexpectedly passed" >&2
	exit 1
fi
grep -q 'iommu-modern must set VERIFY_RING_ACTIVITY=yes' \
    "$work/untraced-iommu.out"

mkdir "$work/status"
printf 'passed=2\nfailed=0\ntotal=2\n' >"$work/status/summary"
printf 'time\tevent\tcase\tstatus\tlog\n' >"$work/status/events.tsv"
"$LUA" "$lab" status --workdir "$work/status" >"$work/status.out"
grep -q '^passed=2$' "$work/status.out"
grep -q '^time	event	case	status	log$' "$work/status.out"
mkdir "$work/not-a-run"
if "$LUA" "$lab" status --workdir "$work/not-a-run" \
    >"$work/not-a-run.out" 2>&1; then
	echo "status accepted a directory without virtio-lab state" >&2
	exit 1
fi
grep -q 'inaccessible or is not a virtio-lab run' "$work/not-a-run.out"

mkdir -m 0700 "$work/cancel-run"
mkdir "$work/cancel-run/status"
"$LUA" "$lab" cancel --workdir "$work/cancel-run" >"$work/cancel.out"
grep -q '^cancelled=0$' "$work/cancel.out"
chmod 0755 "$work/cancel-run"
if "$LUA" "$lab" cancel --workdir "$work/cancel-run" \
    >"$work/cancel-mode.out" 2>&1; then
	echo "cancel accepted an unprotected caller-owned run directory" >&2
	exit 1
fi
grep -q 'cancel requires root or a caller-owned mode-0700 run directory' \
    "$work/cancel-mode.out"
grep -q 'caller uid=' "$work/cancel-mode.out"
grep -q 'workdir uid=' "$work/cancel-mode.out"
grep -q "workdir uid=$(id -u)" "$work/cancel-mode.out"
grep -q 'mode=755' "$work/cancel-mode.out"
grep -q 'rerun cancel as root' "$work/cancel-mode.out"

# Cancellation must reach an active supervised wrapper, not merely validate an
# empty run directory.  The wrapper owns child teardown and publishes its
# terminal status atomically; the scheduler must then release its manager
# lease rather than leaving a resumable run permanently busy.
cat >"$work/cancel-active.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 30 }
cases:
  - id: active-cancel
    executor: orchestrator-probe
    profiles: [cancel]
    env: { LAB_PROBE_NAME: active-cancel, LAB_PROBE_SLEEP: "20", LAB_PROBE_CHILD_SLEEP: "20" }
EOF
cancel_active_run="$work/cancel-active-run"
"$LUA" "$lab" run --manifest "$work/cancel-active.yaml" \
    --profile cancel --workdir "$cancel_active_run" \
    >"$work/cancel-active-manager.out" 2>&1 &
cancel_active_manager=$!
cancel_active_ready=no
for cancel_active_try in 1 2 3 4 5 6 7 8 9 10; do
    if [ -r "$cancel_active_run/status/active-cancel.pid" ] &&
        [ -r "$cancel_active_run/status/active-cancel.child" ] &&
        [ -r "$cancel_active_run/status/active-cancel.pid.fingerprint" ] &&
        [ -r "$cancel_active_run/status/active-cancel.child.fingerprint" ] &&
        [ -r "$cancel_active_run/cases/active-cancel.attempt1/probe-child.pid" ]; then
        cancel_active_ready=yes
        break
    fi
    sleep 1
done
[ "$cancel_active_ready" = yes ] || {
    echo "active cancellation case was not supervised" >&2
    kill -TERM "$cancel_active_manager" 2>/dev/null || true
    wait "$cancel_active_manager" 2>/dev/null || true
    exit 1
}
cancel_active_grandchild=$(cat \
    "$cancel_active_run/cases/active-cancel.attempt1/probe-child.pid")
case $cancel_active_grandchild in
*[!0-9]*|'')
	echo "active cancellation probe recorded an invalid child pid" >&2
	exit 1
	;;
esac
# A mismatched identity is deliberately not cancellation authority.  Restore
# the exact recorded identity before exercising the normal cancellation path.
cp "$cancel_active_run/status/active-cancel.child.fingerprint" \
    "$work/active-cancel.child.fingerprint.saved"
printf '%064d\n' 0 >"$cancel_active_run/status/active-cancel.child.fingerprint"
"$LUA" "$lab" cancel --workdir "$cancel_active_run" \
    >"$work/cancel-active-mismatched.out"
grep -q '^cancelled=0$' "$work/cancel-active-mismatched.out"
mv "$work/active-cancel.child.fingerprint.saved" \
    "$cancel_active_run/status/active-cancel.child.fingerprint"
cancel_active_delivered=no
for cancel_active_try in 1 2 3; do
	"$LUA" "$lab" cancel --workdir "$cancel_active_run" \
	    >"$work/cancel-active.out"
	if grep -q '^cancelled=1$' "$work/cancel-active.out"; then
		cancel_active_delivered=yes
		break
	fi
	# cancel(1) deliberately reports only a signal delivered after its final
	# identity recheck.  Under scheduler load the wrapper may cross an exec or
	# status boundary between scan and signal; a bounded fresh scan is the safe
	# operator action and never reuses the prior PID observation.
	grep -q '^cancelled=0$' "$work/cancel-active.out"
	sleep 1
done
[ "$cancel_active_delivered" = yes ]
if wait "$cancel_active_manager"; then
    echo "cancelled active run unexpectedly passed" >&2
    exit 1
fi
grep -q '^passed=0$' "$cancel_active_run/summary"
grep -q '^failed=1$' "$cancel_active_run/summary"
grep -q '^total=1$' "$cancel_active_run/summary"
grep -q 'FAIL.*active-cancel.*143' "$cancel_active_run/events.tsv"
[ ! -e "$cancel_active_run/manager.lock" ]
if kill -0 "$cancel_active_grandchild" 2>/dev/null; then
	echo "active cancellation left a reparented probe child alive" >&2
	exit 1
fi

# An operator can interrupt the manager itself while a supervised case is
# still live.  This must be recoverable: the stale manager lease is reclaimed
# only after its recorded PID exits, then --resume reattaches to the existing
# wrapper instead of starting a second copy of the case.  Unlike the explicit
# cancel path above, this test intentionally leaves the wrapper running.
cat >"$work/interrupt-recovery.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 30 }
cases:
  - id: interrupted-case
    executor: orchestrator-probe
    profiles: [interrupt]
    env: { LAB_PROBE_NAME: interrupted-case, LAB_PROBE_SLEEP: "8", LAB_PROBE_CHILD_SLEEP: "8" }
EOF
interrupt_run="$work/interrupt-recovery-run"
"$LUA" "$lab" run --manifest "$work/interrupt-recovery.yaml" \
    --profile interrupt --workdir "$interrupt_run" \
    >"$work/interrupt-manager.out" 2>&1 &
interrupt_manager=$!
interrupt_ready=no
for interrupt_try in 1 2 3 4 5 6 7 8 9 10; do
    if [ -r "$interrupt_run/status/interrupted-case.pid" ] &&
        [ -r "$interrupt_run/status/interrupted-case.child" ] &&
        [ -r "$interrupt_run/status/interrupted-case.pid.fingerprint" ] &&
        [ -r "$interrupt_run/status/interrupted-case.child.fingerprint" ] &&
        [ -r "$interrupt_run/cases/interrupted-case.attempt1/probe-child.pid" ]; then
        interrupt_ready=yes
        break
    fi
    sleep 1
done
[ "$interrupt_ready" = yes ] || {
    echo "interrupted manager case was not supervised" >&2
    kill -TERM "$interrupt_manager" 2>/dev/null || true
    wait "$interrupt_manager" 2>/dev/null || true
    exit 1
}
interrupt_grandchild=$(cat \
    "$interrupt_run/cases/interrupted-case.attempt1/probe-child.pid")
case $interrupt_grandchild in
*[!0-9]*|'')
	echo "interrupted manager probe recorded an invalid child pid" >&2
	exit 1
	;;
esac
kill -TERM "$interrupt_manager"
if wait "$interrupt_manager"; then
    echo "interrupted manager unexpectedly completed" >&2
    exit 1
fi
[ -d "$interrupt_run/manager.lock" ] || {
    echo "interrupted manager unexpectedly released its lease" >&2
    exit 1
}
"$LUA" "$lab" run --manifest "$work/interrupt-recovery.yaml" \
    --profile interrupt --workdir "$interrupt_run" --resume \
    >"$work/interrupt-resume.out"
grep -q '^passed=1$' "$interrupt_run/summary"
grep -q '^failed=0$' "$interrupt_run/summary"
grep -q 'REATTACH.*interrupted-case' "$interrupt_run/events.tsv"
[ "$(cat "$interrupt_run/status/interrupted-case.attempt")" -eq 1 ]
[ ! -e "$interrupt_run/manager.lock" ]
if kill -0 "$interrupt_grandchild" 2>/dev/null; then
	echo "resume left the interrupted manager probe child alive" >&2
	exit 1
fi

cat >"$work/scheduler.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 10 }
cases:
  - id: pass-one
    executor: orchestrator-probe
    profiles: [scheduler]
    resources: [serial-a]
    env: { LAB_PROBE_NAME: one }
  - id: fail-seven
    executor: orchestrator-probe
    profiles: [scheduler]
    env: { LAB_PROBE_NAME: seven, LAB_PROBE_FAIL_FIRST: "yes" }
  - id: pass-two
    executor: orchestrator-probe
    profiles: [scheduler]
    resources: [serial-a]
    env: { LAB_PROBE_NAME: two }
EOF
run="$work/run"
if "$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --jobs 3 --workdir "$run" >"$work/run.out" 2>&1; then
	echo "scheduler failure case unexpectedly passed" >&2
	exit 1
fi
grep -q '^passed=2$' "$run/summary"
grep -q '^failed=1$' "$run/summary"
grep -q '	FAIL	fail-seven	7	' "$run/events.tsv"
[ "$(cat "$run/status/pass-one.attempt")" -eq 1 ]

"$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --jobs 3 --workdir "$run" --resume >"$work/resume.out"
grep -q '^passed=3$' "$run/summary"
grep -q '^failed=0$' "$run/summary"
[ "$(cat "$run/status/pass-one.attempt")" -eq 1 ]
[ "$(cat "$run/status/fail-seven.attempt")" -eq 2 ]
grep -q '	REUSE	pass-one	0	' "$run/events.tsv"
grep -q '	PASS	fail-seven	0	' "$run/events.tsv"
"$LUA" "$lab" verify-inputs --workdir "$run" >"$work/verify-inputs.out"
grep -q '^verified$' "$work/verify-inputs.out"
grep -Eq '^inputs=[1-9][0-9]*$' "$work/verify-inputs.out"
grep -Eq '^executor_trees=[1-9][0-9]*$' "$work/verify-inputs.out"

resume_events=$(grep -c '	RESUME	' "$run/events.tsv")
if "$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --jobs 3 --workdir "$run" --resume \
    --set LAB_PROBE_STATUS=0 >"$work/changed-resume.out" 2>&1; then
	echo "changed resume configuration unexpectedly passed" >&2
	exit 1
fi
grep -q 'resume configuration differs' "$work/changed-resume.out"
[ ! -e "$run/manager.lock" ]
[ "$(grep -c '	RESUME	' "$run/events.tsv")" -eq "$resume_events" ]

# A path string is not an immutable input identity.  Mutating a regular file
# named by the effective case environment must invalidate reusable successes.
resume_input="$work/resume-input"
printf 'first\n' >"$resume_input"
cat >"$work/input-resume.yaml" <<EOF
---
version: 1
defaults: { timeout: 10 }
cases:
  - id: input-bound
    executor: orchestrator-probe
    profiles: [input-bound]
    env: { LAB_PROBE_NAME: input, LAB_INPUT: "$resume_input" }
EOF
input_run="$work/input-run"
"$LUA" "$lab" run --manifest "$work/input-resume.yaml" \
    --profile input-bound --workdir "$input_run" >"$work/input-run.out"
printf 'second\n' >"$resume_input"
if "$LUA" "$lab" verify-inputs --workdir "$input_run" \
    >"$work/input-verify.out" 2>&1; then
	echo "input verification accepted a changed file" >&2
	exit 1
fi
grep -q 'recorded input changed since the run' "$work/input-verify.out"
if "$LUA" "$lab" run --manifest "$work/input-resume.yaml" \
    --profile input-bound --workdir "$input_run" --resume \
    >"$work/input-resume.out" 2>&1; then
	echo "resume reused a pass after an input changed in place" >&2
	exit 1
fi
grep -q 'resume configuration differs' "$work/input-resume.out"

filtered_run="$work/filtered-run"
"$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --case pass-one --jobs 3 --workdir "$filtered_run" \
    >"$work/filtered-run.out"
grep -q '^passed=1$' "$filtered_run/summary"
grep -q '^total=1$' "$filtered_run/summary"
if "$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --case pass-two --jobs 3 --workdir "$filtered_run" \
    --resume >"$work/filtered-resume.out" 2>&1; then
	echo "changed resumed case selection unexpectedly passed" >&2
	exit 1
fi
grep -q 'resume configuration differs' "$work/filtered-resume.out"
[ ! -e "$filtered_run/manager.lock" ]

cat >"$work/gate.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 10 }
cases:
  - id: required-gate
    executor: orchestrator-probe
    profiles: [gate]
    exclusive: true
    gate: true
    env: { LAB_PROBE_NAME: gate, LAB_PROBE_FAIL_FIRST: "yes" }
  - id: after-gate
    executor: orchestrator-probe
    profiles: [gate]
    env: { LAB_PROBE_NAME: after }
EOF
gate_run="$work/gate-run"
if "$LUA" "$lab" run --manifest "$work/gate.yaml" --profile gate --jobs 3 \
    --workdir "$gate_run" >"$work/gate-run.out" 2>&1; then
	echo "failing release gate unexpectedly passed" >&2
	exit 1
fi
grep -q '^passed=0$' "$gate_run/summary"
grep -q '^failed=1$' "$gate_run/summary"
grep -q '^blocked=1$' "$gate_run/summary"
grep -q '^total=2$' "$gate_run/summary"
grep -q '	BLOCKED	after-gate	gate:required-gate	' \
    "$gate_run/events.tsv"
[ ! -e "$gate_run/status/after-gate.attempt" ]

"$LUA" "$lab" run --manifest "$work/gate.yaml" --profile gate --jobs 3 \
    --workdir "$gate_run" --resume >"$work/gate-resume.out"
grep -q '^passed=2$' "$gate_run/summary"
grep -q '^failed=0$' "$gate_run/summary"
grep -q '^blocked=0$' "$gate_run/summary"
[ "$(cat "$gate_run/status/required-gate.attempt")" -eq 2 ]
[ "$(cat "$gate_run/status/after-gate.attempt")" -eq 1 ]

cat >"$work/late-gate.yaml" <<'EOF'
---
version: 1
cases:
  - id: ordinary
    executor: orchestrator-probe
    profiles: [late]
  - id: too-late
    executor: orchestrator-probe
    profiles: [late]
    exclusive: true
    gate: true
EOF
if "$LUA" "$lab" plan --manifest "$work/late-gate.yaml" --profile late \
    >"$work/late-gate.out" 2>&1; then
	echo "late gate unexpectedly passed validation" >&2
	exit 1
fi
grep -q 'gates must precede non-gate cases' "$work/late-gate.out"

echo "virtio-lab self-tests completed successfully"

#!/bin/sh
# Verify that the rootless checkpoint tests still exercise the portable,
# pointer-free state boundary rather than a host ABI convenience path.
# TEST-ANCHOR: destination-restore-transaction
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${SRCTOP:-/usr/src}

require_file()
{
	[ -f "$1" ] || {
		echo "snapshot portability: missing $1" >&2
		exit 1
	}
}

require_pattern()
{
	file=$1
	pattern=$2
	grep -Eq "$pattern" "$file" || {
		echo "snapshot portability: $file lacks $pattern" >&2
		exit 1
	}
}

portable=$src/usr.sbin/bhyve/snapshot_portable.h
snapshot=$src/usr.sbin/bhyve/snapshot.c
bhyverun=${BHYVERUN_SOURCE:-$src/usr.sbin/bhyve/bhyverun.c}
session=$src/sys/amd64/include/vmm_snapshot.h
compat=$src/usr.sbin/bhyve/checkpoint_compat.c
makefile=$src/usr.sbin/bhyve/Makefile
test_source=$here/snapshot_portable_test.c
compat_test=$here/checkpoint_compat_test.c
amd64_checkpoint=$src/usr.sbin/bhyve/amd64/checkpoint_cpu_machdep.c
aarch64_checkpoint=$src/usr.sbin/bhyve/aarch64/checkpoint_cpu_machdep.c
riscv_checkpoint=$src/usr.sbin/bhyve/riscv/checkpoint_cpu_machdep.c
virtio_snapshot=${VIRTIO_SNAPSHOT_SOURCE:-$src/usr.sbin/bhyve/virtio.c}
# The shared VirtIO model must remain independent of the CPU execution
# backend.  Permit the self-test to substitute only the common core source;
# all device files remain mandatory members of the production inventory.
virtio_common_core=${VIRTIO_COMMON_CORE_SOURCE:-$src/usr.sbin/bhyve/virtio.c}
# A test-only extra source lets the hostile-input self-test prove that the
# device-model portion of the inventory is checked too.  It is additive: it
# can never replace or hide a production device source.
virtio_extra_device=${VIRTIO_EXTRA_DEVICE_SOURCE:-}

for file in "$portable" "$snapshot" "$bhyverun" "$session" "$compat" "$makefile" "$test_source" \
    "$compat_test" "$amd64_checkpoint" "$aarch64_checkpoint" "$riscv_checkpoint" \
    "$virtio_snapshot" "$virtio_common_core"; do
	require_file "$file"
done
if [ -n "$virtio_extra_device" ]; then
	require_file "$virtio_extra_device"
fi

# The reusable layer supplies explicit endian transforms; typed codecs own
# their magic/version.  Neither layer may silently become a native struct or
# pointer image.
require_pattern "$portable" 'uint(16|32|64)_t'
require_pattern "$portable" 'snapshot_(load|store)_le(16|32|64)'
require_pattern "$compat" 'CHECKPOINT_COMPAT_(MAGIC|VERSION)'
require_pattern "$snapshot" '#include "snapshot_portable.h"'
require_pattern "$snapshot" 'VM_SNAPSHOT_SESSION_(BEGIN|COMMIT|ABORT)'
require_pattern "$session" 'VM_SNAPSHOT_SESSION_VERSION'

# A destination's vCPU threads are created before the restore transaction so
# they are registered with the normal run loop.  They must nevertheless be
# held before creation, then released only after the exact restore lease has
# committed and all device resume callbacks have succeeded.  This source
# ordering is intentionally checked separately from the codec model: it
# proves a failed or partial restore has no initial-execution window.
if ! awk '
function delta(s, t) {
	t = s
	return (gsub(/\{/, "{", t) - gsub(/\}/, "}", t))
}
/^main\(/ { in_main = 1; opened = 0; depth = 0 }
in_main {
	if (index($0, "{") != 0)
		opened = 1
	depth += delta($0)
	if ($0 ~ /checkpoint_restore_startup_hold\(\)/)
		hold = FNR
	if ($0 ~ /bhyve_start_vcpu\(/)
		start = FNR
	if ($0 ~ /vm_restore_transaction\(ctx, &rstate\)/)
		restore = FNR
	if (opened && depth == 0)
		in_main = 0
}
END { exit(hold != 0 && start != 0 && restore != 0 && hold < start && start < restore ? 0 : 1) }
' "$bhyverun"; then
	echo "snapshot portability: restore startup fence is not armed before vCPU creation" >&2
	exit 1
fi
if ! awk '
function delta(s, t) {
	t = s
	return (gsub(/\{/, "{", t) - gsub(/\}/, "}", t))
}
/^vm_restore_transaction\(/ { in_restore = 1; opened = 0; depth = 0 }
in_restore {
	if (index($0, "{") != 0)
		opened = 1
	depth += delta($0)
	if ($0 ~ /checkpoint_restore_startup_held\(\)/)
		held = FNR
	if ($0 ~ /vm_snapshot_session_release_exact\(ctx, &session, true,/)
		commit = FNR
	if ($0 ~ /error = vm_resume_devices\(\)/)
		resume = FNR
	if ($0 ~ /error = checkpoint_restore_startup_release\(\)/)
		release = FNR
	if (opened && depth == 0)
		in_restore = 0
}
END { exit(held != 0 && commit != 0 && resume != 0 && release != 0 && held < commit && commit < resume && resume < release ? 0 : 1) }
' "$snapshot"; then
	echo "snapshot portability: restore startup fence is not held through commit and device resume" >&2
	exit 1
fi

# Restore must capture the destination through the architecture-selected
# callback before comparing a decoded source contract.  The common codec
# knowing an ARM64 or RISC-V tag is not a substitute for an architecture
# capture implementation: those callbacks intentionally fail closed until a
# native CPU-state contract exists.  Keep the three calls ordered in the
# restore block so a later refactor cannot admit a foreign contract by
# comparing or restoring it without destination capture.
if ! awk '
function delta(s, t) {
	t = s
	return (gsub(/\{/, "{", t) - gsub(/\}/, "}", t))
}
/if \(restore_file != NULL\)/ {
	in_restore = 1
	opened = 0
	depth = 0
}
in_restore {
	if (index($0, "{") != 0)
		opened = 1
	depth += delta($0)
	if ($0 ~ /lookup_cpu_contract\(&rstate, &source_cpu\)/)
		lookup = FNR
	if ($0 ~ /checkpoint_cpu_contract_capture\(bsp,/)
		capture = FNR
	if ($0 ~ /checkpoint_cpu_contract_match\(&source_cpu,/)
		compare_line = FNR
	if (opened && depth == 0)
		in_restore = 0
}
END {
	if (lookup == 0 || capture == 0 || compare_line == 0 ||
	    !(lookup < capture && capture < compare_line))
		exit (1)
}
' "$bhyverun"; then
	echo "snapshot portability: restore must decode, capture, then compare CPU contract" >&2
	exit 1
fi

# Atomic rename can make a complete generation visible before the subsequent
# directory fsync reports a durability error.  That error remains visible to
# the caller, but it cannot turn the capture-side event fence into ABORT: the
# visible manifest must retain one coherent capture cut and its members must
# never be reclaimed.  Keep this source-shape check separate from the
# manifest fault-injection test, which independently proves the rename edge.
require_pattern "$snapshot" '&snapshot_session, published, &released'
if grep -Eq '&snapshot_session, error == 0 && published, &released' "$snapshot"; then
	echo "snapshot portability: visible publication must commit the event fence" >&2
	exit 1
fi

# A clean cross-architecture bhyve build must select the matching CPU
# contract callback from source, rather than accidentally resolving an object
# left by an amd64 build.  The common source name is intentional; the Makefile
# search path makes its architecture binding explicit.
require_pattern "$makefile" '\.PATH:[[:space:]]+\$\{\.CURDIR\}/\$\{MACHINE_CPUARCH\}'
require_pattern "$makefile" 'checkpoint_cpu_machdep\.c'
require_pattern "$amd64_checkpoint" 'CHECKPOINT_CPU_ARCH_AMD64'

# The independent model must cover canonical round trips and hostile inputs;
# a codec that merely encodes its own layout is not a portability test.
require_pattern "$test_source" 'fixed_little_endian_vectors'
require_pattern "$test_source" 'boundary_values'
require_pattern "$compat_test" '(portable_round_trip|rejects_malformed_envelope)'
require_pattern "$compat_test" '(noncanonical|transactional|little_endian)'

# ${MACHINE_CPUARCH} is aarch64, not arm64.  Until an ARM64 CPU contract is
# specified, its architecture-selected callback must explicitly reject CPU
# checkpoint capture instead of reaching an x86-only contract path.
require_pattern "$aarch64_checkpoint" 'checkpoint_cpu_contract_capture'
require_pattern "$aarch64_checkpoint" 'return \(EOPNOTSUPP\);'

# RISC-V also has an architecture-selected bhyve directory.  It must retain
# the same explicit unsupported CPU-contract boundary until it has a native,
# versioned CPU state format; common device checkpoint state must never fall
# through to an amd64 capture implementation.
require_pattern "$riscv_checkpoint" 'checkpoint_cpu_contract_capture'
require_pattern "$riscv_checkpoint" 'return \(EOPNOTSUPP\);'

# CPU-specific execution state belongs behind the architecture-selected CPU
# checkpoint adapter.  A shared VirtIO model that directly includes amd64 or
# x86 headers would make an otherwise portable device/state record depend on
# the host VMM implementation.  Keep this inventory deliberately narrow: it
# covers the common core, transport, and every bhyve VirtIO device model, but
# not snapshot.c or libvmmapi, which legitimately select the machine CPU ABI.
for file in "$virtio_common_core" "$src/usr.sbin/bhyve/virtio_pci_modern.c" \
    "$src"/usr.sbin/bhyve/pci_virtio*.c \
    "$src"/usr.sbin/bhyve/virtio_*.c; do
	if grep -nE '^[[:space:]]*#include[[:space:]]*[<"](amd64|x86)/|\b__amd64__\b' \
	    "$file" >/dev/null; then
		echo "snapshot portability: shared VirtIO source has a CPU-specific dependency: $file" >&2
		exit 1
	fi
done
if [ -n "$virtio_extra_device" ] &&
    grep -nE '^[[:space:]]*#include[[:space:]]*[<"](amd64|x86)/|\b__amd64__\b' \
    "$virtio_extra_device" >/dev/null; then
	echo "snapshot portability: shared VirtIO source has a CPU-specific dependency: $virtio_extra_device" >&2
	exit 1
fi

# A missing machine callback may identify an unsupported checkpoint, but must
# not be silently converted into a contract-less image.  The sole current
# format always needs a captured and encoded CPU contract.
if grep -Eq 'error != 0 && error != EOPNOTSUPP' "$snapshot"; then
	echo "snapshot portability: new checkpoints may not ignore a missing CPU contract" >&2
	exit 1
fi
require_pattern "$snapshot" 'A missing CPU-contract codec is not a valid image'
require_pattern "$snapshot" 'if \(error != 0\)'
require_pattern "$snapshot" 'return \(error\);'

# The project has not shipped a checkpoint ABI, so both modern and legacy
# transport records use the sole current fixed-width encoding.  Native-width
# convenience macros would couple that encoding to host endianness, sizeof,
# or _Bool representation and must not appear in any bhyve snapshot producer.
if rg -n 'SNAPSHOT_VAR(_CMP)?_OR_LEAVE[[:space:]]*\(' \
    "$src/usr.sbin/bhyve" --glob '*.c'; then
	echo "snapshot portability: native-width bhyve snapshot field remains" >&2
	exit 1
fi
# The self-test may replace or add one source outside the production tree.
# Scan those explicit inputs as well: checking only the directory would make
# the mutation lane exercise a different inventory from the real gate.
for file in "$virtio_snapshot" "$virtio_common_core"; do
	if grep -nE 'SNAPSHOT_VAR(_CMP)?_OR_LEAVE[[:space:]]*\(' "$file"; then
		echo "snapshot portability: native-width bhyve snapshot field remains" >&2
		exit 1
	fi
done
if [ -n "$virtio_extra_device" ] &&
    grep -nE 'SNAPSHOT_VAR(_CMP)?_OR_LEAVE[[:space:]]*\(' \
    "$virtio_extra_device"; then
	echo "snapshot portability: native-width bhyve snapshot field remains" >&2
	exit 1
fi

echo "virtio snapshot portability: portable envelope and independent hostile-input tests present"

#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
catalog=${1:-"$script_dir/virtio-nonstandard-interfaces.tsv"}
source_root=${2:-}

if [ ! -f "$catalog" ] || [ ! -r "$catalog" ]; then
	echo "virtio private interfaces: catalog is not a readable regular file: $catalog" >&2
	exit 1
fi

# The AF_VSOCK/provider review is deliberately wider than VirtIO wire
# conformance.  Require two fresh kernel traversals around two independently
# reconstructed private-interface inventories, followed by a composed final
# transaction pass.  These are process gates, not interchangeable prose.
review_prompt="$script_dir/../vsock_e2e/DEEP_REVIEW_PROMPT.md"
if [ ! -r "$review_prompt" ]; then
	review_prompt="$script_dir/DEEP_REVIEW_PROMPT.md"
fi
test -r "$review_prompt" || {
	echo "virtio private interfaces: missing AF_VSOCK review procedure" >&2
	exit 1
}
for phase in \
    'Pass H: second independent production-kernel review' \
    'Pass I: non-standard interfaces and operator policy' \
    'Pass J: post-private production-kernel replay' \
    'Pass K: composed private-boundary review' \
    'Pass L: second independent non-standard inventory replay' \
    'Pass M: final kernel/private transaction synthesis' \
    'Pass N: kernel/private adapter failure-atomicity replay' \
    'Pass O: withheld, unsupported, and implementation-defined behavior' \
    'Pass V: repeated common-kernel primitive lifecycle review' \
    'Pass W: repeated non-standard activation-boundary review' \
    'Pass X: terminal production-kernel source review' \
    'Pass Y: terminal non-standard and private-contract review' \
    'Pass Z: independent common-kernel contract replay' \
    'Pass AA: independent private decoder and operator-policy replay' \
    'Pass AB: second final common-kernel and cross-device lifecycle review' \
    'Pass AC: second final non-standard lifecycle and test-orchestration review'; do
	grep -Fq "$phase" "$review_prompt" || {
		echo "virtio private interfaces: missing AF_VSOCK review phase: $phase" >&2
		exit 1
	}
done
grep -Fq 'restarts Passes H through O' "$review_prompt" || {
	echo "virtio private interfaces: missing extended restart rule" >&2
	exit 1
}
grep -Fq 'restarts Passes R through AA' "$review_prompt" || {
	echo "virtio private interfaces: missing repeated final-source restart rule" >&2
	exit 1
}
grep -Fq 'restarts Passes R through AC' "$review_prompt" || {
	echo "virtio private interfaces: missing doubled final review restart rule" >&2
	exit 1
}
# The terminal common-kernel and private-policy replays must be unique.  A
# duplicate stale heading could otherwise satisfy the presence checks while
# making it unclear which review is the required closing traversal.
for phase in AB AC; do
	count=$(grep -Ec "^### Pass ${phase}:" "$review_prompt" || true)
	if [ "$count" -ne 1 ]; then
		echo "virtio private interfaces: review phase ${phase} must occur exactly once" >&2
		exit 1
	fi
done
echo "virtio private interfaces: doubled AF_VSOCK kernel/private reviews required"

awk -F '\t' '
function valid_class(value) {
	return value == "compatibility-contract" ||
	    value == "host-provider-abi" ||
	    value == "versioned-private-abi" ||
	    value == "experimental-guest-interface" ||
	    value == "operator-policy" ||
	    value == "private-implementation" ||
	    value == "implementation-bound" ||
	    value == "observability-contract"
}
BEGIN {
	expected = "id\tclass\towner\tversioning\tdefault\tauthorization\tcompatibility\trollback\tnegative_test\tnotes"
}
NR == 1 {
	if ($0 != expected) {
		print "virtio private interfaces: invalid header" > "/dev/stderr"
		errors++
	}
	next
}
{
	rows++
	if (NF != 10) {
		printf "virtio private interfaces: line %d has %d fields, expected 10\n", NR, NF > "/dev/stderr"
		errors++
		next
	}
	if ($1 !~ /^VIRTIO-PRIVATE-[0-9][0-9][0-9]$/ || seen[$1]++) {
		printf "virtio private interfaces: invalid or duplicate id %s\n", $1 > "/dev/stderr"
		errors++
	}
	if (!valid_class($2)) {
		printf "virtio private interfaces: %s has invalid class %s\n", $1, $2 > "/dev/stderr"
		errors++
	}
	for (i = 3; i <= 10; i++) {
		if ($i == "" || $i == "-") {
			printf "virtio private interfaces: %s has empty field %d\n", $1, i > "/dev/stderr"
			errors++
		}
	}
	if ($9 !~ /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.+*{}-]+$/) {
		printf "virtio private interfaces: %s has invalid negative test %s\n", $1, $9 > "/dev/stderr"
		errors++
	}
}
END {
	if (rows == 0) {
		print "virtio private interfaces: empty catalog" > "/dev/stderr"
		errors++
	}
	if (errors != 0)
		exit 1
	printf "virtio private interfaces: %d entries validated\n", rows
}
' "$catalog"

# Resolve every claimed negative test against the source tree.  This keeps the
# private inventory from becoming a prose-only checklist with stale test names.
awk -F '\t' 'NR > 1 { print $9 }' "$catalog" |
while IFS=: read -r program test_case; do
	case "$program" in
	*.sh)
		source=$script_dir/$program
		if [ ! -r "$source" ] && [ -n "$source_root" ]; then
			source=$source_root/tests/sys/kern/vsock_device_harness/$program
		fi
		test -r "$source" || {
			echo "virtio private interfaces: missing script $program" >&2
			exit 1
		}
		grep -Fq "TEST-ANCHOR: $test_case" "$source" || {
			echo "virtio private interfaces: missing script anchor $program:$test_case" >&2
			exit 1
		}
		;;
	*)
		source=$script_dir/$program.c
		if [ ! -r "$source" ] && [ -n "$source_root" ]; then
			for candidate in \
			    "$source_root/tests/sys/kern/vsock_device_harness/$program.c" \
			    "$source_root/tests/sys/kern/$program.c" \
			    "$source_root/tests/sys/kern/vsock_rx_harness/$program.c" \
			    "$source_root/tests/sys/vmm/$program.c"; do
				if [ -r "$candidate" ]; then
					source=$candidate
					break
				fi
			done
		fi
		if [ ! -r "$source" ]; then
			source=$script_dir/../$program.c
		fi
		if [ ! -r "$source" ]; then
			for candidate in "$script_dir"/../*/"$program.c"; do
				if [ -r "$candidate" ]; then
					source=$candidate
					break
				fi
			done
		fi
		test -r "$source" || {
			echo "virtio private interfaces: missing test program $program" >&2
			exit 1
		}
		grep -Eq "ATF_TC(_WITHOUT_HEAD)?\\($test_case\\)" "$source" || {
			echo "virtio private interfaces: missing test $program:$test_case" >&2
			exit 1
		}
		;;
	esac
done

# TEST-ANCHOR: scmi-callback-lifetime
# The FreeBSD SCMI transport locator and callback API is an internal contract,
# not part of the VirtIO wire specification.  Keep singleton publication
# transactional and make callback removal a synchronous lifetime boundary for
# the consumer-owned private pointer.
if [ -z "$source_root" ]; then
	candidate=$(realpath "$script_dir/../../../..")
	if [ -r "$candidate/sys/dev/virtio/scmi/virtio_scmi.c" ]; then
		source_root=$candidate
	fi
fi
if [ -z "$source_root" ]; then
	echo "virtio private interfaces: source-only SCMI callback check unavailable"
	exit 0
fi

# Reconstruct the withheld/implementation-defined source inventory from the
# final bhyve device model rather than trusting the catalog's owners.  ENOTSUP
# and EOPNOTSUPP in this scope may represent a standard optional operation, a
# deliberately unadvertised provisional facility, or a private backend
# contract; either way, every source file that can return one needs one exact
# catalog owner and a direct negative test.  Keep the source set bounded to
# VirtIO device/core files: unrelated bhyve legacy-device TODOs are outside the
# VirtIO 1.4/private-interface ledger.
unsupported_sources=$(rg -l '\b(ENOTSUP|EOPNOTSUPP)\b' \
    "$source_root/usr.sbin/bhyve"/virtio*.c \
    "$source_root/usr.sbin/bhyve"/pci_virtio_*.c 2>/dev/null | sort -u || true)
test -n "$unsupported_sources" || {
	echo "virtio private interfaces: no VirtIO unsupported-source inventory" >&2
	exit 1
}
for unsupported_source in $unsupported_sources; do
	unsupported_base=${unsupported_source##*/}
	awk -F '\t' -v source="$unsupported_base" '
		NR > 1 && index($3, source) != 0 { found = 1 }
		END { exit(found ? 0 : 1) }
	' "$catalog" || {
		echo "virtio private interfaces: unsupported source lacks a catalog disposition: $unsupported_base" >&2
		exit 1
	}
done
echo "virtio private interfaces: every VirtIO unsupported source is ledger-mapped"

# TEST-ANCHOR: admin-owner-destruction-drain
# Administration queues are deliberately withheld from guests, but their host
# owner must still not release callback arguments while a dispatched command
# can invoke them.  This is an event-driven ownership boundary, not a polling
# timeout: no recovery path can safely destroy the callback storage early.
admin_source=$source_root/usr.sbin/bhyve/virtio_admin.c
admin_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_admin_test.c
test -r "$admin_source" && test -r "$admin_test" || {
	echo "virtio private interfaces: administration owner sources are missing" >&2
	exit 1
}
awk '
/^virtio_admin_owner_destroy\(/ { in_destroy = 1 }
in_destroy && /owner->resetting = true/ { close_admission = NR }
in_destroy && /while \(owner->active_commands != 0\)/ { drain = NR }
in_destroy && /pthread_cond_wait\(&owner->quiesced, &owner->mutex\)/ { wait = NR }
in_destroy && /pthread_cond_destroy\(&owner->quiesced\)/ { destroy_cond = NR }
in_destroy && /free\(owner\)/ {
	exit(close_admission != 0 && drain > close_admission && wait > drain &&
	    destroy_cond > wait ? 0 : 1)
}
END { if (!in_destroy) exit 1 }
' "$admin_source" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(destroy_drains_active_command\)' \
    "$admin_test" &&
    grep -q 'while (!context.owner->resetting)' "$admin_test" || {
	echo "virtio private interfaces: administration owner destruction drain is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: administration owner destruction drain validated"

# TEST-ANCHOR: snapshot-v2-envelope
# The new kernel-state container is a private bhyve compatibility format.  It
# must remain a separate versioned record rather than extending the historical
# host-layout STRUCT_VM stream, and its negative ATF cases must remain present.
snapshot_envelope=$source_root/sys/dev/vmm/vmm_snapshot_envelope.c
snapshot_common=$source_root/sys/dev/vmm/vmm_snapshot_state.c
snapshot_x86=$source_root/sys/amd64/vmm/vmm_snapshot_x86_state.c
snapshot_x86_transaction=$source_root/sys/amd64/vmm/vmm_snapshot_x86_transaction.c
snapshot_x86_kernel=$source_root/sys/amd64/vmm/vmm.c
snapshot_envelope_test=$source_root/tests/sys/vmm/vmm_snapshot_envelope_test.c
test -r "$snapshot_envelope" && test -r "$snapshot_common" &&
    test -r "$snapshot_x86" && test -r "$snapshot_x86_transaction" &&
    test -r "$snapshot_x86_kernel" && test -r "$snapshot_envelope_test" || {
	echo "virtio private interfaces: VMS2 envelope or semantic sources are missing" >&2
	exit 1
}
grep -q 'VMM_SNAPSHOT_ENVELOPE_MAGIC' \
    "$source_root/sys/dev/vmm/vmm_snapshot_envelope.h" &&
    grep -q 'VMM_SNAPSHOT_SECTION_F_CRITICAL' \
    "$source_root/sys/dev/vmm/vmm_snapshot_envelope.h" &&
    grep -q 'vmm_snapshot_ranges_overlap' "$snapshot_envelope" || {
	echo "virtio private interfaces: VMS2 format boundary is incomplete" >&2
	exit 1
}
grep -q 'VMM_SNAPSHOT_SECTION_VM_COMMON' \
    "$source_root/sys/dev/vmm/vmm_snapshot_state.h" &&
    grep -q 'vmm_snapshot_vm_common_decode' "$snapshot_common" &&
    grep -q 'VMM_SNAPSHOT_SECTION_VCPU_X86' \
    "$source_root/sys/amd64/vmm/vmm_snapshot_x86_state.h" &&
    grep -q 'vmm_snapshot_vcpu_x86_decode' "$snapshot_x86" &&
    grep -q 'vmm_snapshot_x86_transaction_decode' \
    "$snapshot_x86_transaction" &&
    grep -q 'vmm_snapshot_x86_transaction_validate_destination' \
    "$snapshot_x86_transaction" || {
	echo "virtio private interfaces: VMS2 semantic boundary is incomplete" >&2
	exit 1
}
grep -q 'vm_snapshot_x86_capture_all' "$snapshot_x86_kernel" &&
    grep -q 'vm_event_state_capture_all(vm, instances, events, count, &index)' \
    "$snapshot_x86_kernel" &&
    grep -q 'vmm_event_capture_commit_validate(generation' \
    "$snapshot_x86_kernel" &&
    grep -q 'memcpy(stage, stage_candidates, stage_length)' \
    "$snapshot_x86_kernel" || {
	echo "virtio private interfaces: VMS2 kernel capture transaction is incomplete" >&2
	exit 1
}
for test_case in round_trip builder_transactionality malformed_records \
    argument_boundaries common_state_codecs x86_state_codec x86_transaction \
    x86_transaction_multivcpu x86_transaction_zero_vcpus; do
	grep -Eq "ATF_TC(_WITHOUT_HEAD)?\\($test_case\\)" \
	    "$snapshot_envelope_test" || {
		echo "virtio private interfaces: missing VMS2 case $test_case" >&2
		exit 1
	}
done

# Checkpoint member digests are an integrity aid inside the operator trust
# boundary, not an authentication mechanism.  Keep that private-ABI property
# and the current-only private format policy explicit in the installed manual.
manual=$source_root/usr.sbin/bhyve/bhyve.8
test -r "$manual" || {
	echo "virtio private interfaces: missing bhyve manual" >&2
	exit 1
}
grep -q 'unkeyed SHA-256 values' "$manual" || {
	echo "virtio private interfaces: checkpoint digest trust boundary is undocumented" >&2
	exit 1
}
grep -q 'Only the current manifest version is accepted' "$manual" || {
	echo "virtio private interfaces: current-only manifest policy is undocumented" >&2
	exit 1
}

scmi_source=$source_root/sys/dev/virtio/scmi/virtio_scmi.c
test -r "$scmi_source" || {
	echo "virtio private interfaces: missing SCMI transport source" >&2
	exit 1
}
grep -Eq 'vtscmi_dev != NULL \|\| vtscmi_attaching' "$scmi_source" || {
	echo "virtio private interfaces: SCMI singleton attach is not reserved" >&2
	exit 1
}
grep -Eq 'if \(vtscmi_dev == dev\)' "$scmi_source" || {
	echo "virtio private interfaces: SCMI detach leaves stale publication" >&2
	exit 1
}
grep -Eq 'while \(q->cb_inflight != 0\)' "$scmi_source" || {
	echo "virtio private interfaces: SCMI callback removal is not synchronous" >&2
	exit 1
}
grep -Eq 'device_busy\(dev\)' "$scmi_source" || {
	echo "virtio private interfaces: SCMI locator lacks a device reference" >&2
	exit 1
}
grep -Eq 'device_unbusy\(dev\)' "$scmi_source" || {
	echo "virtio private interfaces: SCMI locator reference cannot be released" >&2
	exit 1
}
# A failed virtqueue enqueue does not consume its cookie.  The transport must
# return that PDU to its private pool for every error, not only quiesce races,
# or repeated ENOSPC/EIO failures permanently consume the bounded pool.
awk '
/^virtio_scmi_message_enqueue\(/ { in_function = 1 }
in_function && /if \(ret != 0\)/ { failed = NR }
in_function && /virtio_scmi_pdu_put\(dev, pdu\)/ { reclaim = NR }
in_function && /^}/ {
	exit(failed != 0 && reclaim > failed ? 0 : 1)
}
END { if (!in_function) exit 1 }
' "$scmi_source" || {
	echo "virtio private interfaces: SCMI enqueue failure leaks a PDU" >&2
	exit 1
}
grep -Eq 'virtio_scmi_transport_quiesce\(device_t dev\)' "$scmi_source" &&
    grep -Eq 'atomic_store_rel_int\(&sc->quiesced, 1\)' "$scmi_source" &&
    grep -Eq 'virtio_stop\(dev\)' "$scmi_source" &&
    grep -Eq 'virtqueue_drain\(q->vq, &last\)' "$scmi_source" &&
    grep -Eq 'atomic_load_acq_int\(&sc->quiesced\)' "$scmi_source" || {
	echo "virtio private interfaces: SCMI buffer DMA fence is incomplete" >&2
	exit 1
}
scmi_consumer=$source_root/sys/dev/firmware/arm/scmi_virtio.c
grep -Eq 'virtio_scmi_transport_put\(sc->virtio_dev\)' "$scmi_consumer" || {
	echo "virtio private interfaces: SCMI consumer leaks its device reference" >&2
	exit 1
}
awk '
/^scmi_virtio_transport_cleanup\(/ { in_function = 1 }
in_function && /VIRTIO_SCMI_CHAN_A2P, NULL, NULL/ { unregister = NR }
in_function && /virtio_scmi_transport_quiesce/ { quiesce = NR }
in_function && /free\(sc->p2a_pool/ { free_pool = NR }
in_function && /^}/ {
	exit(unregister != 0 && quiesce > unregister && free_pool > quiesce ? 0 : 1)
}
END { if (!in_function) exit 1 }
' "$scmi_consumer" || {
	echo "virtio private interfaces: SCMI consumer frees device-owned buffers" >&2
	exit 1
}
awk '
/^vtscmi_detach\(/ { in_function = 1 }
in_function && /virtio_teardown_intr\(dev\)/ { teardown = NR }
in_function && /virtio_scmi_channel_callback_set/ && /NULL, NULL/ {
	if (first_unregister == 0)
		first_unregister = NR
}
in_function && /vtscmi_free_queues\(sc\)/ { free_queues = NR }
in_function && /^}/ {
	exit(teardown != 0 && first_unregister > teardown &&
	    free_queues > first_unregister ? 0 : 1)
}
END { if (!in_function) exit 1 }
' "$scmi_source" || {
	echo "virtio private interfaces: SCMI detach callback lifetime is unordered" >&2
	exit 1
}

# The two host-side vsock packet queues are implementation resource policy,
# not standard virtqueue sizes or transport credit.  Pin the production bounds
# and independent saturation/resume evidence to their private-ledger rows.
guest_vsock=$source_root/sys/dev/virtio/vsock/virtio_vsock.c
user_vsock=$source_root/sys/kern/uipc_vsock_user.c
transport_test=$source_root/tests/sys/kern/vsock_rx_harness/virtio_vsock_transport_test.c
provider_test=$source_root/tests/sys/kern/vsock_test.c
grep -Eq '^#define[[:space:]]+VTVSOCK_TXQ_MAX[[:space:]]+256$' \
    "$guest_vsock" || {
	echo "virtio private interfaces: guest vsock reply-queue bound drifted" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTVSOCK_TXQ_HIWAT[[:space:]]+\(VTVSOCK_TXQ_MAX - 16\)$' \
    "$guest_vsock" || {
	echo "virtio private interfaces: guest vsock RX high-water policy drifted" >&2
	exit 1
}
grep -q 'ATF_TC_WITHOUT_HEAD(reply_highwater_stalls_and_resumes_rx)' \
    "$transport_test" || {
	echo "virtio private interfaces: guest vsock high-water test is missing" >&2
	exit 1
}
grep -q 'SDT_PROBE_DEFINE6(vsock, , , pkt__tx__drop' "$guest_vsock" || {
	echo "virtio private interfaces: guest vsock TX-drop probe is missing" >&2
	exit 1
}
grep -q 'vtvsock_cnt_tx_drops' "$transport_test" || {
	echo "virtio private interfaces: guest vsock drop counter is untested" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VSOCK_USER_QUEUE_MAX[[:space:]]+128$' \
    "$user_vsock" || {
	echo "virtio private interfaces: userspace-provider queue bound drifted" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VSOCK_USER_QUEUE_DATA_HIWAT[[:space:]]+64$' \
    "$user_vsock" || {
	echo "virtio private interfaces: userspace-provider data high-water drifted" >&2
	exit 1
}
grep -q 'ATF_CHECK(error == 128)' "$provider_test" || {
	echo "virtio private interfaces: userspace-provider saturation test is missing" >&2
	exit 1
}
grep -Eq 'SYSCTL_COUNTER_U64\(_kern_vsock, OID_AUTO, tx_drops,' \
    "$user_vsock" "$source_root/sys/kern/uipc_vsock.c" || {
	echo "virtio private interfaces: guest vsock TX-drop counter is not exported" >&2
	exit 1
}
grep -q 'sysctlbyname("kern.vsock.tx_drops"' "$provider_test" || {
	echo "virtio private interfaces: guest vsock TX-drop sysctl is untested" >&2
	exit 1
}

# Pin externally observable bhyve resource ceilings independently from the
# implementation constants.  These are private availability policy, not
# normative VirtIO maxima, and therefore belong in this inventory rather than
# in the specification oracle.
bhyve_vsock=$source_root/usr.sbin/bhyve/pci_virtio_vsock.c
bhyve_vsock_test=$source_root/tests/sys/kern/vsock_device_harness/vsock_device_test.c
fs_source=$source_root/usr.sbin/bhyve/pci_virtio_fs.c
fs_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_fs_pci_test.c
fs_connection_source=$source_root/usr.sbin/bhyve/virtio_fs_connection.c
fs_connection_header=$source_root/usr.sbin/bhyve/virtio_fs_connection.h
fs_connection_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_fs_connection_test.c
gpu_state_source=$source_root/usr.sbin/bhyve/virtio_gpu_2d_state.c
gpu_state_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_gpu_2d_state_test.c
snd_async_source=$source_root/usr.sbin/bhyve/virtio_snd_async.c
snd_async_header=$source_root/usr.sbin/bhyve/virtio_snd_async.h
snd_async_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_snd_async_test.c
snd_host_source=$source_root/usr.sbin/bhyve/virtio_snd_host.c
snd_host_header=$source_root/usr.sbin/bhyve/virtio_snd_host.h
snd_host_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_snd_host_test.c
mem_host_source=$source_root/usr.sbin/bhyve/virtio_mem_host.c
mem_host_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_mem_host_test.c
rtc_pci_source=$source_root/usr.sbin/bhyve/pci_virtio_rtc.c
mevent_source=$source_root/usr.sbin/bhyve/mevent.c
mevent_test=$source_root/tests/sys/kern/vsock_device_harness/mevent_lifecycle_test.c
vsock_pci_source=$source_root/usr.sbin/bhyve/pci_virtio_vsock.c
vsock_device_test=$source_root/tests/sys/kern/vsock_device_harness/vsock_device_test.c
pmem_source=$source_root/usr.sbin/bhyve/pci_virtio_pmem.c
pmem_worker_source=$source_root/usr.sbin/bhyve/virtio_pmem_worker.c
iommu_source=$source_root/usr.sbin/bhyve/pci_virtio_iommu.c
iommu_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_iommu_pci_test.c
iommu_state_header=$source_root/usr.sbin/bhyve/virtio_iommu_state.h
iommu_state_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_iommu_state_test.c
input_source=$source_root/usr.sbin/bhyve/pci_virtio_input.c
input_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_input_test.c
rng_source=$source_root/usr.sbin/bhyve/pci_virtio_rnd.c
rng_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_rnd_test.c
net_source=$source_root/usr.sbin/bhyve/pci_virtio_net.c
net_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_net_test.c
block_source=$source_root/usr.sbin/bhyve/block_if.c
block_test=$source_root/tests/sys/kern/vsock_device_harness/block_if_test.c
block_pci_source=$source_root/usr.sbin/bhyve/pci_virtio_block.c
block_pci_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_block_test.c
topology_source=$source_root/usr.sbin/bhyve/checkpoint_topology.h
topology_test=$source_root/tests/sys/kern/vsock_device_harness/checkpoint_topology_test.c
scmi_poll_header=$source_root/sys/dev/firmware/arm/scmi_virtio_poll.h
scmi_poll_source=$source_root/sys/dev/firmware/arm/scmi_virtio.c
scmi_poll_test=$source_root/tests/sys/kern/vsock_device_harness/scmi_virtio_poll_test.c
virtio_guest_header=$source_root/sys/dev/virtio/virtio.h

# TEST-ANCHOR: rng-common-queue-snapshot-only
# Entropy is destination-local host state.  The RNG device may retain common
# VirtIO queue/PCI state, but it must not grow a private snapshot record that
# serializes its host descriptor or previously generated bytes.
grep -q 'VIRTIO_ACTIVATION_ASSERTION: common-queue-snapshot-no-entropy-replay' \
    "$rng_source" &&
    grep -q '\.vc_cfgsize =.*0' "$rng_source" &&
    ! grep -q '\.vc_snapshot' "$rng_source" &&
    grep -q '\.pe_snapshot =.*vi_pci_snapshot' "$rng_source" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(save_state_uses_common_queue_only\)' \
    "$rng_test" &&
    grep -q 'ATF_CHECK_EQ(vtrnd_vi_consts.vc_snapshot, NULL)' "$rng_test" || {
	echo "virtio private interfaces: RNG snapshot boundary is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: RNG common-queue snapshot boundary validated"

# TEST-ANCHOR: fs-destruction-withdraws-queue-before-completion
# Filesystem connection destruction drains retained guest requests through the
# normal completion callback.  That callback may query pressure, therefore the
# public queue pointer must be cleared before queue_destroy() can free it.  A
# callback must also be unable to reactivate a replacement queue while the old
# queue is being drained.
awk '
    /virtio_fs_connection_destroy\(struct virtio_fs_connection \*connection\)/ { in_destroy = 1 }
    in_destroy && /connection->destroying = true;/ { destroying = 1 }
    in_destroy && /queue = connection->queue;/ { copied = 1 }
    in_destroy && /connection->queue = NULL;/ { withdrawn = 1 }
    in_destroy && /virtio_fs_queue_destroy\(queue\);/ {
        destroyed = destroying && copied && withdrawn
        exit
    }
    END { exit !(destroying && copied && withdrawn && destroyed) }
' "$fs_connection_source" &&
	grep -q 'serializes concurrent public operations and excludes destroy' \
	    "$fs_connection_header" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(destroy_withdraws_queue_before_completion\)' \
        "$fs_connection_test" &&
    grep -q 'completion.pending_at_completion, 0' "$fs_connection_test" &&
    grep -q 'completion.outgoing_at_completion, 0' "$fs_connection_test" &&
    grep -q 'completion.progress_at_completion, ECANCELED' \
        "$fs_connection_test" || {
	echo "virtio private interfaces: filesystem teardown pressure fence is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: filesystem teardown pressure fence validated"

# TEST-ANCHOR: fs-teardown-completions-reacquire-device-lock
# Normal filesystem progress invokes completion callbacks under vsc_mtx, but
# connection destruction deliberately drops that lock before draining retained
# requests.  Both publish and discard callbacks therefore must re-use the
# serializer helper, which is a no-op for the already-locked progress path and
# acquires/releases the mutex for teardown.  This protects the common packed
# completion reorder state as well as split-ring used publication.  Queue
# failure also reports selective-reset completion during unlocked teardown, so
# that callback must use the same serializer before touching vsc_reset.
sed -n '/^pci_vtfs_complete(/,/^}/p' "$fs_source" | \
    grep -q 'acquired = pci_vtfs_serializer_enter(sc);' &&
    sed -n '/^pci_vtfs_complete(/,/^}/p' "$fs_source" | \
    grep -q 'pci_vtfs_serializer_exit(sc, acquired);' &&
    sed -n '/^pci_vtfs_discard(/,/^}/p' "$fs_source" | \
    grep -q 'acquired = pci_vtfs_serializer_enter(sc);' &&
    sed -n '/^pci_vtfs_discard(/,/^}/p' "$fs_source" | \
    grep -q 'pci_vtfs_serializer_exit(sc, acquired);' &&
    sed -n '/^pci_vtfs_reset_complete(/,/^}/p' "$fs_source" | \
    grep -q 'acquired = pci_vtfs_serializer_enter(sc);' &&
    sed -n '/^pci_vtfs_reset_complete(/,/^}/p' "$fs_source" | \
    grep -q 'pci_vtfs_serializer_exit(sc, acquired);' &&
    grep -q 'Teardown drains this callback after dropping vsc_mtx.' \
        "$fs_test" &&
    grep -q 'ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));' \
        "$fs_test" || {
	echo "virtio private interfaces: filesystem teardown completion lock is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: filesystem teardown completion lock validated"

# TEST-ANCHOR: gpu-presentation-callback-lifetime
# GPU callbacks are explicitly outside the state mutex so the presentation
# owner may query state.  The state must therefore pin every callback before
# releasing the mutex, withdraw command admission at destruction, and drain
# the pin count before mutex or resource storage is released.
awk '
    /^virtio_gpu_2d_state_destroy\(/ { in_destroy = 1 }
    in_destroy && /state->destroying = true;/ { closing = 1 }
    in_destroy && /while \(state->callbacks != 0\)/ { draining = 1 }
    in_destroy && /pthread_cond_destroy\(&state->callback_drain\)/ {
        destroy_cond = closing && draining
        exit
    }
    END { exit !(closing && draining && destroy_cond) }
' "$gpu_state_source" &&
    awk '
    /^virtio_gpu_2d_state_execute\(/ { in_execute = 1 }
    in_execute && /if \(state->destroying\)/ { rejects = 1 }
    in_execute && /state->callbacks\+\+;/ { pins = 1 }
    in_execute && /gpu_state_callback_done\(state\);/ {
        releases = pins
        exit
    }
    END { exit !(rejects && pins && releases) }
' "$gpu_state_source" &&
    awk '
    /^gpu_snapshot_decode\(/ { in_decode = 1 }
    in_decode && /state->callbacks\+\+;/ { pins = 1 }
    in_decode && /ops.dma_validate\(/ { validates = pins }
    in_decode && /gpu_state_callback_done\(state\);/ {
        releases = validates
        exit
    }
    END { exit !(pins && validates && releases) }
' "$gpu_state_source" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(destroy_drains_external_presentation_callbacks\)' \
        "$gpu_state_test" &&
	grep -Eq 'ATF_TC_WITHOUT_HEAD\(destroy_drains_snapshot_dma_validation\)' \
	    "$gpu_state_test" &&
    grep -q 'destroy_callback_seen' "$gpu_state_test" &&
	grep -q 'destroy_reset_seen' "$gpu_state_test" &&
    grep -q 'ATF_CHECK(!context.destroy_finished)' "$gpu_state_test" || {
	echo "virtio private interfaces: GPU presentation callback lifetime is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: GPU presentation callback lifetime validated"

# TEST-ANCHOR: iommu-raw-state-destruction-lifetime
# GPA mapping and fault notification deliberately run outside the IOMMU state
# mutex.  Therefore this raw state object has a device-owner lifetime rather
# than a fictitious internal reference count: the common DMA request owner
# closes admission and drains every endpoint lease before unpublishing it.
grep -q 'No state API may be called concurrently with destruction.' \
    "$iommu_state_header" &&
    grep -q 'drain every lease acquired through' "$iommu_state_header" &&
    grep -q 'virtio_iommu_dma_acquire' "$iommu_state_header" &&
    grep -q 'virtio_iommu_dma_release' "$iommu_state_header" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(active_dma_fences_every_state_transfer_phase\)' \
    "$iommu_state_test" &&
    grep -q 'virtio_iommu_dma_acquire(state, 8)' "$iommu_state_test" &&
    grep -q 'virtio_iommu_dma_release(state, 8)' "$iommu_state_test" || {
	echo "virtio private interfaces: IOMMU raw-state destruction lifetime is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: IOMMU raw-state destruction lifetime validated"

# TEST-ANCHOR: sound-progress-callback-owner-pin
# A sound readiness callback may inspect its async owner.  The progress pin
# keeps the job storage alive after dropping the mutex, while lifecycle and
# destructive operations see that pin as active ownership rather than racing
# the backend's buffer access.
awk '
    /^virtio_snd_async_progress\(/ { in_progress = 1 }
    in_progress && /async->progressing\[stream_id\] = true;/ { pinned = 1 }
    in_progress && /pthread_mutex_unlock\(&async->mutex\);/ && pinned { unlocked = 1 }
    in_progress && /ops.progress\(/ && unlocked { callback = 1 }
    in_progress && /pthread_mutex_lock\(&async->mutex\);/ && callback { relocked = 1 }
    in_progress && /async->progressing\[stream_id\] = false;/ && relocked {
        released = 1
    }
    in_progress && /^virtio_snd_async_cancel\(/ {
        exit(pinned && unlocked && callback && relocked && released ? 0 : 1)
    }
    END { if (!in_progress) exit 1 }
' "$snd_async_source" &&
    grep -q 'Both callbacks execute without the async-owner mutex held.' \
        "$snd_async_header" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(progress_callback_runs_unlocked_while_job_is_pinned\)' \
        "$snd_async_test" &&
    grep -q 'progress_callback_saw_unlocked_owner' "$snd_async_test" || {
	echo "virtio private interfaces: sound progress callback lifetime is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: sound progress callback lifetime validated"

# TEST-ANCHOR: memory-platform-callback-destruction-fence
# The memory model deliberately releases its ordinary locks around platform
# callbacks.  Public-operation admission must therefore retain the model and
# callback argument until destruction has drained every admitted call.
awk '
    /^virtio_mem_host_destroy\(struct virtio_mem_host \*host\)/ { in_destroy = 1 }
    in_destroy && /host->destroying = true;/ { closed = 1 }
    in_destroy && /while \(host->active_calls != 0\)/ { drain = 1 }
    in_destroy && /pthread_cond_wait\(&host->lifetime_cond, &host->lifetime_mutex\)/ && drain { waited = 1 }
    in_destroy && /free\(host\);/ { exit(closed && drain && waited ? 0 : 1) }
    END { if (!in_destroy) exit 1 }
' "$mem_host_source" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(destroy_drains_platform_callback\)' \
        "$mem_host_test" || {
	echo "virtio private interfaces: memory callback destruction fence is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: memory callback destruction fence validated"

# TEST-ANCHOR: sound-host-backend-callback-destruction-fence
# Synchronous sound backend operations retain operation_mutex across the
# callback.  Destruction must use the same lock before it can destroy the
# state mutex or reclaim the callback owner.
awk '
    /^virtio_snd_host_destroy\(struct virtio_snd_host \*host\)/ { in_destroy = 1 }
    in_destroy && /pthread_mutex_lock\(&host->operation_mutex\);/ { operation = 1 }
    in_destroy && /pthread_mutex_lock\(&host->state_mutex\);/ && operation { state = 1 }
    in_destroy && /pthread_mutex_unlock\(&host->state_mutex\);/ && state { state_unlock = 1 }
    in_destroy && /pthread_mutex_unlock\(&host->operation_mutex\);/ && state_unlock { operation_unlock = 1 }
    in_destroy && /pthread_mutex_destroy\(&host->state_mutex\);/ {
        exit(operation && state && state_unlock && operation_unlock ? 0 : 1)
    }
    END { if (!in_destroy) exit 1 }
' "$snd_host_source" &&
    grep -q 'Destruction serializes with a' "$snd_host_header" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(destroy_drains_selected_backend_callback\)' \
        "$snd_host_test" || {
	echo "virtio private interfaces: sound host destruction fence is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: sound host destruction fence validated"

# TEST-ANCHOR: rtc-init-failure-callback-retirement
# An RTC alarm event holds the PCI softc as its callback argument.  An init
# rollback which has installed that event must use the synchronous close-delete
# boundary before it can free the softc or its alarm model.
awk '
    /^pci_vtrtc_init\(/ { in_init = 1 }
    in_init && /^failed_mtx:/ { in_failure = 1 }
    in_failure && /mevent_delete_close_sync\(sc->vrsc_alarm_evp\)/ { sync_delete = 1 }
    in_failure && /virtio_rtc_alarm_destroy\(sc->vrsc_alarm\)/ {
        exit(sync_delete ? 0 : 1)
    }
    END { if (!in_init || !in_failure) exit 1 }
' "$rtc_pci_source" &&
    awk '
    /^mevent_delete_sync_event\(/ { in_delete = 1 }
    in_delete && /evp->me_closefd = 1;/ { queued_close = 1 }
    in_delete && /if \(closefd\)/ { saw_close = 1 }
    in_delete && /close\(evp->me_fd\);/ && saw_close { direct_close = 1 }
    in_delete && /^}\$/ { }
    END { exit(queued_close && direct_close ? 0 : 1) }
' "$mevent_source" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(delete_close_sync_retires_callback_before_fd_close\)' \
        "$mevent_test" || {
	echo "virtio private interfaces: RTC init-failure callback retirement is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: RTC init-failure callback retirement validated"

# TEST-ANCHOR: vsock-init-failure-child-event-retirement
# The userspace-vsock listener can admit child connection events before a
# later initialization step fails.  The failure path must close admission and
# withdraw list lookup before synchronously retiring child event references;
# otherwise a selected callback can retain the soon-to-be-freed device softc.
awk '
    /^vtvsock_init_failure_detach\(/ { in_detach = 1 }
    in_detach && /vtvsock_lifecycle_stop_locked\(sc\);/ { paused = 1 }
    in_detach && /TAILQ_CONCAT\(conns, &sc->vsc_conns, link\);/ { conns = paused }
    in_detach && /TAILQ_CONCAT\(ctl_conns, &sc->vsc_ctl_conns, link\);/ { ctls = conns }
    in_detach && /pthread_mutex_unlock\(&sc->vsc_mtx\);/ {
        exit(paused && conns && ctls ? 0 : 1)
    }
    END { if (!in_detach) exit 1 }
' "$vsock_pci_source" &&
    awk '
    /^vtvsock_conn_destroy_detached\(/ { in_conn = 1 }
    in_conn && /mevent_delete_sync\(conn->tx_evp\)/ { tx = 1 }
    in_conn && /mevent_delete_close_sync\(conn->evp\)/ { rx = tx }
    in_conn && /free\(conn\);/ { exit(rx ? 0 : 1) }
    END { if (!in_conn) exit 1 }
' "$vsock_pci_source" &&
    awk '
    /^failed:/ { in_failure = 1 }
    in_failure && /vtvsock_init_failure_detach\(sc, &conns, &ctl_conns\);/ { detached = 1 }
    in_failure && /vtvsock_conn_destroy_detached\(sc, conn\);/ { conn = detached }
    in_failure && /vtvsock_ctl_conn_destroy_detached\(cc\);/ { ctl = conn }
    in_failure && /free\(sc\);/ { exit(ctl ? 0 : 1) }
    END { if (!in_failure) exit 1 }
' "$vsock_pci_source" &&
    grep -Eq 'ATF_TC_WITHOUT_HEAD\(init_failure_detaches_and_retires_child_events\)' \
        "$vsock_device_test" || {
	echo "virtio private interfaces: vsock init-failure child retirement is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: vsock init-failure child event retirement validated"

# TEST-ANCHOR: fs-monotonic-checkpoint-wait
# The two filesystem checkpoint waits construct absolute CLOCK_MONOTONIC
# deadlines.  Keep the condition variable on that same clock: using the
# default realtime condition clock would make a clock adjustment look like an
# immediate timeout or an unexpectedly long quiesce.
grep -Eq '^#define[[:space:]]+VTFS_CHECKPOINT_TIMEOUT_SEC[[:space:]]+10$' \
    "$fs_source" &&
    grep -q 'pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC)' \
    "$fs_source" &&
    grep -q 'pthread_cond_init(&sc->vsc_checkpoint_cv, &condattr)' \
    "$fs_source" &&
    [ "$(rg -c -F 'clock_gettime(CLOCK_MONOTONIC, &deadline)' \
        "$fs_source")" -eq 2 ] &&
    [ "$(rg -c -F 'pthread_cond_timedwait(&sc->vsc_checkpoint_cv,' \
        "$fs_source")" -eq 2 ] || {
	echo "virtio private interfaces: filesystem checkpoint waits are not monotonic and bounded" >&2
	exit 1
}

# TEST-ANCHOR: pmem-monotonic-worker-drain
# Reset, suspend, and teardown all rely on the worker's bounded drain.  Its
# absolute deadline and condition variable must use the same monotonic clock,
# otherwise host wall-clock adjustment can violate the durable-owner fence.
grep -Eq '^#define[[:space:]]+VTPMEM_DRAIN_TIMEOUT_MS[[:space:]]+30000U$' \
    "$pmem_source" &&
    grep -q 'clock_gettime(CLOCK_MONOTONIC, deadline)' \
    "$pmem_worker_source" &&
    grep -q 'pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)' \
    "$pmem_worker_source" &&
    grep -q 'pthread_cond_init(&worker->condition, &attr)' \
    "$pmem_worker_source" &&
    grep -q 'pthread_cond_timedwait(&worker->condition, &worker->mutex,' \
    "$pmem_worker_source" &&
    grep -q 'virtio_pmem_worker_reset(sc->vsc_worker,' "$pmem_source" &&
    grep -q 'virtio_pmem_worker_destroy(sc->vsc_worker,' "$pmem_source" || {
	echo "virtio private interfaces: persistent-memory worker drain is not monotonic and lifecycle-bound" >&2
	exit 1
}

# TEST-ANCHOR: block-monotonic-reset-drain
# The block model pairs its bounded reset-drain deadline with a monotonic
# condition variable.  Timeout retains the generation fence rather than
# treating a delayed backend callback as a completed reset.
grep -Eq '^#define[[:space:]]+VTBLK_RESET_DRAIN_TIMEOUT_SECONDS[[:space:]]+[1-9][0-9]*$' \
    "$block_pci_source" &&
    grep -q 'clock_gettime(CLOCK_MONOTONIC, &deadline)' "$block_pci_source" &&
    grep -q 'pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC)' \
    "$block_pci_source" &&
    grep -q 'pthread_cond_init(&sc->vbsc_reset_cond, &condattr)' \
    "$block_pci_source" &&
    grep -q 'pci_vtblk_wait_requests_drained_until(sc, &deadline)' \
    "$block_pci_source" &&
    grep -q 'ATF_TC_WITHOUT_HEAD(reset_drain_timeout_is_bounded)' \
    "$block_pci_test" || {
	echo "virtio private interfaces: block reset drain is not monotonic and bounded" >&2
	exit 1
}
virtio_guest_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_guest_contract_test.c
virtio_pci_guest=$source_root/sys/dev/virtio/pci/virtio_pci_modern.c
virtio_pci_host=$source_root/usr.sbin/bhyve/virtio_pci_modern.c
virtio_pci_common=$source_root/sys/dev/virtio/pci/virtio_pci.c
virtio_mmio_guest=$source_root/sys/dev/virtio/mmio/virtio_mmio.c
virtio_gpu_guest=$source_root/sys/dev/virtio/gpu/virtio_gpu.c
virtio_balloon_guest=$source_root/sys/dev/virtio/balloon/virtio_balloon.c
virtio_rtc_guest=$source_root/sys/dev/virtio/rtc/virtio_rtc.c
virtio_block_guest=$source_root/sys/dev/virtio/block/virtio_blk.c
virtio_scsi_guest=$source_root/sys/dev/virtio/scsi/virtio_scsi.c
virtio_scsi_var=$source_root/sys/dev/virtio/scsi/virtio_scsivar.h
virtio_console_guest=$source_root/sys/dev/virtio/console/virtio_console.c
virtio_input_guest=$source_root/sys/dev/virtio/input/virtio_input.c
virtio_p9_guest=$source_root/sys/dev/virtio/p9fs/virtio_p9fs.c
virtio_net_guest=$source_root/sys/dev/virtio/network/if_vtnet.c
virtio_net_var=$source_root/sys/dev/virtio/network/if_vtnetvar.h
vsock_domain_header=$source_root/sys/kern/uipc_vsock.h
vsock_domain_source=$source_root/sys/kern/uipc_vsock.c
vsock_rx_test=$source_root/tests/sys/kern/vsock_rx_harness/vsock_rx_test.c
grep -Eq '^#define[[:space:]]+VTVSOCK_MAX_CONNS[[:space:]]+256$' \
    "$bhyve_vsock" &&
    grep -q 'ATF_REQUIRE_EQ(VTVSOCK_MAX_CONNS, 256)' \
    "$bhyve_vsock_test" || {
	echo "virtio private interfaces: bhyve vsock connection policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTVSOCK_MAX_CTL_CONNS[[:space:]]+16$' \
    "$bhyve_vsock" &&
    grep -q 'ATF_REQUIRE_EQ(VTVSOCK_MAX_CTL_CONNS, 16)' \
    "$bhyve_vsock_test" || {
	echo "virtio private interfaces: bhyve vsock control-client policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTFS_MAX_REQUEST_QUEUES[[:space:]]+64U$' \
    "$fs_source" &&
    grep -q 'ATF_REQUIRE_EQ(VTFS_MAX_REQUEST_QUEUES, 64U)' "$fs_test" &&
    grep -q 'ATF_REQUIRE_EQ(VTFS_MAX_INFLIGHT, 4096U)' "$fs_test" || {
	echo "virtio private interfaces: virtio-fs capacity policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTIOMMU_MAX_MAPPINGS[[:space:]]+8192$' \
    "$iommu_source" &&
    grep -q 'ATF_REQUIRE_EQ(limits.max_endpoints, 256U)' "$iommu_test" &&
    grep -q 'ATF_REQUIRE_EQ(limits.max_domains, 256U)' "$iommu_test" &&
    grep -q 'ATF_REQUIRE_EQ(limits.max_mappings, 8192U)' "$iommu_test" &&
    grep -q 'ATF_REQUIRE_EQ(limits.max_faults, 256U)' "$iommu_test" || {
	echo "virtio private interfaces: virtio-IOMMU table policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTINPUT_MAX_FRAME_EVENTS[[:space:]]+4096$' \
    "$input_source" &&
    grep -q 'ATF_REQUIRE_EQ(VTINPUT_MAX_FRAME_EVENTS, 4096)' "$input_test" || {
	echo "virtio private interfaces: input frame policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTRND_MAX_BYTES[[:space:]]+\(64 \* 1024\)$' \
    "$rng_source" &&
    grep -q 'ATF_REQUIRE_EQ(VTRND_MAX_BYTES, 65536U)' "$rng_test" || {
	echo "virtio private interfaces: RNG service limit is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTNET_MAXSEGS[[:space:]]+256$' \
    "$net_source" &&
    grep -q 'ATF_REQUIRE_EQ(VTNET_MAXSEGS, 256)' "$net_test" || {
	echo "virtio private interfaces: net descriptor limit is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+BLOCKIF_NUMTHR[[:space:]]+8$' \
    "$block_source" &&
    grep -q 'ATF_REQUIRE_EQ(BLOCKIF_RING_MAX, 1024)' "$block_test" &&
    grep -q 'ATF_REQUIRE_EQ(BLOCKIF_NUMTHR, 8)' "$block_test" &&
    grep -q 'ATF_REQUIRE_EQ(BLOCKIF_MAXREQ, 1032)' "$block_test" || {
	echo "virtio private interfaces: block scheduler capacity is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+CHECKPOINT_NUMA_MAX_DOMAINS[[:space:]]+8$' \
    "$topology_source" &&
    grep -q 'ATF_REQUIRE_EQ(CHECKPOINT_NUMA_MAX_DOMAINS, 8)' \
    "$topology_test" || {
	echo "virtio private interfaces: checkpoint NUMA cap is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+SCMI_VIRTIO_POLLING_INTERVAL_MS[[:space:]]+2U$' \
    "$scmi_poll_header" &&
    grep -q 'scmi_virtio_poll_probes(tmo_ms)' "$scmi_poll_source" &&
    grep -q 'scmi_virtio_poll_timed_out(' "$scmi_poll_source" &&
    grep -q 'ATF_REQUIRE_EQ(1U, scmi_virtio_poll_probes(1))' \
    "$scmi_poll_test" &&
    grep -q 'ATF_REQUIRE(!scmi_virtio_poll_timed_out(1))' \
    "$scmi_poll_test" || {
	echo "virtio private interfaces: SCMI polling policy is unpinned" >&2
	exit 1
}
# TEST-ANCHOR: queue-reset-poll-deadline
grep -Eq '^#define[[:space:]]+VIRTIO_RESET_POLL_DELAY_US[[:space:]]+1000U$' \
    "$virtio_guest_header" &&
    grep -Eq '^#define[[:space:]]+VIRTIO_QUEUE_RESET_TIMEOUT_US[[:space:]]+1000000U$' \
    "$virtio_guest_header" &&
    grep -q 'ATF_CHECK_EQ(VIRTIO_QUEUE_RESET_PROBES, 1001U)' \
    "$virtio_guest_test" &&
    grep -q 'ATF_CHECK(!virtio_queue_reset_probe_should_delay(1000U))' \
    "$virtio_guest_test" || {
	echo "virtio private interfaces: queue-reset polling deadline is unpinned" >&2
	exit 1
}
# TEST-ANCHOR: full-reset-ownership-wait
grep -Eq 'while \(vtpci_modern_get_status\(sc\) != VIRTIO_CONFIG_STATUS_RESET\)' \
    "$virtio_pci_guest" &&
    grep -Eq 'while \(vtmmio_get_status\(sc->dev\) !=' "$virtio_mmio_guest" &&
    grep -q 'DELAY(VIRTIO_RESET_POLL_DELAY_US)' "$virtio_pci_guest" &&
    grep -q 'DELAY(VIRTIO_RESET_POLL_DELAY_US)' "$virtio_mmio_guest" || {
	echo "virtio private interfaces: full reset can release device-owned memory" >&2
	exit 1
}
# TEST-ANCHOR: suspend-resume-poll-deadline
for lifecycle_source in "$virtio_pci_guest" "$virtio_mmio_guest"; do
	awk '
/^vt(pci_modern|mmio)_wait_lifecycle\(/ { in_function = 1 }
in_function && /get_status/ { status = NR }
in_function && /sbinuptime\(\) >= deadline/ { deadline = NR }
in_function && /pause_sbt/ { pause = NR }
in_function && /^}/ {
	if (status != 0 && deadline > status && pause > deadline)
		exit 0
	exit 1
}
END { if (!in_function) exit 1 }
' "$lifecycle_source" || {
		echo "virtio private interfaces: lifecycle deadline skips its final status probe" >&2
		exit 1
	}
done
# TEST-ANCHOR: guest-suspend-rollback-fence
# The one-second suspend deadline is FreeBSD policy.  A timeout at the exact
# completion boundary must undo the device transition before the function
# driver is reopened; an indeterminate or failed device remains fenced.
grep -q 'virtio_device_lifecycle_state' "$virtio_guest_header" &&
    grep -q 'VIRTIO_DEVICE_LIFECYCLE_FAILED' "$virtio_guest_test" &&
    grep -q 'VIRTIO_DEVICE_LIFECYCLE_TRANSITION' "$virtio_guest_test" || {
	echo "virtio private interfaces: suspend rollback classifier is untested" >&2
	exit 1
}
for lifecycle_source in "$virtio_pci_guest" "$virtio_mmio_guest"; do
	awk '
/^vt(pci_modern|mmio)_suspend_rollback\(/ { in_function = 1 }
in_function && /VIRTIO_DEVICE_LIFECYCLE_FAILED/ { failed = NR }
in_function && /VIRTIO_DEVICE_LIFECYCLE_RUNNING/ { running = NR }
in_function && /VIRTIO_DEVICE_LIFECYCLE_SUSPENDED/ { suspended = NR }
in_function && /wait_lifecycle\(.*false\)/ { device_resume = NR }
in_function && /bus_generic_resume\(dev\)/ { child_resume = NR }
in_function && /VIRTIO_CONFIG_STATUS_FAILED/ { poison = NR }
in_function && /^}/ {
	ok = failed != 0 && running > failed && suspended > running &&
	    device_resume > suspended && child_resume > device_resume &&
	    poison > child_resume
	exit(ok ? 0 : 1)
}
END { if (!in_function) exit 1 }
' "$lifecycle_source" || {
		echo "virtio private interfaces: unsafe guest suspend rollback transaction" >&2
		exit 1
	}
done
grep -q 'vs->vs_status |= requested_status &' "$virtio_pci_host" &&
    grep -q 'VIRTIO_CONFIG_STATUS_FAILED' "$virtio_pci_host" || {
	echo "virtio private interfaces: suspended device rejects driver FAILED" >&2
	exit 1
}
# TEST-ANCHOR: guest-request-absolute-deadlines
grep -Eq '^#define[[:space:]]+VTGPU_REQUEST_TIMEOUT[[:space:]]+\(10 \* SBT_1S\)$' \
    "$virtio_gpu_guest" &&
    grep -q 'deadline = sbinuptime() + VTGPU_REQUEST_TIMEOUT' \
    "$virtio_gpu_guest" &&
    grep -q 'remaining = deadline - sbinuptime()' "$virtio_gpu_guest" || {
	echo "virtio private interfaces: GPU request wait renews its deadline" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTBALLOON_REQUEST_TIMEOUT[[:space:]]+\(5 \* SBT_1S\)$' \
    "$virtio_balloon_guest" &&
    grep -q 'deadline = sbinuptime() + VTBALLOON_REQUEST_TIMEOUT' \
    "$virtio_balloon_guest" &&
    grep -q 'remaining = deadline - sbinuptime()' \
    "$virtio_balloon_guest" || {
	echo "virtio private interfaces: balloon request wait renews its deadline" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTRTC_REQUEST_TIMEOUT[[:space:]]+\(10 \* SBT_1S\)$' \
    "$virtio_rtc_guest" &&
    grep -q 'deadline = sbinuptime() + VTRTC_REQUEST_TIMEOUT' \
    "$virtio_rtc_guest" &&
    grep -q 'remaining = deadline - sbinuptime()' "$virtio_rtc_guest" || {
	echo "virtio private interfaces: RTC request wait renews its deadline" >&2
	exit 1
}
# TEST-ANCHOR: guest-resource-policy
grep -Eq '^#define[[:space:]]+VTSCSI_MAX_REQUEST_VQS[[:space:]]+64$' \
    "$virtio_scsi_guest" &&
    grep -q 'MIN(mp_ncpus, VTSCSI_MAX_REQUEST_VQS)' "$virtio_scsi_guest" &&
    grep -Eq '^#define[[:space:]]+VTSCSI_NUM_EVENT_BUFS[[:space:]]+4$' \
    "$virtio_scsi_var" &&
    grep -Eq '^#define[[:space:]]+VTSCSI_MAX_EVENT_SIZE[[:space:]]+\(1024 \* 1024\)$' \
    "$virtio_scsi_var" &&
    grep -q 'vtscsi_event_buf_size > VTSCSI_MAX_EVENT_SIZE' \
    "$virtio_scsi_guest" || {
	echo "virtio private interfaces: guest SCSI resource policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTBLK_MAX_VQS[[:space:]]+64$' \
    "$virtio_block_guest" &&
    grep -Eq '^#define[[:space:]]+VTBLK_QUIESCE_TIMEOUT[[:space:]]+\(30 \* SBT_1S\)$' \
    "$virtio_block_guest" &&
    grep -q 'deadline = sbinuptime() + VTBLK_QUIESCE_TIMEOUT' \
    "$virtio_block_guest" &&
    grep -q 'remaining = deadline - sbinuptime()' "$virtio_block_guest" || {
	echo "virtio private interfaces: guest block resource policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTCON_MAX_PORTS[[:space:]]+32$' \
    "$virtio_console_guest" &&
    grep -q 'min(concfg->max_nr_ports, VTCON_MAX_PORTS)' \
    "$virtio_console_guest" || {
	echo "virtio private interfaces: guest console port policy is unpinned" >&2
	exit 1
}
# TEST-ANCHOR: console-io-timeout-policy
grep -Eq '^#define[[:space:]]+VTCON_IO_TIMEOUT[[:space:]]+\(5 \* SBT_1S\)$' \
    "$virtio_console_guest" &&
    [ "$(grep -c 'deadline = sbinuptime() + VTCON_IO_TIMEOUT' \
        "$virtio_console_guest")" -eq 2 ] &&
    [ "$(grep -c 'atomic_set_32(&sc->vtcon_flags, VTCON_FLAG_FAILED)' \
        "$virtio_console_guest")" -eq 2 ] &&
    [ "$(grep -c 'virtqueue_drain(vq, &last)' \
        "$virtio_console_guest")" -ge 2 ] || {
	echo "virtio private interfaces: guest console I/O timeout is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTINPUT_EVENT_SLOTS[[:space:]]+64$' \
    "$virtio_input_guest" &&
    grep -Eq '^#define[[:space:]]+VTINPUT_STATUS_SLOTS[[:space:]]+32$' \
    "$virtio_input_guest" || {
	echo "virtio private interfaces: guest input slot policy is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTGPU_MAX_FB_SIZE[[:space:]]+\(256U \* 1024U \* 1024U\)$' \
    "$virtio_gpu_guest" &&
    grep -q '(uint64_t)VTGPU_MAX_FB_SIZE' "$virtio_gpu_guest" || {
	echo "virtio private interfaces: guest GPU framebuffer policy is unpinned" >&2
	exit 1
}
# TEST-ANCHOR: guest-gpu-deferred-flush
grep -q 'mtx_init(&sc->vtgpu_dirty_mtx, device_get_nameunit(dev),' \
    "$virtio_gpu_guest" &&
	grep -q '"VirtIO GPU dirty rectangle", MTX_SPIN)' \
	    "$virtio_gpu_guest" &&
	grep -q 'taskqueue_create_fast("vtgpu_flush", M_WAITOK,' \
	    "$virtio_gpu_guest" &&
	grep -q 'taskqueue_start_threads(&sc->vtgpu_flush_tq, 1, PI_TTY,' \
	    "$virtio_gpu_guest" &&
	grep -q 'taskqueue_enqueue(sc->vtgpu_flush_tq, &sc->vtgpu_flush_task)' \
	    "$virtio_gpu_guest" &&
	grep -q 'taskqueue_drain(sc->vtgpu_flush_tq, &sc->vtgpu_flush_task)' \
	    "$virtio_gpu_guest" &&
	grep -q 'taskqueue_free(sc->vtgpu_flush_tq)' \
	    "$virtio_gpu_guest" &&
	grep -q 'atomic_set_rel_int(&sc->vtgpu_flags, VTGPU_FLAG_DETACH)' \
	    "$virtio_gpu_guest" || {
	echo "virtio private interfaces: guest GPU deferred flush is unpinned" >&2
	exit 1
}
grep -Eq '^#define[[:space:]]+VTBALLOON_PFNS_PER_REQUEST[[:space:]]+256$' \
    "$virtio_balloon_guest" &&
    grep -q 'CTASSERT(VTBALLOON_PFNS_PER_REQUEST \* sizeof(uint32_t) <= PAGE_SIZE)' \
    "$virtio_balloon_guest" || {
	echo "virtio private interfaces: guest balloon batch policy is unpinned" >&2
	exit 1
}
# TEST-ANCHOR: p9-absolute-request-deadline
grep -Eq '^static unsigned int vt9p_ackmaxidle = 120;$' "$virtio_p9_guest" &&
    grep -q 'deadline = timeout > SBT_MAX - now ? SBT_MAX : now + timeout' \
    "$virtio_p9_guest" &&
    grep -q 'if (req->tc->tag == req->rc->tag)' "$virtio_p9_guest" &&
    grep -q 'remaining = deadline - sbinuptime()' "$virtio_p9_guest" &&
    grep -q 'vt9p_fail_locked(chan)' "$virtio_p9_guest" || {
	echo "virtio private interfaces: 9P request wait is not an absolute predicate loop" >&2
	exit 1
}
# TEST-ANCHOR: guest-network-policy
grep -Eq '^#define[[:space:]]+VTNET_MAX_QUEUE_PAIRS[[:space:]]+32$' \
    "$virtio_net_var" &&
    grep -Eq '^#define[[:space:]]+VTNET_INTR_DISABLE_RETRIES[[:space:]]+4$' \
    "$virtio_net_var" &&
    grep -Eq '^#define[[:space:]]+VTNET_NOTIFY_RETRIES[[:space:]]+4$' \
    "$virtio_net_var" &&
    grep -Eq '^#define[[:space:]]+VTNET_MAX_MAC_ENTRIES[[:space:]]+128$' \
    "$virtio_net_var" &&
    grep -Eq '^#define[[:space:]]+VTNET_TX_TIMEOUT[[:space:]]+5$' \
    "$virtio_net_var" &&
    grep -Eq '^#define[[:space:]]+VTNET_TX_SEGS_MAX[[:space:]]+64$' \
    "$virtio_net_var" &&
    grep -Eq '^static int vtnet_rx_process_limit = 1024;$' \
    "$virtio_net_guest" &&
    grep -Eq '^static int vtnet_lro_entry_count = 128;$' \
    "$virtio_net_guest" || {
	echo "virtio private interfaces: guest network policy is unpinned" >&2
	exit 1
}
# TEST-ANCHOR: guest-buffer-policy
grep -Eq '^#define MAX_SUPPORTED_SGS 20$' "$virtio_p9_guest" &&
    grep -q 'chan->max_nsegs = MAX_SUPPORTED_SGS' "$virtio_p9_guest" &&
    grep -Eq '^#define VTCON_BULK_BUFSZ 128$' "$virtio_console_guest" &&
    grep -Eq '^#define VTCON_CTRL_BUFSZ 128$' "$virtio_console_guest" &&
    grep -Eq '^#define VIRTIO_MAX_INDIRECT \(\(int\) \(PAGE_SIZE / 16\)\)$' \
    "$virtio_guest_header" || {
	echo "virtio private interfaces: guest buffer policy is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: vsock-callout-policy
grep -Eq '^#define[[:space:]]+VTVSOCK_CLOSE_TIMEOUT[[:space:]]+\(hz \* 8\)$' \
    "$vsock_domain_header" &&
    grep -Eq '^#define[[:space:]]+VTVSOCK_CONNECT_TIMEOUT[[:space:]]+\(hz \* 2\)$' \
    "$vsock_domain_header" &&
    grep -q 'callout_drain(&pcb->close_callout)' "$vsock_domain_source" &&
    grep -q 'callout_drain(&pcb->connect_callout)' "$vsock_domain_source" &&
    grep -q 'ATF_TC_WITHOUT_HEAD(connect_timeout_preserves_retryable_binding)' \
    "$vsock_rx_test" &&
    grep -q 'ATF_TC_WITHOUT_HEAD(deferred_shutdown_timeout)' \
    "$vsock_rx_test" || {
	echo "virtio private interfaces: vsock callout policy is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: balloon-lowmem-policy
grep -Eq '^#define VTBALLOON_LOWMEM_TIMEOUT[[:space:]]+hz$' \
    "$virtio_balloon_guest" &&
    grep -q 'sc->vtballoon_timeout = VTBALLOON_LOWMEM_TIMEOUT' \
    "$virtio_balloon_guest" || {
	echo "virtio private interfaces: balloon low-memory retry is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: scsi-reserved-requests
grep -Eq '^#define VTSCSI_RESERVED_REQUESTS[[:space:]]+10$' \
    "$virtio_scsi_var" &&
    grep -q 'openings = sc->vtscsi_nrequests - VTSCSI_RESERVED_REQUESTS' \
    "$virtio_scsi_guest" &&
    grep -q 'nreqs += VTSCSI_RESERVED_REQUESTS' "$virtio_scsi_guest" || {
	echo "virtio private interfaces: SCSI request reserve is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: console-unload-ownership-wait
awk '
/^vtcon_drain_all\(void\)/ { in_function = 1 }
in_function && /for \(.*vtcon_pending_free != 0/ { predicate = NR }
in_function && /msleep\(&vtcon_pending_free/ { wait = NR }
in_function && /^}/ {
	exit(predicate != 0 && wait > predicate ? 0 : 1)
}
END { if (!in_function) exit 1 }
' "$virtio_console_guest" &&
    grep -q 'tty_rel_gone(tp)' "$virtio_console_guest" &&
    grep -q 'wakeup(&vtcon_pending_free)' "$virtio_console_guest" || {
	echo "virtio private interfaces: console unload ownership wait is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: guest-pci-tunables
grep -q 'int vtpci_disable_msix = 0;' "$virtio_pci_common" &&
    grep -q 'OID_AUTO, disable_msix, CTLFLAG_RDTUN' "$virtio_pci_common" &&
    grep -q 'static int vtpci_modern_transitional = 1;' "$virtio_pci_guest" &&
    grep -q 'OID_AUTO, transitional, CTLFLAG_RDTUN' "$virtio_pci_guest" || {
	echo "virtio private interfaces: PCI guest tunables are unpinned" >&2
	exit 1
}

# TEST-ANCHOR: guest-block-policy
grep -q 'static int vtblk_no_ident = 0;' "$virtio_block_guest" &&
    grep -q 'static int vtblk_writecache_mode = -1;' "$virtio_block_guest" &&
    grep -q 'if ((sc->vtblk_flags & VTBLK_FLAG_WCE_CONFIG) == 0)' \
    "$virtio_block_guest" &&
    grep -q 'OID_AUTO, "writecache_mode"' "$virtio_block_guest" &&
    grep -q 'OID_AUTO, "num_queues"' "$virtio_block_guest" &&
    grep -q 'while (sc->vtblk_flags & VTBLK_FLAG_BUSDMA_WAIT)' \
    "$virtio_block_guest" &&
    grep -q '(VTBLK_FLAG_SUSPEND | VTBLK_FLAG_DETACH)' \
    "$virtio_block_guest" &&
    grep -q 'VTBLK_FLAG_BUSDMA_WAIT) != 0 ||' \
    "$virtio_block_guest" || {
	echo "virtio private interfaces: block guest policy is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: block-crash-dump-polling
# The dump path has no scheduler/interrupt progress guarantee and uses a
# preallocated request.  Keep this unbounded emergency policy isolated from
# ordinary I/O and require the old queue to be drained before publishing the
# dedicated dump request.
awk '
/^vtblk_dump_quiesce\(/ { in_quiesce = 1 }
in_quiesce && /while \(!vtblk_virtqueues_empty\(sc\)\)/ { predicate = NR }
in_quiesce && /vtblk_queue_completed/ { dequeue = NR }
in_quiesce && /^}/ { in_quiesce = 0 }
/^vtblk_dump_write\(/ { write = NR }
/^vtblk_dump_flush\(/ { flush = NR }
END {
	exit(predicate != 0 && dequeue > predicate && write > dequeue &&
	    flush > write ? 0 : 1)
}
' "$virtio_block_guest" &&
    grep -q 'req = &sc->vtblk_dump_request' "$virtio_block_guest" &&
    grep -q 'req1 = virtqueue_poll(vq, NULL)' "$virtio_block_guest" || {
	echo "virtio private interfaces: block crash-dump polling policy is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: guest-rtc-sysctl-policy
grep -q 'OID_AUTO, "alarm_time_ns"' "$virtio_rtc_guest" &&
    grep -q 'CTLTYPE_U64 | CTLFLAG_RW | CTLFLAG_MPSAFE' \
    "$virtio_rtc_guest" &&
    grep -q 'OID_AUTO, "alarm_count"' "$virtio_rtc_guest" &&
    grep -q 'OID_AUTO, "alarm_observed_time_ns"' "$virtio_rtc_guest" &&
    grep -q 'CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE' \
    "$virtio_rtc_guest" &&
    grep -q 'return (vtrtc_alarm_control(sc, alarm_time, alarm_time != 0))' \
    "$virtio_rtc_guest" &&
    grep -q 'sc->alarm_time = alarm_time' "$virtio_rtc_guest" || {
	echo "virtio private interfaces: RTC sysctl management policy is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: guest-scsi-policy
grep -q 'static int vtscsi_bus_reset_disable = 1;' "$virtio_scsi_guest" &&
    grep -q 'TUNABLE_INT("hw.vtscsi.bus_reset_disable"' \
    "$virtio_scsi_guest" &&
    grep -q 'OID_AUTO, "debug_level"' "$virtio_scsi_guest" &&
    grep -q 'OID_AUTO, "num_queues"' "$virtio_scsi_guest" &&
    grep -q 'OID_AUTO, "scsi_cmd_timeouts"' "$virtio_scsi_guest" || {
	echo "virtio private interfaces: SCSI guest policy is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: guest-pci-observability
grep -q 'OID_AUTO, "nvqs"' "$virtio_pci_common" &&
    grep -q 'OID_AUTO, "host_features"' "$virtio_pci_common" &&
    grep -q 'OID_AUTO, "negotiated_features"' "$virtio_pci_common" || {
	echo "virtio private interfaces: PCI observability is unpinned" >&2
	exit 1
}

# TEST-ANCHOR: guest-p9-observability
grep -q 'mount_tag_len == 0 || mount_tag_len >= MAXPATHLEN' \
    "$virtio_p9_guest" &&
    grep -Fq "memchr(mount_tag, '\\0', mount_tag_len)" "$virtio_p9_guest" &&
    grep -q 'OID_AUTO, "p9fs_mount_tag"' "$virtio_p9_guest" || {
	echo "virtio private interfaces: 9P observability is unpinned" >&2
	exit 1
}
echo "virtio private interfaces: SCMI callback lifetime validated"

# TEST-ANCHOR: provider-operation-fence
# Provider management uses a private bounded wait.  Pin both its policy value
# and the admission fence which makes the bound reliable under continuous I/O.
grep -Eq '^#define[[:space:]]+VSOCK_USER_OPERATION_TIMEOUT_SECONDS[[:space:]]+30$' \
    "$user_vsock" || {
	echo "virtio private interfaces: provider operation timeout is unpinned" >&2
	exit 1
}
grep -Eq 'if \(!provider->frozen && provider->read_inflight == 0 &&' \
    "$user_vsock" || {
	echo "virtio private interfaces: frozen provider still admits reads" >&2
	exit 1
}
awk '
/cmd == VSOCK_IOC_TRANSPORT_SET_FEATURES/ { in_features = 1 }
in_features && /provider->frozen = true/ { close_admission = NR }
in_features && /while \(provider->write_thread != NULL/ { wait_copy = NR }
in_features && /provider->frozen = false/ { reopen = NR }
in_features && /cmd == VSOCK_IOC_TRANSPORT_FREEZE/ {
	exit(close_admission != 0 && wait_copy > close_admission &&
	    reopen > wait_copy ? 0 : 1)
}
END { if (!in_features) exit 1 }
' "$user_vsock" || {
	echo "virtio private interfaces: feature update lacks a bounded admission fence" >&2
	exit 1
}
awk '
/cmd == VSOCK_IOC_TRANSPORT_RESET/ { in_reset = 1 }
in_reset && /provider->frozen = true/ { close_admission = NR }
in_reset && /while \(provider->write_thread != NULL/ { wait_copy = NR }
in_reset && /reset_precommit_error:/ { rollback = NR }
in_reset && /return \(ENOTTY\)/ {
	ok = close_admission != 0 && wait_copy > close_admission &&
	    rollback > wait_copy
	exit(ok ? 0 : 1)
}
END { if (!in_reset) exit 1 }
' "$user_vsock" || {
	echo "virtio private interfaces: provider reset lacks an admission fence and rollback" >&2
	exit 1
}
echo "virtio private interfaces: provider operation fence validated"

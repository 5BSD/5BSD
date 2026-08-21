#!/bin/sh
# Build and run the bhyve virtio-vsock device-level TX harness locally.
#
# In the tree this is a normal ATF test (see tests/sys/kern/Makefile).  This
# script runs it WITHOUT the ATF runtime: it supplies a tiny <atf-c.h> shim (in
# a throwaway dir, never in the source tree, so it cannot shadow the real ATF
# build) that runs each ATF_TC_BODY inline and reports failures.  It also
# #includes the real pci_virtio_vsock.c and shadows its bhyve headers with the
# mocks here, and compiles against the SOURCE <sys/vsock.h> (pkgbase-installed
# headers may lag the tree).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
srctop=${SRCTOP:-/usr/src}
cc=${CC:-cc}
sanitizers=${SANITIZERS:-address,undefined}
ASAN_OPTIONS=${ASAN_OPTIONS:-halt_on_error=1:abort_on_error=1}
UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:abort_on_error=1:print_stacktrace=1}
export ASAN_OPTIONS UBSAN_OPTIONS
work=$(mktemp -d)
# Optional durable completion record for orchestration wrappers whose captured
# stdout is unavailable after the process exits.  The file is published only
# after every compiler and sanitizer lane has succeeded; callers own the
# parent directory and may use it as an explicit completion contract.
result_file=${RESULT_FILE:-}
result_started=0
cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	# A successful run publishes PASS below as its final operation.  On every
	# earlier exit, replace RUNNING with an explicit non-success state so an
	# orchestrator neither reuses stale success nor mistakes a failed worker for
	# one which is merely slow.  This is diagnostic state only: inability to
	# write it must not mask the compiler/test failure that caused this cleanup.
	if [ -n "$result_file" ] && [ "$result_started" -eq 1 ] &&
	    [ "$status" -ne 0 ]; then
		result_tmp="${result_file}.tmp.$$"
		( printf 'FAIL device harness exit=%s workdir=%s\n' "$status" \
		    "$work" > "$result_tmp" &&
		    mv -f "$result_tmp" "$result_file" ) ||
		    rm -f "$result_tmp" 2>/dev/null || :
	fi
	if [ "${KEEP_WORK:-no}" = yes ]; then
		echo "device harness: preserving workdir $work" >&2
	else
		rm -rf "$work"
	fi
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

if [ -n "$result_file" ]; then
	result_tmp="${result_file}.tmp.$$"
	printf 'RUNNING device harness pid=%s workdir=%s\n' "$$" "$work" > "$result_tmp"
	mv -f "$result_tmp" "$result_file"
	result_started=1
fi

"$here/validate-waspnest-completion-matrix.sh"
"$here/validate-virtio-requirements.sh" \
    "$here/virtio-1.4-requirements.tsv"
"$here/validate-virtio-reference-corpus.sh" \
    "$here/virtio-reference-corpus.tsv" --waspnest
"$here/validate-virtio-dtrace.sh"
"$here/validate-virtio-snapshot-portability.sh"
"$here/validate-virtio-snapshot-portability-selftest.sh"
"$here/validate-virtio-snapshot-runner-selftest.sh"
"$here/validate-virtio-dma-boundary.sh"
sh "$here/validate-sanitizer-parity.sh"
# The normative ledger deliberately excludes implementation-defined and
# withheld interfaces.  Make their separate owner/rollback/negative-test
# ledger a required harness gate as well, so a full rootless pass cannot
# silently omit private backend and unsupported-operation review.
"$here/validate-virtio-nonstandard-interfaces.sh" \
    "$here/virtio-nonstandard-interfaces.tsv" "$srctop"

cp "$here"/*.h "$here/vsock_device_test.c" \
    "$here/virtio_modern_test.c" "$here/virtio_input_test.c" \
    "$here/virtio_rnd_test.c" "$here/virtio_rnd_interrupt_test.c" \
	"$here/virtio_core_test.c" "$here/iov_test.c" \
	"$here/virtio_console_test.c" "$here/virtio_9p_test.c" \
	"$here/virtio_block_test.c" "$here/virtio_blk_capacity_test.c" \
	"$here/block_if_test.c" \
	"$here/audio_test.c" \
	"$here/virtio_net_test.c" \
	"$here/virtio_scsi_test.c" "$here/virtio_guest_contract_test.c" \
	"$here/virtio_host_contract_test.c" "$here/pci_checkpoint_test.c" \
	"$here/checkpoint_compat_test.c" "$here/checkpoint_machine_test.c" \
	"$here/virtio_packed_model_test.c" "$here/virtio_packed_engine_test.c" \
	"$here/virtio_balloon_host_test.c" "$here/virtio_balloon_test.c" \
	"$here/virtio_rtc_host_test.c" "$here/virtio_rtc_test.c" \
	"$here/virtio_pmem_host_test.c" "$here/virtio_pmem_queue_test.c" \
	"$here/virtio_pmem_async_test.c" \
	"$here/virtio_pmem_worker_test.c" \
	"$here/virtio_pmem_pci_test.c" \
	"$here/virtio_rtc_alarm_test.c" \
	"$here/virtio_fs_host_test.c" "$here/virtio_fs_backend_test.c" \
	"$here/virtio_fs_backend_io_test.c" \
	"$here/virtio_fs_backend_client_test.c" \
	"$here/virtio_fs_connection_test.c" \
	"$here/virtio_fs_pending_test.c" \
	"$here/virtio_fs_state_test.c" \
	"$here/virtio_fs_dispatch_test.c" \
	"$here/virtio_fs_chain_test.c" \
	"$here/virtio_fs_outbox_test.c" \
	"$here/virtio_fs_queue_test.c" \
	"$here/virtio_fs_pci_test.c" \
	"$here/virtio_fs_export_test.c" \
	"$here/virtio_fs_fuse_test.c" \
	"$here/virtio_fs_handle_test.c" \
	"$here/virtio_fs_session_test.c" \
	"$here/virtio_fs_server_test.c" \
	"$here/virtiofsd_daemon_test.c" \
	"$here/virtio_gpu_2d_protocol_test.c" \
	"$here/virtio_gpu_2d_state_test.c" \
	"$here/virtio_gpu_2d_queue_test.c" \
	"$here/virtio_gpu_2d_display_test.c" \
	"$here/virtio_gpu_2d_pci_test.c" \
	"$here/virtio_iommu_config_test.c" \
	"$here/virtio_iommu_pci_test.c" \
	"$here/virtio_iommu_state_test.c" \
	"$here/virtio_iommu_protocol_test.c" \
	"$here/virtio_iommu_request_test.c" \
	"$here/virtio_iommu_queue_test.c" \
	"$here/virtio_iommu_event_test.c" \
	"$here/virtio_iommu_topology_test.c" \
	"$here/virtio_iommu_viot_test.c" \
	"$here/virtio_mem_host_test.c" "$here/virtio_mem_test.c" \
	"$here/bhyvegc_test.c" \
	"$here/usb_mouse_model_test.c" \
	"$here/pci_nvme_model_test.c" \
	"$here/pci_ahci_model_test.c" \
	"$here/pci_e82545_model_test.c" \
	"$here/pci_fbuf_model_test.c" \
	"$here/pci_hda_model_test.c" \
	"$here/pci_xhci_model_test.c" \
	"$here/uart_backend_model_test.c" \
	"$here/console_owner_test.c" \
	"$here/mevent_lifecycle_test.c" \
	"$here/tpm_intf_crb_model_test.c" \
	"$here/pvpanic_model_test.c" \
	"$here/virtio_snd_async_test.c" \
	"$here/virtio_snd_host_test.c" "$here/virtio_snd_queue_test.c" \
	"$here/virtio_snd_test.c" \
	"$here/virtio_admin_test.c" \
	"$here/virtio_admin_pci_test.c" \
	"$here/virtio_admin_capability_test.c" \
	"$here/virtio_admin_device_parts_test.c" \
	"$here/virtio_admin_group_test.c" \
	"$here/virtio_admin_resource_test.c" \
	"$here/virtio_admin_sriov_test.c" \
	"$here/virtio_device_parts_test.c" \
	"$here/virtio_device_parts_handler_test.c" \
	"$here/checkpoint_topology_test.c" \
	"$here/checkpoint_numa_test.c" \
	"$here/checkpoint_cpu_test.c" \
	"$here/checkpoint_cpu_machdep_test.c" \
	"$here/lib9p_fs_path_test.c" \
	"$here/p9_guest_wire_test.c" \
	"$here/snapshot_manifest_test.c" \
	"$here/snapshot_devmem_test.c" \
	"$here/snapshot_identity_test.c" \
	"$here/vmmapi_memory_test.c" \
	"$here/snapshot_portable_test.c" \
	"$here/qemu_fwcfg_snapshot_test.c" \
	"$work/"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock.c"        "$work/pci_virtio_vsock.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock_iov.h"    "$work/pci_virtio_vsock_iov.h"
# DTrace USDT probe wrappers: harness builds WITHOUT -DWITH_DTRACE, so the header
# resolves every VSOCK_PROBE_* to a no-op (no <sys/sdt.h>, no DOF needed).
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock_probes.h" "$work/pci_virtio_vsock_probes.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_pci_modern.c" "$work/virtio_pci_modern.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_pci_modern_probes.h" "$work/virtio_pci_modern_probes.h"
ln -s "$srctop/usr.sbin/bhyve/bhyvegc.c" "$work/bhyvegc.c"
ln -s "$srctop/usr.sbin/bhyve/console.c" "$work/console_owner.c"
ln -s "$srctop/usr.sbin/bhyve/mevent.c" "$work/mevent_dut.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_admin_pci.c" "$work/virtio_admin_pci.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_admin_pci.h" "$work/virtio_admin_pci.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_input.c" "$work/pci_virtio_input.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_rnd.c" "$work/pci_virtio_rnd.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_gpu.c" "$work/pci_virtio_gpu.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_console.c" "$work/pci_virtio_console.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_9p.c" "$work/pci_virtio_9p.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_block.c" "$work/pci_virtio_block.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_net.c" "$work/pci_virtio_net.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_scsi.c" "$work/pci_virtio_scsi.c"
ln -s "$srctop/usr.sbin/bhyve/virtio.c" "$work/virtio.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_packed.c" "$work/virtio_packed.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_packed.h" "$work/virtio_packed.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_balloon_host.c" "$work/virtio_balloon_host.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_balloon_host.h" "$work/virtio_balloon_host.h"
ln -s "$srctop/lib/libvmmapi/vmmapi_memory.c" "$work/vmmapi_memory.c"
ln -s "$srctop/lib/libvmmapi/vmmapi_memory.h" "$work/vmmapi_memory.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_balloon.c" "$work/pci_virtio_balloon.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_rtc.c" "$work/pci_virtio_rtc.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_rtc_host.c" "$work/virtio_rtc_host.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_rtc_host.h" "$work/virtio_rtc_host.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_rtc_alarm.c" "$work/virtio_rtc_alarm.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_rtc_alarm.h" "$work/virtio_rtc_alarm.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_host.c" "$work/virtio_pmem_host.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_host.h" "$work/virtio_pmem_host.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_queue.c" "$work/virtio_pmem_queue.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_queue.h" "$work/virtio_pmem_queue.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_async.c" "$work/virtio_pmem_async.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_async.h" "$work/virtio_pmem_async.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_worker.c" "$work/virtio_pmem_worker.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_pmem_worker.h" "$work/virtio_pmem_worker.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_pmem.c" "$work/pci_virtio_pmem.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_host.c" "$work/virtio_fs_host.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_host.h" "$work/virtio_fs_host.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_backend.c" \
	"$work/virtio_fs_backend.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_backend.h" \
	"$work/virtio_fs_backend.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_backend_io.c" \
	"$work/virtio_fs_backend_io.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_backend_io.h" \
	"$work/virtio_fs_backend_io.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_backend_client.c" \
	"$work/virtio_fs_backend_client.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_backend_client.h" \
	"$work/virtio_fs_backend_client.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_connection.c" \
	"$work/virtio_fs_connection.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_connection.h" \
	"$work/virtio_fs_connection.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_pending.c" \
	"$work/virtio_fs_pending.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_pending.h" \
	"$work/virtio_fs_pending.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_state.c" \
	"$work/virtio_fs_state.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_state.h" \
	"$work/virtio_fs_state.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_dispatch.c" \
	"$work/virtio_fs_dispatch.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_dispatch.h" \
	"$work/virtio_fs_dispatch.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_chain.c" \
	"$work/virtio_fs_chain.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_chain.h" \
	"$work/virtio_fs_chain.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_outbox.c" \
	"$work/virtio_fs_outbox.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_outbox.h" \
	"$work/virtio_fs_outbox.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_queue.c" \
	"$work/virtio_fs_queue.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_fs_queue.h" \
	"$work/virtio_fs_queue.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_fs.c" \
	"$work/pci_virtio_fs.c"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd.c" \
	"$work/virtiofsd.c"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_export.c" \
	"$work/virtiofsd_export.c"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_export.h" \
	"$work/virtiofsd_export.h"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_fuse.c" \
	"$work/virtiofsd_fuse.c"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_fuse.h" \
	"$work/virtiofsd_fuse.h"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_handle.c" \
	"$work/virtiofsd_handle.c"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_handle.h" \
	"$work/virtiofsd_handle.h"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_session.c" \
	"$work/virtiofsd_session.c"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_session.h" \
	"$work/virtiofsd_session.h"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_server.c" \
	"$work/virtiofsd_server.c"
ln -s "$srctop/usr.sbin/virtiofsd/virtiofsd_server.h" \
	"$work/virtiofsd_server.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_protocol.c" \
	"$work/virtio_gpu_2d_protocol.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_protocol.h" \
	"$work/virtio_gpu_2d_protocol.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_state.c" \
	"$work/virtio_gpu_2d_state.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_state.h" \
	"$work/virtio_gpu_2d_state.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_queue.c" \
	"$work/virtio_gpu_2d_queue.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_queue.h" \
	"$work/virtio_gpu_2d_queue.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_display.c" \
	"$work/virtio_gpu_2d_display.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_gpu_2d_display.h" \
	"$work/virtio_gpu_2d_display.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_state.c" \
	"$work/virtio_iommu_state.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_state.h" \
	"$work/virtio_iommu_state.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_config.c" \
	"$work/virtio_iommu_config.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_config.h" \
	"$work/virtio_iommu_config.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_protocol.c" \
	"$work/virtio_iommu_protocol.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_protocol.h" \
	"$work/virtio_iommu_protocol.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_request.c" \
	"$work/virtio_iommu_request.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_request.h" \
	"$work/virtio_iommu_request.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_queue.c" \
	"$work/virtio_iommu_queue.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_queue.h" \
	"$work/virtio_iommu_queue.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_event.c" \
	"$work/virtio_iommu_event.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_event.h" \
	"$work/virtio_iommu_event.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_topology.c" \
	"$work/virtio_iommu_topology.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_topology.h" \
	"$work/virtio_iommu_topology.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_viot.c" \
	"$work/virtio_iommu_viot.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_iommu_viot.h" \
	"$work/virtio_iommu_viot.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_iommu.c" \
	"$work/pci_virtio_iommu.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_iommu.h" \
	"$work/pci_virtio_iommu.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_mem_host.c" \
	"$work/virtio_mem_host.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_mem_host.h" \
	"$work/virtio_mem_host.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_mem.c" \
	"$work/pci_virtio_mem.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_snd_host.c" \
	"$work/virtio_snd_host.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_snd_host.h" \
	"$work/virtio_snd_host.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_snd_async.c" \
	"$work/virtio_snd_async.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_snd_async.h" \
	"$work/virtio_snd_async.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_snd_queue.c" \
	"$work/virtio_snd_queue.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_snd_queue.h" \
	"$work/virtio_snd_queue.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_snd.c" \
	"$work/pci_virtio_snd.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_state_range.h" \
	"$work/virtio_state_range.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_dma.h" "$work/virtio_dma.h"
ln -s "$srctop/usr.sbin/bhyve/iov.c" "$work/iov.c"
ln -s "$srctop/usr.sbin/bhyve/iov.h" "$work/iov.h"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_manifest.c" "$work/checkpoint_manifest.c"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_manifest.h" "$work/checkpoint_manifest.h"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_topology.c" "$work/checkpoint_topology.c"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_topology.h" "$work/checkpoint_topology.h"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_numa.c" "$work/checkpoint_numa.c"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_numa.h" "$work/checkpoint_numa.h"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_cpu.c" "$work/checkpoint_cpu.c"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_cpu.h" "$work/checkpoint_cpu.h"
ln -s "$srctop/usr.sbin/bhyve/amd64/checkpoint_cpu_machdep.c" \
	"$work/checkpoint_cpu_machdep.c"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_compat.c" "$work/checkpoint_compat.c"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_compat.h" "$work/checkpoint_compat.h"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_machine.c" "$work/checkpoint_machine.c"
ln -s "$srctop/usr.sbin/bhyve/checkpoint_machine.h" "$work/checkpoint_machine.h"
ln -s "$srctop/usr.sbin/bhyve/snapshot_devmem.c" "$work/snapshot_devmem.c"
ln -s "$srctop/usr.sbin/bhyve/snapshot_devmem.h" "$work/snapshot_devmem.h"
ln -s "$srctop/usr.sbin/bhyve/snapshot_identity.h" "$work/snapshot_identity.h"
ln -s "$srctop/usr.sbin/bhyve/snapshot_portable.h" "$work/snapshot_portable.h"
ln -s "$srctop/usr.sbin/bhyve/snapshot_metadata.h" "$work/snapshot_metadata.h"

mkdir -p "$work/inc/sys"
cp "$srctop/sys/sys/vsock.h" "$work/inc/sys/vsock.h"

# Minimal <atf-c.h> shim: isolate each ATF_TC_BODY like atf-run(1) and report
# aggregate case failures.
mkdir -p "$work/atfshim"
cat > "$work/atfshim/atf-c.h" <<'EOF'
#ifndef ATF_SHIM_H
#define ATF_SHIM_H
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int atf_checks, atf_failed;
#define ATF_TC_WITHOUT_HEAD(n) static void atf_tcbody_##n(void *tc)
#define ATF_TC_BODY(n, tc)     static void atf_tcbody_##n(void *tc)
#define ATF_CHECK(x) do { atf_checks++; if (!(x)) { \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); \
    atf_failed++; } } while (0)
#define ATF_CHECK_EQ(a, b) ATF_CHECK((a) == (b))
#define ATF_CHECK_STREQ(a, b) ATF_CHECK(strcmp((a), (b)) == 0)
#define ATF_CHECK_MSG(x, ...) ATF_CHECK(x)
#define ATF_REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "  ABORT %s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } \
    } while (0)
#define ATF_REQUIRE_EQ(a, b) ATF_REQUIRE((a) == (b))
#define ATF_REQUIRE_STREQ(a, b) ATF_REQUIRE(strcmp((a), (b)) == 0)
#define ATF_REQUIRE_MSG(x, ...) ATF_REQUIRE(x)
/*
 * Opt-in progress is deliberately emitted by the shim rather than baked into
 * individual tests.  It makes a blocked test identifiable in a local,
 * sanitizer-backed harness run without making normal successful runs noisy.
 */
static void
atf_run_case(const char *name, void (*body)(void *))
{
    pid_t child;
    int status;

    if (getenv("ATF_SHIM_TRACE") != NULL)
        fprintf(stderr, "device harness: RUN %s\n", name);
    child = fork();
    if (child == -1)
        abort();
    if (child == 0) {
        atf_checks = 0;
        atf_failed = 0;
        body(NULL);
        _exit(atf_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    if (waitpid(child, &status, 0) != child)
        abort();
    atf_checks++;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  FAIL device harness case %s terminated\n", name);
        atf_failed++;
    }
}
#define ATF_TP_ADD_TC(tp, n) \
    atf_run_case(#n, atf_tcbody_##n)
#define atf_no_error() (fprintf(stderr, \
    "device harness: %d checks, %d failed\n", atf_checks, atf_failed), \
    atf_failed ? 1 : 0)
#define ATF_TP_ADD_TCS(tp) int main(void)
#endif
EOF

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work/inc" \
    -I"$srctop/sys" \
    -o "$work/devtest" "$work/vsock_device_test.c" \
    -Wl,--wrap=socket,--wrap=connectat,--wrap=send,--wrap=recv,--wrap=sendmsg,--wrap=shutdown,--wrap=poll,--wrap=close,--wrap=accept,--wrap=socketpair,--wrap=fcntl,--wrap=setsockopt,--wrap=getsockopt,--wrap=recvmsg,--wrap=ioctl,--wrap=realloc,--wrap=writev \
    -lpthread

"$work/devtest"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-o "$work/modern-test" \
    "$work/virtio_modern_test.c" -lpthread

"$work/modern-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -DWITHOUT_CAPSICUM \
	-I"$work/atfshim" -I"$work/inc" \
    -I"$work" -I"$srctop/sys" -o "$work/input-test" \
    "$work/virtio_input_test.c" -lpthread

"$work/input-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -DWITHOUT_CAPSICUM \
	-I"$work/atfshim" -I"$work/inc" \
    -I"$work" -I"$srctop/sys" -o "$work/rnd-test" \
    "$work/virtio_rnd_test.c" -lpthread

"$work/rnd-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/rnd-interrupt-test" \
	"$work/virtio_rnd_interrupt_test.c" -lpthread

"$work/rnd-interrupt-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/core-test" \
	"$work/virtio_core_test.c" -lpthread

"$work/core-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$srctop/sys" \
	-o "$work/guest-contract-test" \
	"$work/virtio_guest_contract_test.c"

"$work/guest-contract-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-o "$work/host-contract-test" \
	"$work/virtio_host_contract_test.c"

"$work/host-contract-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/packed-model-test" \
	"$work/virtio_packed_model_test.c"

"$work/packed-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/packed-engine-test" \
	"$work/virtio_packed_engine_test.c"

"$work/packed-engine-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/balloon-host-test" \
	"$work/virtio_balloon_host_test.c"

"$work/balloon-host-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-ffunction-sections -fdata-sections -DWITHOUT_CAPSICUM \
	-I"$work/atfshim" -I"$work/inc" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/balloon-test" \
	"$work/virtio_balloon_test.c" -lpthread

"$work/balloon-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/rtc-host-test" "$work/virtio_rtc_host_test.c" -lpthread

"$work/rtc-host-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/pmem-host-test" "$work/virtio_pmem_host_test.c"

"$work/pmem-host-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pmem-queue-test" "$work/virtio_pmem_queue_test.c"
"$work/pmem-queue-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/pmem-async-test" "$work/virtio_pmem_async_test.c" -lpthread

"$work/pmem-async-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/pmem-worker-test" "$work/virtio_pmem_worker_test.c" -lpthread

"$work/pmem-worker-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-ffunction-sections -fdata-sections -DWITHOUT_CAPSICUM \
	-DBHYVE_SNAPSHOT \
	-I"$work/atfshim" -I"$work/inc" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/pmem-pci-test" \
	"$work/virtio_pmem_pci_test.c" "$work/virtio_pmem_host.c" \
	"$work/virtio_pmem_queue.c" "$work/virtio_pmem_async.c" \
	"$work/virtio_pmem_worker.c" -lpthread

"$work/pmem-pci-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/rtc-alarm-test" "$work/virtio_rtc_alarm_test.c" -lpthread

"$work/rtc-alarm-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-ffunction-sections -fdata-sections -DWITHOUT_CAPSICUM \
	-I"$work/atfshim" -I"$work/inc" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/rtc-test" \
	"$work/virtio_rtc_test.c" -lpthread

"$work/rtc-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-host-test" "$work/virtio_fs_host_test.c"

"$work/fs-host-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-backend-test" "$work/virtio_fs_backend_test.c"

"$work/fs-backend-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-backend-io-test" "$work/virtio_fs_backend_io_test.c"

"$work/fs-backend-io-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-backend-client-test" \
	"$work/virtio_fs_backend_client_test.c"

"$work/fs-backend-client-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-connection-test" \
	"$work/virtio_fs_connection_test.c" -lpthread

"$work/fs-connection-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-pending-test" "$work/virtio_fs_pending_test.c" -lpthread

"$work/fs-pending-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-state-test" "$work/virtio_fs_state_test.c"

"$work/fs-state-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-dispatch-test" "$work/virtio_fs_dispatch_test.c" -lpthread

"$work/fs-dispatch-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-chain-test" "$work/virtio_fs_chain_test.c"

"$work/fs-chain-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-outbox-test" "$work/virtio_fs_outbox_test.c" -lpthread

"$work/fs-outbox-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-queue-test" "$work/virtio_fs_queue_test.c" -lpthread

"$work/fs-queue-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-DBHYVE_SNAPSHOT -ffunction-sections -fdata-sections \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/sys" -Wl,--gc-sections \
	-o "$work/fs-pci-test" "$work/virtio_fs_pci_test.c" -lpthread

"$work/fs-pci-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-export-test" "$work/virtio_fs_export_test.c" -lpthread

"$work/fs-export-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-fuse-test" "$work/virtio_fs_fuse_test.c"

"$work/fs-fuse-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-handle-test" "$work/virtio_fs_handle_test.c" -lpthread

"$work/fs-handle-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-session-test" "$work/virtio_fs_session_test.c" -lpthread

"$work/fs-session-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/fs-server-test" "$work/virtio_fs_server_test.c" -lpthread

"$work/fs-server-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/virtiofsd-daemon-test" \
	"$work/virtiofsd_daemon_test.c" -lpthread

"$work/virtiofsd-daemon-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/gpu-2d-protocol-test" \
	"$work/virtio_gpu_2d_protocol_test.c"

"$work/gpu-2d-protocol-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/gpu-2d-state-test" \
	"$work/virtio_gpu_2d_state_test.c" -lpthread

"$work/gpu-2d-state-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/gpu-2d-queue-test" \
	"$work/virtio_gpu_2d_queue_test.c" -lpthread

"$work/gpu-2d-queue-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/gpu-2d-display-test" \
	"$work/virtio_gpu_2d_display_test.c"

"$work/gpu-2d-display-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-ffunction-sections -fdata-sections -DBHYVE_SNAPSHOT \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/sys" -Wl,--gc-sections \
	-o "$work/gpu-2d-pci-test" \
	"$work/virtio_gpu_2d_pci_test.c"

"$work/gpu-2d-pci-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/iommu-config-test" \
	"$work/virtio_iommu_config_test.c" -lpthread

"$work/iommu-config-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-DBHYVE_SNAPSHOT -ffunction-sections -fdata-sections \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/usr.sbin" -I"$srctop/sys" -Wl,--gc-sections \
	-o "$work/iommu-pci-test" \
	"$work/virtio_iommu_pci_test.c" -lpthread

"$work/iommu-pci-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/iommu-state-test" \
	"$work/virtio_iommu_state_test.c" -lpthread

"$work/iommu-state-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/iommu-protocol-test" \
	"$work/virtio_iommu_protocol_test.c"

"$work/iommu-protocol-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/iommu-request-test" \
	"$work/virtio_iommu_request_test.c" -lpthread

"$work/iommu-request-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/iommu-queue-test" \
	"$work/virtio_iommu_queue_test.c" -lpthread

"$work/iommu-queue-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/iommu-event-test" \
	"$work/virtio_iommu_event_test.c" -lpthread

"$work/iommu-event-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/iommu-topology-test" \
	"$work/virtio_iommu_topology_test.c"

"$work/iommu-topology-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/iommu-viot-test" \
	"$work/virtio_iommu_viot_test.c"

"$work/iommu-viot-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/mem-host-test" \
	"$work/virtio_mem_host_test.c" -lpthread

"$work/mem-host-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections \
	-fdata-sections -Wno-cast-align \
	-I"$work/atfshim" -I"$work" -I"$srctop/lib/libvmmapi" \
	-I"$srctop/usr.sbin/bhyve" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/mem-test" \
	"$work/virtio_mem_test.c" -lpthread

"$work/mem-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/snd-async-test" \
	"$work/virtio_snd_async_test.c" -lpthread

"$work/snd-async-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/snd-host-test" \
	"$work/virtio_snd_host_test.c" -lpthread

"$work/snd-host-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/snd-queue-test" \
	"$work/virtio_snd_queue_test.c" -lpthread

"$work/snd-queue-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-ffunction-sections -fdata-sections -DBHYVE_SNAPSHOT -DWITHOUT_CAPSICUM \
	-Wno-cast-align -I"$work/atfshim" -I"$work/inc" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/snd-test" \
	"$work/virtio_snd_test.c" -lpthread

"$work/snd-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/admin-test" \
	"$work/virtio_admin_test.c" -lpthread

"$work/admin-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/sys" -o "$work/admin-pci-test" \
	"$work/virtio_admin_pci_test.c"

"$work/admin-pci-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/admin-capability-test" \
	"$work/virtio_admin_capability_test.c" -lpthread

"$work/admin-capability-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/admin-device-parts-test" \
	"$work/virtio_admin_device_parts_test.c" -lpthread

"$work/admin-device-parts-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/admin-group-test" \
	"$work/virtio_admin_group_test.c" -lpthread

"$work/admin-group-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/admin-resource-test" \
	"$work/virtio_admin_resource_test.c" -lpthread

"$work/admin-resource-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/admin-sriov-test" \
	"$work/virtio_admin_sriov_test.c" -lpthread

"$work/admin-sriov-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/device-parts-test" \
	"$work/virtio_device_parts_test.c"

"$work/device-parts-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/device-parts-handler-test" \
	"$work/virtio_device_parts_handler_test.c" -lpthread

"$work/device-parts-handler-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-DBHYVE_SNAPSHOT -I"$work/atfshim" -I"$srctop/usr.sbin" \
	-I"$srctop/sys" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pci-checkpoint-test" "$work/pci_checkpoint_test.c" -lpthread

"$work/pci-checkpoint-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-DBHYVE_SNAPSHOT -I"$work/atfshim" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" \
	-o "$work/checkpoint-compat-test" "$work/checkpoint_compat_test.c" -lz

"$work/checkpoint-compat-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-DBHYVE_SNAPSHOT -I"$work/atfshim" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" \
	-o "$work/checkpoint-machine-test" "$work/checkpoint_machine_test.c" -lmd

"$work/checkpoint-machine-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/snapshot-identity-test" \
	"$work/snapshot_identity_test.c"

"$work/snapshot-identity-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-ffunction-sections -fdata-sections \
	-I"$work/atfshim" -I"$work/inc" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" -I"$srctop/sys" \
	-Wl,--gc-sections,--wrap=close,--wrap=fsync,--wrap=write \
	-o "$work/snapshot-manifest-test" \
	"$work/snapshot_manifest_test.c" -lmd

"$work/snapshot-manifest-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/checkpoint-topology-test" \
	"$work/checkpoint_topology_test.c"

"$work/checkpoint-topology-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/checkpoint-numa-test" \
	"$work/checkpoint_numa_test.c"

"$work/checkpoint-numa-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/checkpoint-cpu-test" \
	"$work/checkpoint_cpu_test.c"

"$work/checkpoint-cpu-test"

if [ "$(uname -p)" = "amd64" ]; then
	"$cc" -g -O1 -fsanitize="$sanitizers" \
		-I"$work/atfshim" -I"$work" \
		-I"$srctop/sys" \
		-I"$srctop/sys/amd64/include" \
		-I"$srctop/usr.sbin/bhyve" -I"$srctop/usr.sbin/bhyve/amd64" \
		-I"$srctop/lib/libvmmapi" \
		-o "$work/checkpoint-cpu-machdep-test" \
		"$work/checkpoint_cpu_machdep_test.c"

	"$work/checkpoint-cpu-machdep-test"
fi

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/sys" \
	-o "$work/snapshot-devmem-test" \
	"$work/snapshot_devmem_test.c"

"$work/snapshot-devmem-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/vmmapi-memory-test" \
	"$work/vmmapi_memory_test.c"

"$work/vmmapi-memory-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" \
	-o "$work/snapshot-portable-test" \
	"$work/snapshot_portable_test.c"

"$work/snapshot-portable-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/qemu-fwcfg-snapshot-test" \
	"$work/qemu_fwcfg_snapshot_test.c"

"$work/qemu-fwcfg-snapshot-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/sys" \
	-o "$work/iov-test" "$work/iov_test.c"

"$work/iov-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections,--wrap=send,--wrap=realloc -o "$work/console-test" \
	"$work/virtio_console_test.c" -lpthread

"$work/console-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/contrib/lib9p" \
	-I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/9p-test" \
	"$work/virtio_9p_test.c" -lpthread

"$work/9p-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-I"$work/atfshim" -I"$srctop/contrib/lib9p" \
	-Wl,--gc-sections -o "$work/lib9p-fs-path-test" \
	"$work/lib9p_fs_path_test.c" -l9p -lsbuf -lpthread

"$work/lib9p-fs-path-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$srctop/sys" \
	-o "$work/p9-guest-wire-test" \
	"$work/p9_guest_wire_test.c"

"$work/p9-guest-wire-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/block-test" \
	"$work/virtio_block_test.c" -lpthread

"$work/block-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$srctop/sys" \
	-o "$work/block-capacity-test" "$work/virtio_blk_capacity_test.c"

"$work/block-capacity-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections,--wrap=pwrite,--wrap=pwritev -o "$work/block-if-test" \
	"$work/block_if_test.c" -lpthread

"$work/block-if-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" \
	-I"$work" -I"$srctop/usr.sbin/bhyve" \
	-Wl,--gc-sections,--wrap=read,--wrap=write,--wrap=close \
	-o "$work/audio-test" "$work/audio_test.c"

"$work/audio-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/bhyvegc-test" "$work/bhyvegc_test.c"

"$work/bhyvegc-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/usb-mouse-model-test" "$work/usb_mouse_model_test.c"

"$work/usb-mouse-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pci-nvme-model-test" "$work/pci_nvme_model_test.c"

"$work/pci-nvme-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pci-ahci-model-test" "$work/pci_ahci_model_test.c"

"$work/pci-ahci-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pci-e82545-model-test" \
	"$work/pci_e82545_model_test.c"

"$work/pci-e82545-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pci-fbuf-model-test" \
	"$work/pci_fbuf_model_test.c"

"$work/pci-fbuf-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pci-hda-model-test" "$work/pci_hda_model_test.c"

"$work/pci-hda-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pci-xhci-model-test" "$work/pci_xhci_model_test.c"

"$work/pci-xhci-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/uart-backend-model-test" \
	"$work/uart_backend_model_test.c"

"$work/uart-backend-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/console-owner-test" "$work/console_owner_test.c" -lpthread

"$work/console-owner-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -DWITHOUT_CAPSICUM \
	-Wno-thread-safety-analysis -I"$work/atfshim" -I"$work" \
	-I"$srctop/usr.sbin/bhyve" -o "$work/mevent-lifecycle-test" \
	"$work/mevent_lifecycle_test.c" -lpthread

"$work/mevent-lifecycle-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/tpm-intf-crb-model-test" \
	"$work/tpm_intf_crb_model_test.c"

"$work/tpm-intf-crb-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work" -I"$srctop/usr.sbin/bhyve" \
	-o "$work/pvpanic-model-test" "$work/pvpanic_model_test.c"

"$work/pvpanic-model-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/net-test" \
	"$work/virtio_net_test.c" -lpthread

"$work/net-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections -fdata-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin/bhyve" \
	-I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections,--wrap=pthread_mutex_init,--wrap=pthread_cond_init \
	-o "$work/scsi-test" \
	"$work/virtio_scsi_test.c" -lpthread

"$work/scsi-test"

# Keep a terminal marker separate from individual test-program summaries.
# The harness intentionally emits many expected malformed-input diagnostics;
# a caller following a redirected log needs an unambiguous indication that
# every compiler and sanitizer lane reached the end of this script.  Publish
# the durable result before the cosmetic stdout marker: an executor can reap
# the process group immediately after the final test returns, and at that
# point every lane has already succeeded even if stdout is no longer captured.
if [ -n "$result_file" ]; then
	result_tmp="${result_file}.tmp.$$"
	printf '%s\n' 'PASS device harness all tests passed' > "$result_tmp"
	mv -f "$result_tmp" "$result_file"
fi
echo "device harness all tests passed"

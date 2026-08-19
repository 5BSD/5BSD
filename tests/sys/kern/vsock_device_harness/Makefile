# Device-level ATF harness for the bhyve virtio-vsock host device.  It #includes
# the real pci_virtio_vsock.c and shadows its bhyve headers with the mocks in
# this directory; host-socket syscalls are intercepted with ld --wrap.  See
# README.md.  The DUT sources are copied into ${.OBJDIR} so their quote-includes
# resolve to the mocks here (via -I) rather than the real bhyve headers.
#
# Packaged in vsock-tests (not the base tests package) so it can be installed on
# its own.  run.sh runs the device/transport tests under sanitizers without
# ATF.

.include <src.opts.mk>

PACKAGE=	vsock-tests
TESTSDIR=	${TESTSBASE}/sys/kern/vsock_device_harness
SCRIPTSDIR=	${TESTSDIR}

ATF_TESTS_C+=	vsock_device_test
ATF_TESTS_C+=	virtio_modern_test
ATF_TESTS_C+=	virtio_input_test
ATF_TESTS_C+=	virtio_rnd_test
ATF_TESTS_C+=	virtio_rnd_interrupt_test
ATF_TESTS_C+=	virtio_core_test
ATF_TESTS_C+=	iov_test
ATF_TESTS_C+=	virtio_console_test
ATF_TESTS_C+=	virtio_9p_test
ATF_TESTS_C+=	virtio_block_test
ATF_TESTS_C+=	virtio_blk_capacity_test
ATF_TESTS_C+=	block_if_test
ATF_TESTS_C+=	audio_test
ATF_TESTS_C+=	bhyvegc_test
ATF_TESTS_C+=	usb_mouse_model_test
ATF_TESTS_C+=	pci_nvme_model_test
ATF_TESTS_C+=	pci_ahci_model_test
ATF_TESTS_C+=	pci_e82545_model_test
ATF_TESTS_C+=	pci_fbuf_model_test
ATF_TESTS_C+=	pci_hda_model_test
ATF_TESTS_C+=	pci_xhci_model_test
ATF_TESTS_C+=	uart_backend_model_test
ATF_TESTS_C+=	console_owner_test
ATF_TESTS_C+=	mevent_lifecycle_test
ATF_TESTS_C+=	tpm_intf_crb_model_test
ATF_TESTS_C+=	pvpanic_model_test
ATF_TESTS_C+=	migration_dirty_test
ATF_TESTS_C+=	migration_precopy_test
ATF_TESTS_C+=	migration_session_test
ATF_TESTS_C+=	vmmapi_dirty_log_test
ATF_TESTS_C+=	virtio_net_test
ATF_TESTS_C+=	virtio_scsi_test
ATF_TESTS_C+=	scmi_virtio_poll_test
ATF_TESTS_C+=	virtio_guest_contract_test
ATF_TESTS_C+=	virtio_host_contract_test
ATF_TESTS_C+=	virtio_packed_model_test
ATF_TESTS_C+=	virtio_packed_engine_test
ATF_TESTS_C+=	virtio_balloon_host_test
ATF_TESTS_C+=	virtio_balloon_test
ATF_TESTS_C+=	checkpoint_topology_test
ATF_TESTS_C+=	checkpoint_numa_test
ATF_TESTS_C+=	checkpoint_cpu_test
ATF_TESTS_C+=	snapshot_identity_test
ATF_TESTS_C+=	pci_checkpoint_test
.if ${MACHINE_ARCH} == "amd64"
ATF_TESTS_C+=	checkpoint_cpu_machdep_test
ATF_TESTS_C+=	vmm_cpu_contract_abi_test
ATF_TESTS_C+=	x86_cpuid_topology_test
.endif
ATF_TESTS_C+=	checkpoint_compat_test
ATF_TESTS_C+=	checkpoint_machine_test
ATF_TESTS_C+=	virtio_rtc_host_test
ATF_TESTS_C+=	virtio_rtc_test
ATF_TESTS_C+=	virtio_rtc_alarm_test
ATF_TESTS_C+=	virtio_pmem_host_test
ATF_TESTS_C+=	virtio_pmem_queue_test
ATF_TESTS_C+=	virtio_pmem_async_test
ATF_TESTS_C+=	virtio_pmem_worker_test
ATF_TESTS_C+=	virtio_pmem_pci_test
ATF_TESTS_C+=	virtio_fs_host_test
ATF_TESTS_C+=	virtio_fs_backend_test
ATF_TESTS_C+=	virtio_fs_backend_io_test
ATF_TESTS_C+=	virtio_fs_backend_client_test
ATF_TESTS_C+=	virtio_fs_connection_test
ATF_TESTS_C+=	virtio_fs_pending_test
ATF_TESTS_C+=	virtio_fs_state_test
ATF_TESTS_C+=	virtio_fs_dispatch_test
ATF_TESTS_C+=	virtio_fs_chain_test
ATF_TESTS_C+=	virtio_fs_outbox_test
ATF_TESTS_C+=	virtio_fs_queue_test
ATF_TESTS_C+=	virtio_fs_pci_test
ATF_TESTS_C+=	virtio_fs_export_test
ATF_TESTS_C+=	virtio_fs_fuse_test
ATF_TESTS_C+=	virtio_fs_handle_test
ATF_TESTS_C+=	virtio_fs_session_test
ATF_TESTS_C+=	virtio_fs_server_test
ATF_TESTS_C+=	virtiofsd_daemon_test
ATF_TESTS_C+=	virtio_gpu_2d_protocol_test
ATF_TESTS_C+=	virtio_gpu_2d_state_test
ATF_TESTS_C+=	virtio_gpu_2d_queue_test
ATF_TESTS_C+=	virtio_gpu_2d_display_test
ATF_TESTS_C+=	virtio_gpu_2d_pci_test
ATF_TESTS_C+=	virtio_scsi_event_test
ATF_TESTS_C+=	virtio_iommu_config_test
ATF_TESTS_C+=	virtio_iommu_pci_test
ATF_TESTS_C+=	virtio_iommu_state_test
ATF_TESTS_C+=	virtio_iommu_protocol_test
ATF_TESTS_C+=	virtio_iommu_request_test
ATF_TESTS_C+=	virtio_iommu_queue_test
ATF_TESTS_C+=	virtio_iommu_event_test
ATF_TESTS_C+=	virtio_iommu_topology_test
ATF_TESTS_C+=	virtio_iommu_viot_test
ATF_TESTS_C+=	virtio_mem_host_test
ATF_TESTS_C+=	virtio_mem_test
ATF_TESTS_C+=	virtio_snd_async_test
ATF_TESTS_C+=	virtio_snd_host_test
ATF_TESTS_C+=	virtio_snd_queue_test
ATF_TESTS_C+=	virtio_snd_test
ATF_TESTS_C+=	virtio_admin_test
ATF_TESTS_C+=	virtio_admin_pci_test
ATF_TESTS_C+=	virtio_admin_capability_test
ATF_TESTS_C+=	virtio_admin_device_parts_test
ATF_TESTS_C+=	virtio_admin_group_test
ATF_TESTS_C+=	virtio_admin_resource_test
ATF_TESTS_C+=	virtio_admin_sriov_test
ATF_TESTS_C+=	virtio_device_parts_test
ATF_TESTS_C+=	virtio_device_parts_handler_test
ATF_TESTS_C+=	snapshot_manifest_test
ATF_TESTS_C+=	snapshot_portable_test
ATF_TESTS_C+=	qemu_fwcfg_snapshot_test
ATF_TESTS_C+=	snapshot_devmem_test
ATF_TESTS_C+=	vmmapi_memory_test
ATF_TESTS_C+=	lib9p_tversion_test
ATF_TESTS_C+=	lib9p_name_test
ATF_TESTS_C+=	lib9p_fs_path_test
ATF_TESTS_C+=	lib9p_threadpool_test
ATF_TESTS_C+=	lib9p_marshal_test
ATF_TESTS_C+=	lib9p_dispatch_test
ATF_TESTS_C+=	p9_guest_wire_test
ATF_TESTS_SH+=	virtio_requirements_test
SCRIPTS+=	validate-waspnest-completion-matrix.sh
SCRIPTSNAME_validate-waspnest-completion-matrix.sh= \
	validate-waspnest-completion-matrix.sh
SCRIPTS+=	validate-virtio-requirements.sh
SCRIPTSNAME_validate-virtio-requirements.sh=	validate-virtio-requirements.sh
SCRIPTS+=	validate-virtio-nonstandard-interfaces.sh
SCRIPTSNAME_validate-virtio-nonstandard-interfaces.sh= \
	validate-virtio-nonstandard-interfaces.sh
SCRIPTS+=	validate-virtio-reference-corpus.sh
SCRIPTSNAME_validate-virtio-reference-corpus.sh= \
	validate-virtio-reference-corpus.sh
SCRIPTS+=	validate-virtio-snapshot-portability.sh
SCRIPTSNAME_validate-virtio-snapshot-portability.sh= \
	validate-virtio-snapshot-portability.sh
SCRIPTS+=	validate-virtio-snapshot-portability-selftest.sh
SCRIPTSNAME_validate-virtio-snapshot-portability-selftest.sh= \
	validate-virtio-snapshot-portability-selftest.sh
SCRIPTS+=	validate-virtio-snapshot-runner-selftest.sh
SCRIPTSNAME_validate-virtio-snapshot-runner-selftest.sh= \
	validate-virtio-snapshot-runner-selftest.sh
SCRIPTS+=	validate-virtio-dma-boundary.sh
SCRIPTSNAME_validate-virtio-dma-boundary.sh= \
	validate-virtio-dma-boundary.sh
SCRIPTS+=	validate-virtio-dtrace.sh
SCRIPTSNAME_validate-virtio-dtrace.sh=	validate-virtio-dtrace.sh
SCRIPTS+=	validate-sanitizer-parity.sh
SCRIPTSNAME_validate-sanitizer-parity.sh=	validate-sanitizer-parity.sh
SCRIPTS+=	run.sh
SCRIPTSNAME_run.sh=	run.sh
SCRIPTS+=	run-snapshot-model.sh
SCRIPTSNAME_run-snapshot-model.sh=	run-snapshot-model.sh
SCRIPTS+=	validate-bhyve-build-modes.sh
SCRIPTSNAME_validate-bhyve-build-modes.sh=	validate-bhyve-build-modes.sh
VIRTIO_VALIDATION_FILES=	virtio-1.4-requirements.tsv \
				virtio-feature-activation.tsv \
				virtio-nonstandard-interfaces.tsv \
				virtio-reference-corpus.tsv \
				virtio.h \
				validate-bhyve-build-modes.sh \
				VIRTIO_1_4_FULL_REVIEW_PROMPT.md \
				bhyve_virtio_compat.h \
				virtio_1_4_spec.h \
				virtio_1_4_wire.h \
				iov_test.c \
				virtio_9p_test.c \
				virtio_block_test.c \
				virtio_blk_capacity_test.c \
				block_if_test.c \
				audio_test.c \
				bhyvegc_test.c \
				usb_mouse_model_test.c \
				pci_nvme_model_test.c \
				pci_ahci_model_test.c \
				pci_e82545_model_test.c \
				pci_fbuf_model_test.c \
				pci_hda_model_test.c \
				pci_xhci_model_test.c \
				uart_backend_model_test.c \
				console_owner_test.c \
				mevent_lifecycle_test.c \
				tpm_intf_crb_model_test.c \
				pvpanic_model_test.c \
				virtio_console_test.c \
				virtio_core_test.c \
				virtio_guest_contract_test.c \
				virtio_host_contract_test.c \
				virtio_input_test.c \
				virtio_modern_test.c \
				virtio_net_test.c \
				virtio_packed_model_test.c \
				virtio_packed_engine_test.c \
				virtio_balloon_host_test.c \
				virtio_balloon_test.c \
				virtio_rtc_host_test.c \
				virtio_rtc_test.c \
				virtio_rtc_alarm_test.c \
				virtio_pmem_host_test.c \
				virtio_pmem_queue_test.c \
				virtio_pmem_async_test.c \
				virtio_pmem_worker_test.c \
				virtio_pmem_pci_test.c \
				virtio_fs_host_test.c \
				virtio_fs_backend_test.c \
				virtio_fs_backend_io_test.c \
				virtio_fs_backend_client_test.c \
				virtio_fs_connection_test.c \
				virtio_fs_pending_test.c \
				virtio_fs_state_test.c \
				virtio_fs_dispatch_test.c \
				virtio_fs_chain_test.c \
				virtio_fs_outbox_test.c \
				virtio_fs_queue_test.c \
				virtio_fs_pci_test.c \
				virtio_fs_fuse_test.c \
				virtio_fs_handle_test.c \
				virtio_fs_session_test.c \
				virtio_fs_server_test.c \
				virtiofsd_daemon_test.c \
				virtio_gpu_2d_protocol_test.c \
				virtio_gpu_2d_state_test.c \
				virtio_gpu_2d_queue_test.c \
				virtio_fs_export_test.c \
				virtio_gpu_2d_display_test.c \
				virtio_gpu_2d_pci_test.c \
				virtio_scsi_event_test.c \
				virtio_iommu_config_test.c \
				virtio_iommu_pci_test.c \
				virtio_iommu_state_test.c \
				virtio_iommu_protocol_test.c \
				virtio_iommu_request_test.c \
				virtio_iommu_queue_test.c \
				virtio_iommu_event_test.c \
				virtio_iommu_topology_test.c \
				virtio_iommu_viot_test.c \
				virtio_mem_host_test.c \
				virtio_mem_test.c \
				virtio_snd_async_test.c \
				virtio_snd_host_test.c \
				virtio_snd_queue_test.c \
				virtio_snd_test.c \
				virtio_admin_test.c \
				virtio_admin_pci_test.c \
				virtio_admin_capability_test.c \
				virtio_admin_device_parts_test.c \
				virtio_admin_group_test.c \
				virtio_admin_resource_test.c \
				virtio_admin_sriov_test.c \
				virtio_device_parts_test.c \
				virtio_device_parts_handler_test.c \
				checkpoint_compat_test.c \
				checkpoint_machine_test.c \
				pci_checkpoint_test.c \
				virtio_rnd_interrupt_test.c \
				virtio_rnd_test.c \
				virtio_scsi_test.c \
				scmi_virtio_poll_test.c \
				vsock_device_test.c
SANITIZER_HARNESS_FILES=	bhyverun.h \
				block_if.h \
				checkpoint_compat.c \
				checkpoint_compat.h \
				checkpoint_machine.c \
				checkpoint_machine.h \
				checkpoint_topology_test.c \
				checkpoint_numa_test.c \
				checkpoint_cpu_test.c \
				checkpoint_cpu_machdep_test.c \
				snapshot_identity_test.c \
				vmm_cpu_contract_abi_test.c \
				x86_cpuid_topology_test.c \
				config.h \
				debug.h \
				mevent.h \
				net_backends.h \
				net_utils.h \
				pci_emul.h \
				snapshot.h \
				snapshot_identity.h \
				sockstream.h \
				virtio_config_read_test_support.h \
				virtio_dma.h \
				snapshot_manifest_test.c \
				snapshot_devmem_test.c \
				vmmapi_memory_test.c \
				snapshot_portable_test.c \
				qemu_fwcfg_snapshot_test.c
VIRTIO_VALIDATION_FILES+=	lib9p_tversion_test.c lib9p_name_test.c \
				lib9p_fs_path_test.c p9_guest_wire_test.c \
				lib9p_marshal_test.c lib9p_dispatch_test.c \
				vmmapi_dirty_log_test.c
VIRTIO_REQUIREMENTS_COMPANION_FILES=	Makefile run.sh \
				run-snapshot-model.sh \
				validate-virtio-snapshot-runner-selftest.sh
${PACKAGE}FILES+=	${VIRTIO_VALIDATION_FILES} ${SANITIZER_HARNESS_FILES} \
			DEEP_REVIEW_PROMPT.md Makefile
CFLAGS.vsock_device_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_modern_test+=	-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin \
				-I${SRCTOP}/sys
CFLAGS.virtio_packed_model_test+= -I${.CURDIR} -I${.OBJDIR}
CFLAGS.usb_mouse_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pci_nvme_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pci_ahci_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pci_e82545_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pci_fbuf_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pci_hda_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pci_xhci_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.uart_backend_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pvpanic_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_packed_engine_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_balloon_host_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.checkpoint_topology_test+= -I${.CURDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.snapshot_identity_test+= -I${.CURDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.pci_checkpoint_test+= -DBHYVE_SNAPSHOT -I${SRCTOP}/usr.sbin
CFLAGS.checkpoint_numa_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.checkpoint_cpu_test+= -I${.CURDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.checkpoint_cpu_machdep_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys \
				-I${SRCTOP}/sys/amd64/include \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin/bhyve/amd64 \
				-I${SRCTOP}/lib/libvmmapi
CFLAGS.vmm_cpu_contract_abi_test+= -I${.CURDIR} \
				-I${SRCTOP}/sys
CFLAGS.checkpoint_compat_test+= -DBHYVE_SNAPSHOT -I${.CURDIR} \
				-I${.OBJDIR} -I${SRCTOP}/usr.sbin/bhyve
LIBADD.checkpoint_compat_test+= z
CFLAGS.checkpoint_machine_test+= -DBHYVE_SNAPSHOT -I${.CURDIR} \
				-I${.OBJDIR} -I${SRCTOP}/usr.sbin/bhyve
LIBADD.checkpoint_machine_test+= md
CFLAGS.snapshot_manifest_test+= -I${.OBJDIR}
CFLAGS.qemu_fwcfg_snapshot_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.vmmapi_memory_test+= -I${.OBJDIR}
LDFLAGS.snapshot_manifest_test+= -Wl,--wrap=close -Wl,--wrap=fsync -Wl,--wrap=write
LIBADD.snapshot_manifest_test+= md
CFLAGS.virtio_balloon_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_rtc_host_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/sys
CFLAGS.virtio_rtc_test+=	-DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_rtc_alarm_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/sys
CFLAGS.virtio_pmem_host_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.virtio_pmem_queue_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_pmem_async_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_pmem_worker_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_pmem_pci_test+= -DWITHOUT_CAPSICUM -DBHYVE_SNAPSHOT \
				-ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CWARNFLAGS.virtio_pmem_pci_test.c+= -Wno-thread-safety-analysis
SRCS.virtio_pmem_pci_test=	virtio_pmem_pci_test.c \
				virtio_pmem_host.c virtio_pmem_queue.c \
				virtio_pmem_async.c virtio_pmem_worker.c
LIBADD.virtio_pmem_pci_test+= pthread
CFLAGS.virtio_fs_host_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_backend_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_backend_io_test+= -I${.CURDIR} -I${.OBJDIR} \
				    -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_backend_client_test+= -I${.CURDIR} -I${.OBJDIR} \
					-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_connection_test+= -I${.CURDIR} -I${.OBJDIR} \
				    -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_pending_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_state_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_dispatch_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_chain_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_outbox_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_queue_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_pci_test+= -DBHYVE_SNAPSHOT -ffunction-sections -fdata-sections \
	-Wno-error=cast-align \
	-I${.CURDIR} -I${.OBJDIR} -I${SRCTOP}/usr.sbin/bhyve \
	-I${SRCTOP}/sys
CFLAGS.virtio_gpu_2d_protocol_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_gpu_2d_state_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_gpu_2d_queue_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_gpu_2d_display_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_gpu_2d_pci_test+= -DBHYVE_SNAPSHOT -ffunction-sections \
	-Wno-error=cast-align -I${.CURDIR} \
	-I${.OBJDIR} -I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.console_owner_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
LIBADD.console_owner_test+= pthread
CFLAGS.bhyvegc_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_scsi_event_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_iommu_config_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.virtio_iommu_pci_test+= -ffunction-sections -fdata-sections \
	-DBHYVE_SNAPSHOT -Wno-error=cast-align -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_iommu_state_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.virtio_iommu_protocol_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_iommu_request_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.virtio_iommu_queue_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.virtio_iommu_event_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.virtio_iommu_topology_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_iommu_viot_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_mem_host_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_snd_async_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_fs_export_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/virtiofsd
CFLAGS.virtio_fs_fuse_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/virtiofsd
CFLAGS.virtio_fs_handle_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/virtiofsd
CFLAGS.virtio_fs_session_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/virtiofsd
CFLAGS.virtio_fs_server_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin/virtiofsd
CFLAGS.virtiofsd_daemon_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin/virtiofsd
CFLAGS.virtio_snd_host_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_snd_queue_test+= -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_snd_test+= -DBHYVE_SNAPSHOT -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -Wno-cast-align \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_mem_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
	-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/lib/libvmmapi -I${SRCTOP}/usr.sbin/bhyve \
	-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_admin_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_admin_pci_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve -I${SRCTOP}/sys
CFLAGS.virtio_admin_capability_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_admin_device_parts_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_admin_group_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_admin_resource_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_admin_sriov_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_device_parts_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_device_parts_handler_test+= -I${.CURDIR} -I${.OBJDIR} \
	-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.virtio_input_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_rnd_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.scmi_virtio_poll_test+= -I${SRCTOP}/sys
CFLAGS.virtio_rnd_interrupt_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin \
				-I${SRCTOP}/sys
CFLAGS.virtio_core_test+=	-DWITHOUT_CAPSICUM -ffunction-sections \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin \
				-I${SRCTOP}/sys
CFLAGS.iov_test+=		-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_console_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_9p_test+=	-DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/contrib/lib9p \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_block_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_blk_capacity_test+= -I${SRCTOP}/sys
CFLAGS.block_if_test+=	-DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.audio_test+=	-DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} \
				-I${SRCTOP}/usr.sbin/bhyve
CFLAGS.mevent_lifecycle_test+= -DWITHOUT_CAPSICUM -I${.CURDIR} \
				-I${.OBJDIR} -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.tpm_intf_crb_model_test+= -I${SRCTOP}/usr.sbin/bhyve
CWARNFLAGS.mevent_lifecycle_test.c+= -Wno-thread-safety-analysis
CFLAGS.virtio_net_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_scsi_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_guest_contract_test+= -I${SRCTOP}/sys
CFLAGS.virtio_host_contract_test+= -I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.snapshot_portable_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.snapshot_devmem_test+= -I${SRCTOP}/usr.sbin/bhyve
CFLAGS.lib9p_tversion_test+= -I${SRCTOP}/contrib/lib9p
# lib9p_request.c is shared by more than one prog (Tversion and dispatch
# tests).  Pin its include path to the source itself so it resolves lib9p.h
# regardless of which prog first triggers its compilation.
CFLAGS.lib9p_request.c+= -I${SRCTOP}/contrib/lib9p
# The boundary test exercises the in-tree Tversion dispatcher.  Do not let a
# pre-existing installed lib9p.a silently substitute an older implementation
# when the device harness is built without a full world install.
SRCS.lib9p_tversion_test= lib9p_tversion_test.c lib9p_request.c
LIBADD.lib9p_tversion_test+= 9p sbuf pthread
CFLAGS.lib9p_name_test+= -I${SRCTOP}/contrib/lib9p
LIBADD.lib9p_name_test+= 9p sbuf pthread
CFLAGS.lib9p_fs_path_test+= -ffunction-sections -fdata-sections \
				-I${SRCTOP}/contrib/lib9p
LDFLAGS.lib9p_fs_path_test+= -Wl,--gc-sections
CFLAGS.lib9p_threadpool_test+= -I${SRCTOP}/contrib/lib9p
LIBADD.lib9p_threadpool_test+= 9p sbuf pthread
# Marshalling round-trip tests drive the in-tree pack.c through the public
# entry points.  pack.c is compiled locally (as request.c is for the Tversion
# and dispatch tests) so a stale installed lib9p.a cannot mask a marshalling
# regression; -l9p is still needed for l9p_logf and sbuf.
CFLAGS.lib9p_marshal_test+= -I${SRCTOP}/contrib/lib9p
CFLAGS.lib9p_pack.c+= -I${SRCTOP}/contrib/lib9p
SRCS.lib9p_marshal_test= lib9p_marshal_test.c lib9p_pack.c
LIBADD.lib9p_marshal_test+= 9p sbuf pthread
# The dispatch tests exercise the in-tree request.c (compiled locally, as for
# lib9p_tversion_test) so an older installed lib9p.a cannot be substituted.
CFLAGS.lib9p_dispatch_test+= -I${SRCTOP}/contrib/lib9p
SRCS.lib9p_dispatch_test= lib9p_dispatch_test.c lib9p_request.c
LIBADD.lib9p_dispatch_test+= 9p sbuf pthread
CFLAGS.p9_guest_wire_test+= -I${SRCTOP}/sys
.if ${MK_CASPER} != "no"
LIBADD.lib9p_tversion_test+= casper cap_pwd cap_grp
LIBADD.lib9p_marshal_test+= casper cap_pwd cap_grp
LIBADD.lib9p_dispatch_test+= casper cap_pwd cap_grp
LIBADD.lib9p_name_test+= casper cap_pwd cap_grp
LIBADD.lib9p_threadpool_test+= casper cap_pwd cap_grp
.endif
# The mock-included device source and the ld --wrap interceptors (non-static so
# the linker binds them, tripping -Wmissing-prototypes) warn; keep non-fatal.
# Must be CWARNFLAGS.<src> (appended after -Werror) -- CFLAGS.<prog> is emitted
# before -Werror and would have no effect.
CWARNFLAGS.vsock_device_test.c+=	-Wno-error
CWARNFLAGS.virtio_modern_test.c+=	-Wno-cast-align \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_input_test.c+=	-Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_rnd_test.c+=	-Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_rnd_interrupt_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_core_test.c+=	-Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_console_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_9p_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_block_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.block_if_test.c+=	-Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.audio_test.c+=	-Wno-error
CWARNFLAGS.virtio_net_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_scsi_test.c+= -Wno-error \
						-Wno-thread-safety-analysis
CWARNFLAGS.virtio_balloon_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_rtc_test.c+=	-Wno-cast-align \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_mem_test.c+=	-Wno-cast-align
CWARNFLAGS.virtio_snd_test.c+=	-Wno-cast-align
CWARNFLAGS.virtio_host_contract_test.c+= -Wno-cast-align
LDFLAGS.vsock_device_test+=	-Wl,--wrap=socket -Wl,--wrap=connectat \
	-Wl,--wrap=send -Wl,--wrap=recv -Wl,--wrap=sendmsg -Wl,--wrap=shutdown \
	-Wl,--wrap=poll -Wl,--wrap=close -Wl,--wrap=accept \
	-Wl,--wrap=socketpair -Wl,--wrap=fcntl -Wl,--wrap=setsockopt \
	-Wl,--wrap=getsockopt -Wl,--wrap=recvmsg -Wl,--wrap=ioctl \
	-Wl,--wrap=realloc -Wl,--wrap=writev
LDFLAGS.virtio_core_test+=	-Wl,--gc-sections
LDFLAGS.virtio_rnd_interrupt_test+= -Wl,--gc-sections
LDFLAGS.virtio_console_test+= -Wl,--gc-sections -Wl,--wrap=send \
				-Wl,--wrap=realloc
LDFLAGS.virtio_9p_test+=	-Wl,--gc-sections
LDFLAGS.virtio_block_test+=	-Wl,--gc-sections
LDFLAGS.block_if_test+=		-Wl,--gc-sections -Wl,--wrap=pwrite -Wl,--wrap=pwritev
LDFLAGS.audio_test+=		-Wl,--gc-sections -Wl,--wrap=read \
				-Wl,--wrap=write -Wl,--wrap=close
LDFLAGS.virtio_net_test+=	-Wl,--gc-sections
LDFLAGS.virtio_scsi_test+=	-Wl,--gc-sections \
	-Wl,--wrap=pthread_mutex_init -Wl,--wrap=pthread_cond_init
LDFLAGS.virtio_balloon_test+=	-Wl,--gc-sections
LDFLAGS.virtio_rtc_test+=	-Wl,--gc-sections
LDFLAGS.virtio_gpu_2d_pci_test+= -Wl,--gc-sections
LIBADD.virtio_gpu_2d_pci_test+=	pthread
LDFLAGS.virtio_iommu_pci_test+= -Wl,--gc-sections
LDFLAGS.virtio_fs_pci_test+= -Wl,--gc-sections
LDFLAGS.virtio_mem_test+=	-Wl,--gc-sections
LDFLAGS.virtio_snd_test+=	-Wl,--gc-sections
LIBADD.vsock_device_test+=	pthread
LIBADD.virtio_modern_test+=	pthread
LIBADD.virtio_input_test+=	pthread
LIBADD.virtio_rnd_test+=	pthread
LIBADD.virtio_rnd_interrupt_test+= pthread
LIBADD.virtio_core_test+=	pthread
LIBADD.migration_dirty_test+=	pthread
CFLAGS.migration_dirty_test+=	-I${SRCTOP}/sys
LIBADD.migration_precopy_test+=	pthread
CFLAGS.migration_precopy_test+=	-I${SRCTOP}/lib/libvmmapi -I${SRCTOP}/sys \
				-I${SRCTOP}/sys/${MACHINE}/include
LIBADD.migration_session_test+=	pthread z
CFLAGS.vmmapi_dirty_log_test+=	-I${SRCTOP}/lib/libvmmapi -I${SRCTOP}/sys \
				-I${SRCTOP}/sys/${MACHINE}/include
LIBADD.virtio_console_test+= pthread
LIBADD.virtio_9p_test+=	pthread
LIBADD.virtio_block_test+=	pthread
LIBADD.block_if_test+=		pthread
LIBADD.mevent_lifecycle_test+=	pthread
LIBADD.virtio_net_test+=	pthread
LIBADD.virtio_scsi_test+=	pthread
LIBADD.virtio_balloon_test+=	pthread
LIBADD.virtio_rtc_test+=	pthread
LIBADD.virtio_rtc_host_test+= pthread
LIBADD.virtio_rtc_alarm_test+= pthread
LIBADD.virtio_pmem_async_test+= pthread
LIBADD.virtio_pmem_worker_test+= pthread
LIBADD.virtio_fs_pending_test+=	pthread
LIBADD.virtio_fs_backend_client_test+=	pthread
LIBADD.virtio_fs_connection_test+=	pthread
LIBADD.virtio_fs_dispatch_test+=	pthread
LIBADD.virtio_fs_outbox_test+=	pthread
LIBADD.virtio_fs_queue_test+=	pthread
LIBADD.virtio_fs_pci_test+=	pthread
LIBADD.virtio_fs_export_test+=	pthread
LIBADD.virtio_fs_handle_test+=	pthread
LIBADD.virtio_fs_session_test+=	pthread
LIBADD.virtio_fs_server_test+=	pthread
LIBADD.virtiofsd_daemon_test+=	pthread
LIBADD.virtio_gpu_2d_state_test+=	pthread
LIBADD.virtio_gpu_2d_queue_test+=	pthread
LIBADD.virtio_iommu_config_test+=	pthread
LIBADD.virtio_iommu_pci_test+=	pthread
LIBADD.virtio_iommu_state_test+=	pthread
LIBADD.virtio_iommu_request_test+=	pthread
LIBADD.virtio_iommu_queue_test+=	pthread
LIBADD.virtio_iommu_event_test+=	pthread
LIBADD.virtio_mem_host_test+=	pthread
LIBADD.virtio_mem_test+=	pthread
LIBADD.virtio_snd_async_test+=	pthread
LIBADD.virtio_snd_host_test+=	pthread
LIBADD.virtio_snd_queue_test+=	pthread
LIBADD.virtio_snd_test+=	pthread
LIBADD.virtio_admin_test+=	pthread
LIBADD.virtio_admin_capability_test+=	pthread
LIBADD.virtio_admin_device_parts_test+=	pthread
LIBADD.virtio_admin_group_test+=	pthread
LIBADD.virtio_admin_resource_test+=	pthread
LIBADD.virtio_admin_sriov_test+=	pthread
LIBADD.virtio_device_parts_handler_test+=	pthread
CLEANFILES+=	pci_virtio_vsock.c pci_virtio_vsock_iov.h \
		pci_virtio_vsock_probes.h virtio_pci_modern.c \
		virtio_pci_modern_probes.h pci_virtio_input.c pci_virtio_rnd.c \
		pci_virtio_console.c pci_virtio_9p.c pci_virtio_block.c \
		pci_virtio_net.c pci_virtio_scsi.c pci_virtio_balloon.c \
		pci_virtio_rtc.c \
		pci_virtio_gpu.c \
		virtio.c virtio_balloon_host.c virtio_balloon_host.h iov.c iov.h
CLEANFILES+=	virtio_rtc_host.c virtio_rtc_host.h
CLEANFILES+=	virtio_rtc_alarm.c virtio_rtc_alarm.h
CLEANFILES+=	virtio_pmem_host.c virtio_pmem_host.h
CLEANFILES+=	virtio_pmem_queue.c virtio_pmem_queue.h
CLEANFILES+=	virtio_pmem_async.c virtio_pmem_async.h
CLEANFILES+=	virtio_pmem_worker.c virtio_pmem_worker.h
CLEANFILES+=	pci_virtio_pmem.c
CLEANFILES+=	virtio_admin_pci.h
CLEANFILES+=	virtio_admin_pci.c
CLEANFILES+=	virtio_fs_host.c virtio_fs_host.h
CLEANFILES+=	virtio_fs_backend.c virtio_fs_backend.h
CLEANFILES+=	virtio_fs_backend_io.c virtio_fs_backend_io.h
CLEANFILES+=	virtio_fs_backend_client.c virtio_fs_backend_client.h
CLEANFILES+=	virtio_fs_connection.c virtio_fs_connection.h
CLEANFILES+=	virtio_fs_pending.c virtio_fs_pending.h
CLEANFILES+=	virtio_fs_state.c virtio_fs_state.h
CLEANFILES+=	virtio_fs_dispatch.c virtio_fs_dispatch.h
CLEANFILES+=	virtio_fs_chain.c virtio_fs_chain.h
CLEANFILES+=	virtio_fs_outbox.c virtio_fs_outbox.h
CLEANFILES+=	virtio_fs_queue.c virtio_fs_queue.h
CLEANFILES+=	pci_virtio_fs.c
CLEANFILES+=	virtio_gpu_2d_protocol.c virtio_gpu_2d_protocol.h
CLEANFILES+=	console_owner.c
CLEANFILES+=	bhyvegc.c
CLEANFILES+=	virtio_gpu_2d_state.c virtio_gpu_2d_state.h
CLEANFILES+=	virtio_gpu_2d_queue.c virtio_gpu_2d_queue.h
CLEANFILES+=	virtio_gpu_2d_display.c virtio_gpu_2d_display.h
CLEANFILES+=	virtio_scsi_event.c virtio_scsi_event.h
CLEANFILES+=	pci_virtio_iommu.c virtio_iommu_config.c \
		virtio_iommu_config.h
CLEANFILES+=	virtio_iommu_state.c virtio_iommu_state.h
CLEANFILES+=	virtio_iommu_protocol.c virtio_iommu_protocol.h
CLEANFILES+=	virtio_iommu_request.c virtio_iommu_request.h
CLEANFILES+=	virtio_iommu_queue.c virtio_iommu_queue.h
CLEANFILES+=	virtio_iommu_event.c virtio_iommu_event.h
CLEANFILES+=	virtio_iommu_topology.c virtio_iommu_topology.h
CLEANFILES+=	virtio_iommu_viot.c virtio_iommu_viot.h
CLEANFILES+=	virtio_mem_host.c virtio_mem_host.h pci_virtio_mem.c
CLEANFILES+=	virtio_snd_async.c virtio_snd_async.h \
		virtio_snd_host.c virtio_snd_host.h \
		virtio_snd_queue.c virtio_snd_queue.h pci_virtio_snd.c
CLEANFILES+=	virtio_state_range.h
CLEANFILES+=	virtio_dma.h
CLEANFILES+=	checkpoint_manifest.c checkpoint_manifest.h
CLEANFILES+=	checkpoint_numa.c checkpoint_numa.h
CLEANFILES+=	snapshot_identity.h
CLEANFILES+=	vmmapi_memory.c vmmapi_memory.h
CLEANFILES+=	mevent_dut.c

# Several bsd.test.mk recursive program builds share one object directory.
# Publish copied inputs atomically so parallel builds cannot observe a file
# while another recursive make is truncating and replacing it.
_COPY_ATOMIC=	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID} && \
		mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}

# Copy the DUT sources into ${.OBJDIR} at beforedepend (not as an .o prerequisite:
# ATF builds a PIE object, so an .o-only prerequisite never fires and a stale
# copy would be compiled).  Re-copies whenever the bhyve sources change.
beforedepend:	pci_virtio_vsock.c pci_virtio_vsock_iov.h \
		pci_virtio_vsock_probes.h virtio_pci_modern.c \
		virtio_pci_modern_probes.h pci_virtio_input.c pci_virtio_rnd.c \
		pci_virtio_console.c pci_virtio_9p.c pci_virtio_block.c \
		pci_virtio_net.c pci_virtio_scsi.c virtio.c iov.c iov.h
beforedepend:	pci_virtio_balloon.c virtio_balloon_host.c \
		virtio_balloon_host.h
beforedepend:	pci_virtio_rtc.c virtio_rtc_host.c virtio_rtc_host.h
beforedepend:	virtio_rtc_alarm.c virtio_rtc_alarm.h
beforedepend:	virtio_pmem_host.c virtio_pmem_host.h
beforedepend:	virtio_pmem_queue.c virtio_pmem_queue.h
beforedepend:	virtio_pmem_async.c virtio_pmem_async.h
beforedepend:	virtio_pmem_worker.c virtio_pmem_worker.h
beforedepend:	pci_virtio_pmem.c
beforedepend:	virtio_admin_pci.c virtio_admin_pci.h
beforedepend:	pci_virtio_gpu.c
beforedepend:	console_owner.c
beforedepend:	bhyvegc.c
beforedepend:	virtio_fs_host.c virtio_fs_host.h
beforedepend:	virtio_fs_backend.c virtio_fs_backend.h
beforedepend:	virtio_fs_backend_io.c virtio_fs_backend_io.h
beforedepend:	virtio_fs_backend_client.c virtio_fs_backend_client.h
beforedepend:	virtio_fs_connection.c virtio_fs_connection.h
beforedepend:	virtio_fs_pending.c virtio_fs_pending.h
beforedepend:	virtio_fs_state.c virtio_fs_state.h
beforedepend:	virtio_fs_dispatch.c virtio_fs_dispatch.h
beforedepend:	virtio_fs_chain.c virtio_fs_chain.h
beforedepend:	virtio_fs_outbox.c virtio_fs_outbox.h
beforedepend:	virtio_fs_queue.c virtio_fs_queue.h
beforedepend:	pci_virtio_fs.c
beforedepend:	virtio_gpu_2d_protocol.c virtio_gpu_2d_protocol.h
beforedepend:	virtio_gpu_2d_state.c virtio_gpu_2d_state.h
beforedepend:	virtio_gpu_2d_queue.c virtio_gpu_2d_queue.h
beforedepend:	virtio_gpu_2d_display.c virtio_gpu_2d_display.h
beforedepend:	virtio_scsi_event.c virtio_scsi_event.h
beforedepend:	pci_virtio_iommu.c virtio_iommu_config.c \
		virtio_iommu_config.h
beforedepend:	virtio_iommu_state.c virtio_iommu_state.h
beforedepend:	virtio_iommu_protocol.c virtio_iommu_protocol.h
beforedepend:	virtio_iommu_request.c virtio_iommu_request.h
beforedepend:	virtio_iommu_queue.c virtio_iommu_queue.h
beforedepend:	virtio_iommu_event.c virtio_iommu_event.h
beforedepend:	virtio_iommu_topology.c virtio_iommu_topology.h
beforedepend:	virtio_iommu_viot.c virtio_iommu_viot.h
beforedepend:	virtio_mem_host.c virtio_mem_host.h pci_virtio_mem.c
beforedepend:	virtio_snd_async.c virtio_snd_async.h \
		virtio_snd_host.c virtio_snd_host.h \
		virtio_snd_queue.c virtio_snd_queue.h pci_virtio_snd.c
beforedepend:	virtio_state_range.h
beforedepend:	virtio_dma.h
beforedepend:	checkpoint_manifest.c checkpoint_manifest.h
beforedepend:	checkpoint_numa.c checkpoint_numa.h
beforedepend:	snapshot_identity.h
beforedepend:	vmmapi_memory.c vmmapi_memory.h
beforedepend:	mevent_dut.c
pci_virtio_vsock.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock.c
	${_COPY_ATOMIC}
mevent_dut.c:	${SRCTOP}/usr.sbin/bhyve/mevent.c
	${_COPY_ATOMIC}
pci_virtio_gpu.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_gpu.c
	${_COPY_ATOMIC}
console_owner.c:	${SRCTOP}/usr.sbin/bhyve/console.c
	${_COPY_ATOMIC}
bhyvegc.c:	${SRCTOP}/usr.sbin/bhyve/bhyvegc.c
	${_COPY_ATOMIC}
pci_virtio_vsock_iov.h:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock_iov.h
	${_COPY_ATOMIC}
# No -DWITH_DTRACE here, so every VSOCK_PROBE_* resolves to a no-op.
pci_virtio_vsock_probes.h:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock_probes.h
	${_COPY_ATOMIC}
virtio_pci_modern.c:	${SRCTOP}/usr.sbin/bhyve/virtio_pci_modern.c
	${_COPY_ATOMIC}
virtio_pci_modern_probes.h: ${SRCTOP}/usr.sbin/bhyve/virtio_pci_modern_probes.h
	${_COPY_ATOMIC}
virtio_admin_pci.h: ${SRCTOP}/usr.sbin/bhyve/virtio_admin_pci.h
	${_COPY_ATOMIC}
virtio_admin_pci.c: ${SRCTOP}/usr.sbin/bhyve/virtio_admin_pci.c
	${_COPY_ATOMIC}
virtio_modern_test: virtio_admin_pci.h
virtio_admin_pci_test: virtio_admin_pci.c
pci_virtio_input.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_input.c
	${_COPY_ATOMIC}
pci_virtio_rnd.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_rnd.c
	${_COPY_ATOMIC}
pci_virtio_console.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_console.c
	${_COPY_ATOMIC}
pci_virtio_9p.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_9p.c
	${_COPY_ATOMIC}
pci_virtio_block.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_block.c
	${_COPY_ATOMIC}
pci_virtio_net.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_net.c
	${_COPY_ATOMIC}
pci_virtio_scsi.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_scsi.c
	${_COPY_ATOMIC}
virtio.c:	${SRCTOP}/usr.sbin/bhyve/virtio.c
	${_COPY_ATOMIC}
checkpoint_manifest.c: ${SRCTOP}/usr.sbin/bhyve/checkpoint_manifest.c
	${_COPY_ATOMIC}
checkpoint_manifest.h: ${SRCTOP}/usr.sbin/bhyve/checkpoint_manifest.h
	${_COPY_ATOMIC}
checkpoint_numa.c: ${SRCTOP}/usr.sbin/bhyve/checkpoint_numa.c
	${_COPY_ATOMIC}
checkpoint_numa.h: ${SRCTOP}/usr.sbin/bhyve/checkpoint_numa.h
	${_COPY_ATOMIC}
snapshot_identity.h: ${SRCTOP}/usr.sbin/bhyve/snapshot_identity.h
	${_COPY_ATOMIC}
vmmapi_memory.c: ${SRCTOP}/lib/libvmmapi/vmmapi_memory.c
	${_COPY_ATOMIC}
vmmapi_memory.h: ${SRCTOP}/lib/libvmmapi/vmmapi_memory.h
	${_COPY_ATOMIC}
virtio_balloon_host.c: ${SRCTOP}/usr.sbin/bhyve/virtio_balloon_host.c
	${_COPY_ATOMIC}
pci_virtio_balloon.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_balloon.c
	${_COPY_ATOMIC}
pci_virtio_rtc.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_rtc.c
	${_COPY_ATOMIC}
virtio_balloon_host.h: ${SRCTOP}/usr.sbin/bhyve/virtio_balloon_host.h
	${_COPY_ATOMIC}
virtio_rtc_host.c: ${SRCTOP}/usr.sbin/bhyve/virtio_rtc_host.c
	${_COPY_ATOMIC}
virtio_rtc_host.h: ${SRCTOP}/usr.sbin/bhyve/virtio_rtc_host.h
	${_COPY_ATOMIC}
virtio_rtc_alarm.c: ${SRCTOP}/usr.sbin/bhyve/virtio_rtc_alarm.c
	${_COPY_ATOMIC}
virtio_rtc_alarm.h: ${SRCTOP}/usr.sbin/bhyve/virtio_rtc_alarm.h
	${_COPY_ATOMIC}
virtio_pmem_host.c: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_host.c
	${_COPY_ATOMIC}
virtio_pmem_host.h: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_host.h
	${_COPY_ATOMIC}
virtio_pmem_queue.c: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_queue.c
	${_COPY_ATOMIC}
virtio_pmem_queue.h: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_queue.h
	${_COPY_ATOMIC}
virtio_pmem_async.c: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_async.c
	${_COPY_ATOMIC}
virtio_pmem_async.h: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_async.h
	${_COPY_ATOMIC}
virtio_pmem_worker.c: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_worker.c
	${_COPY_ATOMIC}
virtio_pmem_worker.h: ${SRCTOP}/usr.sbin/bhyve/virtio_pmem_worker.h
	${_COPY_ATOMIC}
pci_virtio_pmem.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_pmem.c
	${_COPY_ATOMIC}
virtio_fs_host.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_host.c
	${_COPY_ATOMIC}
virtio_fs_host.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_host.h
	${_COPY_ATOMIC}
virtio_fs_backend.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_backend.c
	${_COPY_ATOMIC}
virtio_fs_backend.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_backend.h
	${_COPY_ATOMIC}
virtio_fs_backend_io.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_backend_io.c
	${_COPY_ATOMIC}
virtio_fs_backend_io.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_backend_io.h
	${_COPY_ATOMIC}
virtio_fs_backend_client.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_backend_client.c
	${_COPY_ATOMIC}
virtio_fs_backend_client.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_backend_client.h
	${_COPY_ATOMIC}
virtio_fs_connection.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_connection.c
	${_COPY_ATOMIC}
virtio_fs_connection.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_connection.h
	${_COPY_ATOMIC}
virtio_fs_pending.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_pending.c
	${_COPY_ATOMIC}
virtio_fs_pending.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_pending.h
	${_COPY_ATOMIC}
virtio_fs_state.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_state.c
	${_COPY_ATOMIC}
virtio_fs_state.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_state.h
	${_COPY_ATOMIC}
virtio_fs_dispatch.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_dispatch.c
	${_COPY_ATOMIC}
virtio_fs_dispatch.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_dispatch.h
	${_COPY_ATOMIC}
virtio_fs_chain.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_chain.c
	${_COPY_ATOMIC}
virtio_fs_chain.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_chain.h
	${_COPY_ATOMIC}
virtio_fs_outbox.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_outbox.c
	${_COPY_ATOMIC}
virtio_fs_outbox.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_outbox.h
	${_COPY_ATOMIC}
virtio_fs_queue.c: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_queue.c
	${_COPY_ATOMIC}
virtio_fs_queue.h: ${SRCTOP}/usr.sbin/bhyve/virtio_fs_queue.h
	${_COPY_ATOMIC}
pci_virtio_fs.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_fs.c
	${_COPY_ATOMIC}
virtio_gpu_2d_protocol.c: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_protocol.c
	${_COPY_ATOMIC}
virtio_gpu_2d_protocol.h: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_protocol.h
	${_COPY_ATOMIC}
virtio_gpu_2d_state.c: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_state.c
	${_COPY_ATOMIC}
virtio_gpu_2d_state.h: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_state.h
	${_COPY_ATOMIC}
virtio_gpu_2d_queue.c: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_queue.c
	${_COPY_ATOMIC}
virtio_gpu_2d_queue.h: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_queue.h
	${_COPY_ATOMIC}
virtio_gpu_2d_display.c: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_display.c
	${_COPY_ATOMIC}
virtio_gpu_2d_display.h: ${SRCTOP}/usr.sbin/bhyve/virtio_gpu_2d_display.h
	${_COPY_ATOMIC}
virtio_scsi_event.c: ${SRCTOP}/usr.sbin/bhyve/virtio_scsi_event.c
	${_COPY_ATOMIC}
virtio_scsi_event.h: ${SRCTOP}/usr.sbin/bhyve/virtio_scsi_event.h
	${_COPY_ATOMIC}
virtio_iommu_config.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_config.c
	${_COPY_ATOMIC}
virtio_iommu_config.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_config.h
	${_COPY_ATOMIC}
pci_virtio_iommu.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_iommu.c
	${_COPY_ATOMIC}
virtio_iommu_state.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_state.c
	${_COPY_ATOMIC}
virtio_iommu_state.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_state.h
	${_COPY_ATOMIC}
virtio_iommu_protocol.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_protocol.c
	${_COPY_ATOMIC}
virtio_iommu_protocol.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_protocol.h
	${_COPY_ATOMIC}
virtio_iommu_request.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_request.c
	${_COPY_ATOMIC}
virtio_iommu_request.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_request.h
	${_COPY_ATOMIC}
virtio_iommu_queue.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_queue.c
	${_COPY_ATOMIC}
virtio_iommu_queue.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_queue.h
	${_COPY_ATOMIC}
virtio_iommu_event.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_event.c
	${_COPY_ATOMIC}
virtio_iommu_event.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_event.h
	${_COPY_ATOMIC}
virtio_iommu_topology.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_topology.c
	${_COPY_ATOMIC}
virtio_iommu_topology.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_topology.h
	${_COPY_ATOMIC}
virtio_iommu_viot.c: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_viot.c
	${_COPY_ATOMIC}
virtio_iommu_viot.h: ${SRCTOP}/usr.sbin/bhyve/virtio_iommu_viot.h
	${_COPY_ATOMIC}
virtio_mem_host.c: ${SRCTOP}/usr.sbin/bhyve/virtio_mem_host.c
	${_COPY_ATOMIC}
virtio_mem_host.h: ${SRCTOP}/usr.sbin/bhyve/virtio_mem_host.h
	${_COPY_ATOMIC}
virtio_snd_async.c: ${SRCTOP}/usr.sbin/bhyve/virtio_snd_async.c
	${_COPY_ATOMIC}
virtio_snd_async.h: ${SRCTOP}/usr.sbin/bhyve/virtio_snd_async.h
	${_COPY_ATOMIC}
virtio_snd_host.c: ${SRCTOP}/usr.sbin/bhyve/virtio_snd_host.c
	${_COPY_ATOMIC}
virtio_snd_host.h: ${SRCTOP}/usr.sbin/bhyve/virtio_snd_host.h
	${_COPY_ATOMIC}
virtio_snd_queue.c: ${SRCTOP}/usr.sbin/bhyve/virtio_snd_queue.c
	${_COPY_ATOMIC}
virtio_snd_queue.h: ${SRCTOP}/usr.sbin/bhyve/virtio_snd_queue.h
	${_COPY_ATOMIC}
pci_virtio_snd.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_snd.c
	${_COPY_ATOMIC}
virtio_state_range.h: ${SRCTOP}/usr.sbin/bhyve/virtio_state_range.h
	${_COPY_ATOMIC}
pci_virtio_mem.c: ${SRCTOP}/usr.sbin/bhyve/pci_virtio_mem.c
	${_COPY_ATOMIC}
virtio_dma.h: ${SRCTOP}/usr.sbin/bhyve/virtio_dma.h
	${_COPY_ATOMIC}
checkpoint_compat.c: ${SRCTOP}/usr.sbin/bhyve/checkpoint_compat.c
	${_COPY_ATOMIC}
checkpoint_compat.h: ${SRCTOP}/usr.sbin/bhyve/checkpoint_compat.h
	${_COPY_ATOMIC}
checkpoint_machine.c: ${SRCTOP}/usr.sbin/bhyve/checkpoint_machine.c
	${_COPY_ATOMIC}
checkpoint_machine.h: ${SRCTOP}/usr.sbin/bhyve/checkpoint_machine.h
	${_COPY_ATOMIC}
iov.c:		${SRCTOP}/usr.sbin/bhyve/iov.c
	${_COPY_ATOMIC}
iov.h:		${SRCTOP}/usr.sbin/bhyve/iov.h
	${_COPY_ATOMIC}

# The shell ATF program resolves companion files through atf_get_srcdir().
# Supply them in a separate object directory, but never make source-tree
# files cleanable when .OBJDIR and .CURDIR are the same.
.if ${.OBJDIR} != ${.CURDIR}
CLEANFILES+=	validate-waspnest-completion-matrix.sh \
		validate-virtio-requirements.sh \
		validate-virtio-nonstandard-interfaces.sh \
		validate-virtio-reference-corpus.sh DEEP_REVIEW_PROMPT.md \
		lib9p_request.c lib9p_pack.c ${VIRTIO_VALIDATION_FILES} \
		${VIRTIO_REQUIREMENTS_COMPANION_FILES}
beforedepend:	validate-waspnest-completion-matrix.sh \
		validate-virtio-requirements.sh \
		validate-virtio-nonstandard-interfaces.sh \
		validate-virtio-reference-corpus.sh DEEP_REVIEW_PROMPT.md \
		lib9p_request.c lib9p_pack.c ${VIRTIO_VALIDATION_FILES} \
		${VIRTIO_REQUIREMENTS_COMPANION_FILES}
validate-waspnest-completion-matrix.sh: \
    ${.CURDIR}/validate-waspnest-completion-matrix.sh
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	chmod 555 ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
validate-virtio-requirements.sh: ${.CURDIR}/validate-virtio-requirements.sh
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	chmod 555 ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
validate-virtio-nonstandard-interfaces.sh: \
    ${.CURDIR}/validate-virtio-nonstandard-interfaces.sh
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	chmod 555 ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
validate-virtio-reference-corpus.sh: \
    ${.CURDIR}/validate-virtio-reference-corpus.sh
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	chmod 555 ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
lib9p_request.c: ${SRCTOP}/contrib/lib9p/request.c
	${_COPY_ATOMIC}
lib9p_pack.c: ${SRCTOP}/contrib/lib9p/pack.c
	${_COPY_ATOMIC}
DEEP_REVIEW_PROMPT.md: ${.CURDIR}/../vsock_e2e/DEEP_REVIEW_PROMPT.md
	${_COPY_ATOMIC}
.for _validation_file in ${VIRTIO_VALIDATION_FILES} ${VIRTIO_REQUIREMENTS_COMPANION_FILES}
${_validation_file}: ${.CURDIR}/${_validation_file}
	${_COPY_ATOMIC}
.endfor

.endif

.include <bsd.test.mk>

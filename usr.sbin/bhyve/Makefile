#
#

.include <src.opts.mk>

# bhyve is the underlying hypervisor engine and keeps its name.  The "waspnest"
# name belongs to the VM capability daemon (system.Waspnest, usr.sbin/waspnest),
# not to this engine binary.
PROG=	bhyve
PACKAGE=	bhyve

MAN=	bhyve.8 bhyve_config.5

BHYVE_SYSDIR?=${SRCTOP}

.PATH:	${.CURDIR}/${MACHINE_CPUARCH}	\
	${SRCTOP}/sys/libkern		\
	${SRCTOP}/sys/cam/ctl

SRCS=	\
	acpi.c			\
	acpi_device.c		\
	audio.c			\
	basl.c			\
	bhyvegc.c		\
	bhyverun.c		\
	bhyverun_machdep.c	\
	block_if.c		\
	bootrom.c		\
	config.c		\
	console.c		\
	crc16.c			\
	ctl_nvme_all.c		\
	ctl_scsi_all.c		\
	ctl_util.c		\
	hda_codec.c		\
	iov.c			\
	mem.c			\
	migration_dirty.c	\
	migration_precopy.c	\
	migration_session.c	\
	mevent.c		\
	net_backend_netmap.c	\
	net_backend_slirp.c	\
	net_backends.c		\
	net_utils.c		\
	pci_ahci.c		\
	pci_e82545.c		\
	pci_emul.c		\
	pci_hda.c		\
	pci_hostbridge.c	\
	pci_i6300esb.c		\
	pci_irq.c		\
	pci_nvme.c		\
	pci_uart.c		\
	pci_virtio_9p.c		\
	pci_virtio_balloon.c	\
	pci_virtio_block.c	\
	pci_virtio_console.c	\
	pci_virtio_crypto.c	\
	pci_virtio_fs.c		\
	pci_virtio_gpu.c	\
	pci_virtio_input.c	\
	pci_virtio_iommu.c	\
	pci_virtio_mem.c	\
	pci_virtio_pmem.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_virtio_rtc.c	\
	pci_virtio_vsock.c	\
	pci_virtio_scsi.c	\
	pci_virtio_snd.c	\
	pci_xhci.c		\
	qemu_fwcfg.c		\
	qemu_loader.c		\
	smbiostbl.c		\
	sockstream.c		\
	tpm_device.c		\
	tpm_emul_passthru.c	\
	tpm_emul_swtpm.c	\
	tpm_intf_crb.c		\
	tpm_ppi_qemu.c		\
	uart_backend.c		\
	uart_emul.c		\
	usb_emul.c		\
	usb_mouse.c		\
	virtio.c		\
	virtio_admin.c		\
	virtio_admin_capability.c \
	virtio_admin_device_parts.c \
	virtio_admin_group.c	\
	virtio_admin_queue.c	\
	virtio_admin_pci.c	\
	virtio_admin_resource.c	\
	virtio_admin_sriov.c	\
	virtio_balloon_host.c	\
	virtio_device_parts.c	\
	virtio_device_parts_handler.c \
	virtio_fs_backend.c	\
	virtio_fs_backend_client.c \
	virtio_fs_backend_io.c	\
	virtio_fs_chain.c	\
	virtio_fs_connection.c	\
	virtio_fs_dispatch.c	\
	virtio_fs_host.c	\
	virtio_fs_outbox.c	\
	virtio_fs_pending.c	\
	virtio_fs_queue.c	\
	virtio_fs_state.c	\
	virtio_gpu_2d_display.c	\
	virtio_gpu_2d_protocol.c \
	virtio_gpu_2d_queue.c	\
	virtio_gpu_2d_state.c	\
	virtio_scsi_event.c	\
	virtio_iommu_config.c	\
	virtio_iommu_state.c	\
	virtio_iommu_protocol.c	\
	virtio_iommu_request.c	\
	virtio_iommu_queue.c	\
	virtio_iommu_event.c	\
	virtio_iommu_topology.c	\
	virtio_iommu_viot.c	\
	virtio_mem_host.c	\
	virtio_packed.c		\
	virtio_pci_modern.c	\
	virtio_pmem_async.c	\
	virtio_pmem_host.c	\
	virtio_pmem_queue.c	\
	virtio_pmem_worker.c	\
	virtio_rtc_host.c	\
	virtio_rtc_alarm.c	\
	virtio_snd_async.c	\
	virtio_snd_host.c	\
	virtio_snd_queue.c	\
	vmexit.c		\
	vmgenc.c

.if ${MK_BHYVE_SNAPSHOT} != "no"
.PATH:	${.CURDIR}/${MACHINE_CPUARCH}
SRCS+=	checkpoint_compat.c checkpoint_machine.c checkpoint_cpu.c checkpoint_cpu_machdep.c \
	checkpoint_manifest.c checkpoint_numa.c \
	checkpoint_topology.c \
	snapshot.c snapshot_devmem.c

.endif

.include "${MACHINE_CPUARCH}/Makefile.inc"

SUBDIR+= slirp

.if defined(BHYVE_FDT_SUPPORT)
LIBADD+= fdt
CFLAGS+= -I${SRCTOP}/sys/contrib/libfdt
.endif

.if defined(BHYVE_GDB_SUPPORT)
SRCS+=	gdb.c
CFLAGS+= -DBHYVE_GDB
.ifdef GDB_LOG
CFLAGS+=-DGDB_LOG
.endif
SUBDIR+= gdb
.endif

CFLAGS+=-I${.CURDIR}		\
	-I${.CURDIR}/../../contrib/lib9p \
	-I${SRCTOP}/lib/libvmmapi	\
	-I${SRCTOP}/sys

LIBADD+= vmmapi md nv uvmem pthread rt z util sbuf cam 9p

.if ${MK_BHYVE_SNAPSHOT} != "no"
LIBADD+= ucl xo
.endif

.if ${MK_INET_SUPPORT} != "no"
CFLAGS+=-DINET
.endif
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DINET6
.endif
.if ${MK_NETGRAPH_SUPPORT} != "no"
SRCS+=	net_backend_netgraph.c
LIBADD+=	netgraph
.endif
.if ${MK_OPENSSL} == "no"
CFLAGS+=-DNO_OPENSSL
.else
LIBADD+=	crypto
CFLAGS+=-DOPENSSL_API_COMPAT=0x10100000L
.endif

CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/e1000
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/mii
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/usb/controller
.if ${MK_BHYVE_SNAPSHOT} != "no"
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
CFLAGS+= -DBHYVE_SNAPSHOT
.endif

# Disable thread safety analysis since it only finds very simple bugs and
# yields many false positives.
NO_WTHREAD_SAFETY=

NO_WCAST_ALIGN=

# DTrace USDT provider for the virtio-vsock host device (pci_virtio_vsock.c).
# Adding the .d to SRCS makes the build run dtrace -h (generate the probe
# header) and dtrace -G (emit the DOF linked into bhyve).  -I${.OBJDIR} lets the
# source find the generated header; -DWITH_DTRACE arms the probe macros.
.if ${MK_DTRACE} != "no"
SRCS+=		vsock_provider.d
CFLAGS+=	-I${.OBJDIR}
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.prog.mk>

#
# bsd.prog.mk does not encode CFLAGS in an object's dependency graph.  That is
# normally harmless, but snapshot support changes both the preprocessor view
# of most bhyve sources and the set of objects linked into bhyve.  Reusing one
# object directory while toggling MK_BHYVE_SNAPSHOT could therefore link
# snapshot-enabled objects without snapshot.c (or the inverse).  Keep a small
# mode stamp as an explicit prerequisite of every object so a mode transition
# rebuilds the common objects before the link.
#
BHYVE_SNAPSHOT_MODE_FILE=${.OBJDIR}/.bhyve_snapshot_mode
BHYVE_SNAPSHOT_MODE=${MK_BHYVE_SNAPSHOT}

.PHONY: bhyve_snapshot_mode_force
bhyve_snapshot_mode_force:

${BHYVE_SNAPSHOT_MODE_FILE}: bhyve_snapshot_mode_force
	# A mode change changes the CPP view of common sources.  Do not rely on
	# the mode-stamp mtime alone: a no->yes build can occur within the
	# filesystem timestamp granularity and otherwise reuse a non-snapshot
	# virtio.pieo at the snapshot-enabled link.  All ordinary objects wait for
	# this target, so invalidating this private object set here is serialized
	# before any of them are rebuilt.
	@if test -r ${.TARGET} && \
	    test "`cat ${.TARGET}`" = "${BHYVE_SNAPSHOT_MODE}"; then \
		:; \
	else \
		rm -f ${OBJS} ${PROG}.full; \
		printf '%s\\n' "${BHYVE_SNAPSHOT_MODE}" >${.TARGET}.tmp && \
		mv ${.TARGET}.tmp ${.TARGET}; \
	fi

# DTrace's generated provider object consumes its prerequisites as ELF input;
# a mode stamp must not be appended to that command line.  The provider will
# still rebuild after the PIE objects below change.
.for _bhyve_object in ${OBJS:N*.o}
${_bhyve_object}: ${BHYVE_SNAPSHOT_MODE_FILE}
.endfor

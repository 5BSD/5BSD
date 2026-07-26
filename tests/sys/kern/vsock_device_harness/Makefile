# Device-level ATF harness for the bhyve virtio-vsock host device.  It #includes
# the real pci_virtio_vsock.c and shadows its bhyve headers with the mocks in
# this directory; host-socket syscalls are intercepted with ld --wrap.  See
# README.md.  The DUT sources are copied into ${.OBJDIR} so their quote-includes
# resolve to the mocks here (via -I) rather than the real bhyve headers.
#
# Packaged in vsock-tests (not the base tests package) so it can be installed on
# its own.  run.sh runs the device/transport tests under sanitizers without
# ATF.

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
ATF_TESTS_C+=	block_if_test
ATF_TESTS_C+=	virtio_net_test
ATF_TESTS_C+=	virtio_scsi_test
ATF_TESTS_C+=	virtio_guest_contract_test
ATF_TESTS_C+=	virtio_host_contract_test
ATF_TESTS_SH+=	virtio_requirements_test
SCRIPTS+=	validate-virtio-requirements.sh
SCRIPTSNAME_validate-virtio-requirements.sh=	validate-virtio-requirements.sh
SCRIPTS+=	run.sh
SCRIPTSNAME_run.sh=	run.sh
VIRTIO_VALIDATION_FILES=	virtio-1.4-requirements.tsv \
				bhyve_virtio_compat.h \
				virtio_1_4_spec.h \
				virtio_1_4_wire.h \
				iov_test.c \
				virtio_9p_test.c \
				virtio_block_test.c \
				block_if_test.c \
				virtio_console_test.c \
				virtio_core_test.c \
				virtio_guest_contract_test.c \
				virtio_host_contract_test.c \
				virtio_input_test.c \
				virtio_modern_test.c \
				virtio_net_test.c \
				virtio_rnd_interrupt_test.c \
				virtio_rnd_test.c \
				virtio_scsi_test.c \
				vsock_device_test.c
SANITIZER_HARNESS_FILES=	bhyverun.h \
				block_if.h \
				config.h \
				debug.h \
				mevent.h \
				net_backends.h \
				net_utils.h \
				pci_emul.h \
				sockstream.h \
				virtio.h \
				pci_checkpoint_test.c \
				snapshot_manifest_test.c
${PACKAGE}FILES+=	${VIRTIO_VALIDATION_FILES} ${SANITIZER_HARNESS_FILES}
CFLAGS.vsock_device_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_modern_test+=	-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin \
				-I${SRCTOP}/sys
CFLAGS.virtio_input_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_rnd_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
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
CFLAGS.block_if_test+=	-DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_net_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_scsi_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-fdata-sections -I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin/bhyve \
				-I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
CFLAGS.virtio_guest_contract_test+= -I${SRCTOP}/sys
CFLAGS.virtio_host_contract_test+= -I${SRCTOP}/usr.sbin -I${SRCTOP}/sys
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
CWARNFLAGS.virtio_net_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_scsi_test.c+= -Wno-error \
						-Wno-thread-safety-analysis
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
LDFLAGS.block_if_test+=		-Wl,--gc-sections -Wl,--wrap=pwrite
LDFLAGS.virtio_net_test+=	-Wl,--gc-sections
LDFLAGS.virtio_scsi_test+=	-Wl,--gc-sections \
	-Wl,--wrap=pthread_mutex_init -Wl,--wrap=pthread_cond_init
LIBADD.vsock_device_test+=	pthread
LIBADD.virtio_modern_test+=	pthread
LIBADD.virtio_input_test+=	pthread
LIBADD.virtio_rnd_test+=	pthread
LIBADD.virtio_rnd_interrupt_test+= pthread
LIBADD.virtio_core_test+=	pthread
LIBADD.virtio_console_test+= pthread
LIBADD.virtio_9p_test+=	pthread
LIBADD.virtio_block_test+=	pthread
LIBADD.virtio_net_test+=	pthread
LIBADD.virtio_scsi_test+=	pthread
CLEANFILES+=	pci_virtio_vsock.c pci_virtio_vsock_iov.h \
		pci_virtio_vsock_probes.h virtio_pci_modern.c \
		virtio_pci_modern_probes.h pci_virtio_input.c pci_virtio_rnd.c \
		pci_virtio_console.c pci_virtio_9p.c pci_virtio_block.c \
		pci_virtio_net.c pci_virtio_scsi.c virtio.c iov.c iov.h

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
pci_virtio_vsock.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock.c
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
iov.c:		${SRCTOP}/usr.sbin/bhyve/iov.c
	${_COPY_ATOMIC}
iov.h:		${SRCTOP}/usr.sbin/bhyve/iov.h
	${_COPY_ATOMIC}

# The shell ATF program resolves companion files through atf_get_srcdir().
# Supply them in a separate object directory, but never make source-tree
# files cleanable when .OBJDIR and .CURDIR are the same.
.if ${.OBJDIR} != ${.CURDIR}
CLEANFILES+=	validate-virtio-requirements.sh ${VIRTIO_VALIDATION_FILES}
beforedepend:	validate-virtio-requirements.sh ${VIRTIO_VALIDATION_FILES}
validate-virtio-requirements.sh: ${.CURDIR}/validate-virtio-requirements.sh
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	chmod 555 ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
.for _validation_file in ${VIRTIO_VALIDATION_FILES}
${_validation_file}: ${.CURDIR}/${_validation_file}
	${_COPY_ATOMIC}
.endfor
.endif

.include <bsd.test.mk>

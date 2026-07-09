.include <src.opts.mk>

PACKAGE=	tests

TESTSRC=	${SRCTOP}/contrib/netbsd-tests/kernel
.PATH:		${SRCTOP}/sys/kern

TESTSDIR=	${TESTSBASE}/sys/kern

CFLAGS+=	-I${SRCTOP}/tests

ATF_TESTS_C+=	basic_signal
ATF_TESTS_C+=	cap_confinement_test
ATF_TESTS_C+=	cap_xfer_test
ATF_TESTS_C+=	copy_file_range
.if ${MACHINE_ARCH} != "i386" && ${MACHINE_ARCH} != "powerpc"
# No support for atomic_load_64 on i386 or (32-bit) powerpc
ATF_TESTS_C+=	kcov
.endif
ATF_TESTS_C+=	kern_copyin
ATF_TESTS_C+=	kern_descrip_test
# One test modifies the maxfiles limit, which can cause spurious test failures.
TEST_METADATA.kern_descrip_test+= is_exclusive="true"
PLAIN_TESTS_C+=	execve_overflow
ATF_TESTS_C+=	exterr_test
ATF_TESTS_C+=	fdgrowtable_test
ATF_TESTS_C+=	getdirentries_test
ATF_TESTS_C+=	jail_lookup_root
ATF_TESTS_C+=	jaildesc
ATF_TESTS_C+=	inotify_test
ATF_TESTS_C+=	jaildesc_cap_test
ATF_TESTS_C+=	kill_zombie
.if ${MK_OPENSSL} != "no"
ATF_TESTS_C+=	ktls_test
ATF_TESTS_C+=	ssl_sendfile
.endif
ATF_TESTS_C+=	ktrace_test
ATF_TESTS_C+=	listener_wakeup
ATF_TESTS_C+=	module_test
ATF_TESTS_C+=	pdrfork
ATF_TESTS_C+=	pdwait
ATF_TESTS_C+=	prace
ATF_TESTS_C+=	procdesc
ATF_TESTS_C+=	ptrace_test
TEST_METADATA.ptrace_test+=		timeout="15"
ATF_TESTS_C+=	reaper
ATF_TESTS_C+=	sched_affinity
ATF_TESTS_C+=	shutdown_dgram
ATF_TESTS_C+=	sigaltstack
ATF_TESTS_C+=	sigwait
ATF_TESTS_C+=	socket_accept
ATF_TESTS_C+=	socket_accf
ATF_TESTS_C+=	socket_msg_trunc
ATF_TESTS_C+=	socket_msg_waitall
ATF_TESTS_C+=	socket_splice
ATF_TESTS_C+=	vsock_test
ATF_TESTS_C+=	vsock_wire_test
ATF_TESTS_C+=	vsock_iov_test
CFLAGS.vsock_iov_test+=	-I${SRCTOP}/usr.sbin/bhyve

# Device-level ATF harness for the bhyve virtio-vsock host device (see
# vsock_device_harness/README.md).  It #includes the real pci_virtio_vsock.c and
# shadows its bhyve headers with the mocks in vsock_device_harness/.  The DUT and
# its bounded-copy header are copied into ${.OBJDIR} so their quote-includes
# resolve to those mocks (via -I) instead of the real headers next to the
# original; deliberately no -I to usr.sbin/bhyve is added, so the real
# virtio.h/mevent.h/... are never on the search path.  Host-socket syscalls are
# intercepted with ld --wrap.
ATF_TESTS_C+=	vsock_device_test
.PATH:		${SRCTOP}/tests/sys/kern/vsock_device_harness
CFLAGS.vsock_device_test+=	-DWITHOUT_CAPSICUM \
	-I${SRCTOP}/tests/sys/kern/vsock_device_harness -I${.OBJDIR}
# The mock-included device source and the ld --wrap interceptor functions (which
# must be non-static for the linker to bind them, so they trip
# -Wmissing-prototypes) produce warnings we do not want fatal.  This must live in
# CWARNFLAGS.<src> -- appended after the base -Werror in share/mk/bsd.sys.mk --
# because -Wno-error in CFLAGS.<prog> is emitted before -Werror and has no effect.
CWARNFLAGS.vsock_device_test.c+=	-Wno-error
LDFLAGS.vsock_device_test+=	-Wl,--wrap=socket -Wl,--wrap=connectat \
	-Wl,--wrap=send -Wl,--wrap=recv -Wl,--wrap=sendmsg -Wl,--wrap=shutdown \
	-Wl,--wrap=poll -Wl,--wrap=close
LIBADD.vsock_device_test+=	pthread
CLEANFILES+=	pci_virtio_vsock.c pci_virtio_vsock_iov.h pci_virtio_vsock_probes.h
# The DUT sources are copied into ${.OBJDIR} and #included by the test.  Wire the
# copies to beforedepend, NOT vsock_device_test.o: ATF builds a PIE object
# (vsock_device_test.pieo), so an .o-only prerequisite never fires and a stale or
# missing copy gets compiled.  beforedepend runs regardless of the object suffix
# and re-copies whenever the bhyve sources change.
beforedepend:	pci_virtio_vsock.c pci_virtio_vsock_iov.h \
		pci_virtio_vsock_probes.h
pci_virtio_vsock.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock.c
	cp ${.ALLSRC} ${.TARGET}
pci_virtio_vsock_iov.h:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock_iov.h
	cp ${.ALLSRC} ${.TARGET}
# DTrace USDT probe wrappers; no -DWITH_DTRACE here so every VSOCK_PROBE_* is a
# no-op (the header pulls in <sys/sdt.h> only under WITH_DTRACE).
pci_virtio_vsock_probes.h:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock_probes.h
	cp ${.ALLSRC} ${.TARGET}

TEST_METADATA.sigwait+=	is_exclusive="true"
TEST_METADATA.vsock_test+=	required_user="root"
TEST_METADATA.vsock_test+=	required_kmods="vsock"
TEST_METADATA.vsock_test+=	timeout="60"
.if ${MACHINE_ARCH} != "i386" && ${MACHINE_ARCH:Mpowerpc*} == ""
ATF_TESTS_C+=	subr_physmem_test
.endif
PLAIN_TESTS_C+=	subr_unit_test
ATF_TESTS_C+=	sysctl_kern_proc
ATF_TESTS_C+=	sys_getrandom
ATF_TESTS_C+=	timerfd
LIBADD.timerfd+=	pthread
# One test modifies the system time.
TEST_METADATA.timerfd+=	is_exclusive="true"
ATF_TESTS_C+=	timerfd_cap_test
ATF_TESTS_C+=	fcntl_readahead_cap_test
ATF_TESTS_C+=	posix_fadvise_cap_test
ATF_TESTS_C+=	tty_pts
ATF_TESTS_C+=	unix_dgram
ATF_TESTS_C+=	unix_passfd_dgram
TEST_METADATA.unix_passfd_dgram+=	is_exclusive="true"
ATF_TESTS_C+=	unix_passfd_stream
TEST_METADATA.unix_passfd_stream+=	is_exclusive="true"
ATF_TESTS_C+=	unix_seqpacket_test
TEST_METADATA.unix_seqpacket_test+=	timeout="15"
ATF_TESTS_C+=	unix_stream
ATF_TESTS_C+=	waitpid_nohang
ATF_TESTS_C+=	pdeathsig
ATF_TESTS_C+=	sigsys
TEST_METADATA.sigsys+=	is_exclusive="true"

ATF_TESTS_SH+=	coredump_phnum_test
ATF_TESTS_SH+=	logsigexit_test
ATF_TESTS_SH+=	jailmeta
ATF_TESTS_SH+=	sonewconn_overflow
TEST_METADATA.sonewconn_overflow+=	required_programs="python"
TEST_METADATA.sonewconn_overflow+=	required_user="root"
TEST_METADATA.sonewconn_overflow+=	is_exclusive="true"
ATF_TESTS_SH+=	sendfile_test
ATF_TESTS_SH+=	sysctl_security_jail_children

${PACKAGE}FILES+=	sonewconn_overflow.py
${PACKAGE}FILESMODE_sonewconn_overflow.py=0555

BINDIR=		${TESTSDIR}
PROGS+=		coredump_phnum_helper
PROGS+=		pdeathsig_helper
PROGS+=		sendfile_helper

LIBADD.copy_file_range+=		md
LIBADD.jail_lookup_root+=		jail util
LIBADD.jaildesc+=			pthread
LIBADD.ssl_sendfile+=			pthread crypto ssl
CFLAGS.sys_getrandom+=			-I${SRCTOP}/sys/contrib/zstd/lib
LIBADD.sys_getrandom+=			zstd
LIBADD.sys_getrandom+=			c
LIBADD.sys_getrandom+=			pthread
LIBADD.ptrace_test+=			pthread
LIBADD.unix_seqpacket_test+=		pthread
LIBADD.inotify_test+=			util
LIBADD.jaildesc_cap_test+=		jail
LIBADD.kcov+=				pthread
CFLAGS.ktls_test+=			-DOPENSSL_API_COMPAT=0x10100000L
LIBADD.ktls_test+=			crypto util
LIBADD.listener_wakeup+=		pthread
LIBADD.procdesc+=			pthread
LIBADD.shutdown_dgram+=			pthread
LIBADD.socket_msg_waitall+=		pthread
LIBADD.socket_splice+=			pthread
LIBADD.vsock_test+=			pthread
LIBADD.sendfile_helper+=		pthread
LIBADD.fdgrowtable_test+=		util pthread kvm procstat
LIBADD.sigwait+=			rt
LIBADD.ktrace_test+=			sysdecode
LIBADD.unix_passfd_dgram+=		jail
LIBADD.unix_passfd_stream+=		jail
LIBADD.unix_stream+=			pthread

NETBSD_ATF_TESTS_C+=	lockf_test
NETBSD_ATF_TESTS_C+=	mqueue_test
NETBSD_ATF_TESTS_C+=	sysv_test

CFLAGS.mqueue_test+=	-I${SRCTOP}/tests
LIBADD.mqueue_test+=	rt

LIBADD.tty_pts+=	atf_c util

ATF_TESTS_C+=	libkern_crc32
SRCS.libkern_crc32+=	libkern_crc32.c
.PATH: ${SRCTOP}/sys/libkern
SRCS.libkern_crc32+=	gsb_crc32.c
CFLAGS.libkern_crc32+=	-DTESTING
.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386"
.PATH: ${SRCTOP}/sys/libkern/x86
SRCS.libkern_crc32+=	crc32_sse42.c
.elif ${MACHINE_CPUARCH} == "aarch64"
.PATH: ${SRCTOP}/sys/libkern/arm64
SRCS.libkern_crc32+=	crc32c_armv8.S
.endif

CFLAGS.subr_physmem.c+=	-D_WANT_FREEBSD_BITSET
SRCS.subr_physmem_test+= subr_physmem_test.c subr_physmem.c

# subr_unit.c contains functions whose prototypes lie in headers that cannot be
# included in userland.  But as far as subr_unit_test goes, they're effectively
# static.  So it's ok to disable -Wmissing-prototypes for this program.
CFLAGS.subr_unit.c+=	-Wno-missing-prototypes
SRCS.subr_unit_test+=	subr_unit.c

WARNS?=	3

TESTS_SUBDIRS+=	acct
TESTS_SUBDIRS+=	execve
TESTS_SUBDIRS+=	pipe
TESTS_SUBDIRS+=	tty

.include <netbsd-tests.test.mk>

.include <bsd.test.mk>

PACKAGE=	mac-capability-tests
TESTSDIR=	${TESTSBASE}/sys/mac_capability
SCRIPTSDIR=	${TESTSDIR}

ATF_TESTS_C+=	mac_capability_test
ATF_TESTS_C+=	mac_capability_coalition_test
ATF_TESTS_C+=	mac_capability_isolation_test
ATF_TESTS_C+=	mac_capability_identity_test
ATF_TESTS_C+=	mac_capability_node_test
ATF_TESTS_C+=	mac_capability_accounting_test
ATF_TESTS_C+=	mac_capability_procdesc_test
ATF_TESTS_C+=	mac_capability_mount_test
ATF_TESTS_C+=	mac_capability_system_test
ATF_TESTS_C+=	mac_capability_channel_test
PROGS+=		mac_capability_exec_helper
PROGS+=		mac_capability_channel_helper
PROGS+=		mac_capability_isolation_helper
PROGS+=		mac_capability_shield_helper
ATF_TESTS_SH+=	process_context_test
PROGS+=		process_context_helper process_context_edge_helper \
		process_context_ipc_helper
.for helper in process_context_helper process_context_edge_helper process_context_ipc_helper
CFLAGS.${helper}+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libchannel
LIBADD.${helper}+=	channel capability pthread
.endfor
# authority_boot_helper runs only as PID 1 in an isolated VM image.
PROGS+= authority_boot_helper authority_session_helper
PROGS+= authority_loader_helper
FILES+= authority-inject.so
FILESDIR= ${TESTSDIR}
CLEANFILES+= authority-inject.so
authority-inject.so: ${.CURDIR}/authority_preload_helper.c
	${CC} ${CFLAGS} ${LDFLAGS} -shared -fPIC -o ${.TARGET} ${.ALLSRC}
all: authority-inject.so
CFLAGS.authority_boot_helper+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libcapability
LIBADD.authority_boot_helper+= channel capability pthread
NO_SHARED.authority_boot_helper= yes
CFLAGS.authority_session_helper+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libservice
CFLAGS.authority_session_helper+= -I${SRCTOP}/lib/libcapsulert
LIBADD.authority_session_helper+= service
SCRIPTS+=	run_tests.sh
BINDIR=		${TESTSDIR}

CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/sys/dev/mac_capability
LIBADD.mac_capability_test+=	jail
LIBADD.mac_capability_test+=	util
LIBADD.mac_capability_coalition_test+=	jail
LIBADD.mac_capability_isolation_test+=	jail
LIBADD.mac_capability_isolation_helper+=	jail

.include <bsd.test.mk>

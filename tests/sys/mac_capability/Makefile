TESTSDIR=	${TESTSBASE}/sys/mac_capability

ATF_TESTS_C+=	mac_capability_test
ATF_TESTS_C+=	mac_capability_coalition_test
ATF_TESTS_C+=	mac_capability_isolation_test
ATF_TESTS_C+=	mac_capability_identity_test
ATF_TESTS_C+=	mac_capability_node_test
ATF_TESTS_C+=	mac_capability_accounting_test
ATF_TESTS_C+=	mac_capability_procdesc_test
ATF_TESTS_C+=	mac_capability_mount_test
ATF_TESTS_C+=	mac_capability_system_test
PROGS+=		mac_capability_exec_helper
PROGS+=		mac_capability_isolation_helper
PROGS+=		mac_capability_shield_helper
BINDIR=		${TESTSDIR}

CFLAGS+=	-I${SRCTOP}/sys/dev/mac_capability
LIBADD.mac_capability_test+=	jail
LIBADD.mac_capability_coalition_test+=	jail
LIBADD.mac_capability_isolation_test+=	jail
LIBADD.mac_capability_isolation_helper+=	jail

.include <bsd.test.mk>

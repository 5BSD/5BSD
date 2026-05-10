TESTSDIR=	${TESTSBASE}/sys/cap_rt

ATF_TESTS_C+=	cap_rt_test
ATF_TESTS_C+=	cap_rt_coalition_test
ATF_TESTS_C+=	cap_rt_isolation_test
ATF_TESTS_C+=	cap_rt_identity_test
ATF_TESTS_C+=	cap_rt_node_test
ATF_TESTS_C+=	cap_rt_accounting_test
ATF_TESTS_C+=	cap_rt_procdesc_test
PROGS+=		cap_rt_exec_helper
PROGS+=		cap_rt_isolation_helper
PROGS+=		cap_rt_shield_helper

CFLAGS+=	-I${SRCTOP}/sys/dev/cap_rt
LIBADD.cap_rt_test+=	jail
LIBADD.cap_rt_coalition_test+=	jail

.include <bsd.test.mk>

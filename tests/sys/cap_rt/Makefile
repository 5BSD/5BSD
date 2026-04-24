TESTSDIR=	${TESTSBASE}/sys/cap_rt

ATF_TESTS_C+=	cap_rt_test
PROGS+=		cap_rt_exec_helper
PROGS+=		cap_rt_shield_helper

CFLAGS+=	-I${SRCTOP}/sys/dev/cap_rt
LIBADD.cap_rt_test+=	jail

.include <bsd.test.mk>

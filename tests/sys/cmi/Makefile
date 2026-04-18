TESTSDIR=	${TESTSBASE}/sys/cmi

ATF_TESTS_C+=	cmi_test
PROGS+=		cmi_exec_helper

CFLAGS+=	-I${SRCTOP}/sys/dev/cmi
LIBADD.cmi_test+=	jail

.include <bsd.test.mk>

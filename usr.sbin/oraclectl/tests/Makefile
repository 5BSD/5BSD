PACKAGE=	oraclectl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/oraclectl

.PATH: ${SRCTOP}/usr.sbin/oracled/tests

ATF_TESTS_SH+=	oraclectl_test

PROGS+=		capd_test_guardian
BINDIR=		${TESTSDIR}

${PACKAGE}FILES+=	capd_test_harness.sh

.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capd_test_harness.sh: ${SRCTOP}/usr.sbin/oracled/tests/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	capd_test_harness.sh
.endif

.include <bsd.test.mk>

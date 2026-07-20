PACKAGE=	oraclectl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/oraclectl

.PATH: ${SRCTOP}/usr.sbin/oracled/tests

ATF_TESTS_SH+=	oraclectl_test

PROGS+=		capd_test_guardian
BINDIR=		${TESTSDIR}

${PACKAGE}FILES+=	capd_test_harness.sh

.include <bsd.test.mk>

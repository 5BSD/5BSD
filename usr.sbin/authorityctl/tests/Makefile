PACKAGE=	authorityctl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/authorityctl

.PATH: ${SRCTOP}/usr.sbin/authorityd/tests

ATF_TESTS_SH+=	authorityctl_test

PROGS+=		capd_test_guardian
BINDIR=		${TESTSDIR}

${PACKAGE}FILES+=	capd_test_harness.sh

.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capd_test_harness.sh: ${SRCTOP}/usr.sbin/authorityd/tests/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	capd_test_harness.sh
.endif

.include <bsd.test.mk>

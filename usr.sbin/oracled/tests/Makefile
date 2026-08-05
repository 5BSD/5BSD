PACKAGE=	oracled-tests

ATF_TESTS_SH+=	oracled_test
ATF_TESTS_SH+=	oracled_init_test
ATF_TESTS_SH+=	oracled_bootstrap_test
ATF_TESTS_SH+=	capd_test_guardian_test

PROGS+=		capd_test_guardian
PROGS+=		capd_bootstrap_fixture
BINDIR=		${TESTSDIR}

CFLAGS.capd_bootstrap_fixture+=	-I${SRCTOP}/sys
CFLAGS.capd_bootstrap_fixture+=	-I${SRCTOP}/lib/liboraclert

${PACKAGE}FILES+=	capd_test_harness.sh

# Keep the shared harness beside generated ATF programs for object-tree runs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capd_test_harness.sh: ${.CURDIR}/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	capd_test_harness.sh
.endif

ATF_TESTS_C+=	req_validate_test
CFLAGS.req_validate_test+=	-I${SRCTOP}/sys
CFLAGS.req_validate_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.req_validate_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.req_validate_test+=	-I${SRCTOP}/usr.sbin/oracled

.include <bsd.test.mk>

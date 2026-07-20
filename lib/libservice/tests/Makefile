PACKAGE=	libservice-tests
TESTSDIR=	${TESTSBASE}/lib/libservice

.PATH: ${SRCTOP}/usr.sbin/oracled/tests

ATF_TESTS_SH+=	libservice_test
ATF_TESTS_C+=	libservice_api_test

PROGS+=		capd_service_fixture
PROGS+=		capd_test_guardian
BINDIR=		${TESTSDIR}

LIBADD.capd_service_fixture+=	service
LIBADD.libservice_api_test+=	service
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.libservice_api_test+=	-I${SRCTOP}/sys

${PACKAGE}FILES+=	capd_test_harness.sh

.include <bsd.test.mk>

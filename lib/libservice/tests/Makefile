PACKAGE=	libservice-tests
TESTSDIR=	${TESTSBASE}/lib/libservice
NO_SHARED=

.PATH: ${SRCTOP}/usr.sbin/oracled/tests

ATF_TESTS_SH+=	libservice_test
ATF_TESTS_C+=	libservice_api_test

PROGS+=		capd_service_fixture
PROGS+=		capd_test_guardian
BINDIR=		${TESTSDIR}

LIBADD.capd_service_fixture+=	service
LIBADD.capd_service_fixture+=	channel
LIBADD.capd_service_fixture+=	capability
LIBADD.capd_service_fixture+=	pthread
LIBADD.libservice_api_test+=	service
LIBADD.libservice_api_test+=	channel
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libchannel
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapability
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.libservice_api_test+=	-I${SRCTOP}/sys

${PACKAGE}FILES+=	capd_test_harness.sh

all:
	${INSTALL} -m 0444 \
	    ${SRCTOP}/usr.sbin/oracled/tests/capd_test_harness.sh ${.OBJDIR}/

.include <bsd.test.mk>

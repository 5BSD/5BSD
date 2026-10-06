PACKAGE=	libservice-tests
TESTSDIR=	${TESTSBASE}/lib/libservice
NO_SHARED=	no
NO_SHARED.capd_test_guardian=	yes
NO_SHARED.libservice_api_test=	yes
NO_SHARED.service_ambient_test=	yes
NO_SHARED.software_identity_test=	yes

.PATH: ${SRCTOP}/usr.sbin/capsule/tests

ATF_TESTS_SH+=	libservice_test
ATF_TESTS_SH+=	worker_contract_test
.PATH: ${SRCTOP}/usr.sbin/switchboard
SRCS.libservice_api_test= libservice_api_test.c
CFLAGS.libservice_api_test+= -I${SRCTOP}/usr.sbin/switchboard
ATF_TESTS_C+=	libservice_api_test
ATF_TESTS_C+=	service_ambient_test
.PATH: ${SRCTOP}/lib/libservice
ATF_TESTS_C+=	software_identity_test

PROGS+=		capd_service_fixture
PROGS+=		capd_test_guardian
BINDIR=		${TESTSDIR}

LIBADD.capd_service_fixture+=	service
LIBADD.capd_service_fixture+=	channel
LIBADD.capd_service_fixture+=	capability
LIBADD.capd_service_fixture+=	pthread
LIBADD.libservice_api_test+=	service
LIBADD.libservice_api_test+=	channel
LIBADD.service_ambient_test+=	service
LIBADD.service_ambient_test+=	channel
LIBADD.service_ambient_test+=	capability
LIBADD.service_ambient_test+=	pthread
CFLAGS.service_ambient_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.service_ambient_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.service_ambient_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.service_ambient_test+=	-I${SRCTOP}/sys
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libchannel
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapability
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.libservice_api_test+=	-I${SRCTOP}/sys


# Kernel sender identity and ABI layout, plus a live channel round trip.
LIBADD.software_identity_test+=	service
LIBADD.software_identity_test+=	channel
CFLAGS.software_identity_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.software_identity_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.software_identity_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.software_identity_test+=	-I${SRCTOP}/sys


${PACKAGE}FILES+=	capd_test_harness.sh

ATF_TESTS_SH_SED_worker_contract_test+=	-e 's,@SRCTOP@,${SRCTOP},g'


all:
	${INSTALL} -m 0444 \
	    ${SRCTOP}/usr.sbin/capsule/tests/capd_test_harness.sh ${.OBJDIR}/

LIBADD.capd_service_fixture+= capsulert

.include <bsd.test.mk>

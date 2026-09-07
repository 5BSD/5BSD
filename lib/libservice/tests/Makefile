PACKAGE=	libservice-tests
TESTSDIR=	${TESTSBASE}/lib/libservice
NO_SHARED=	no
NO_SHARED.capd_test_guardian=	yes
NO_SHARED.libservice_api_test=	yes
NO_SHARED.service_ambient_test=	yes
NO_SHARED.reclaim_msg_test=	yes
NO_SHARED.ambient_lookup_test=	yes

.PATH: ${SRCTOP}/usr.sbin/authorityd/tests

ATF_TESTS_SH+=	libservice_test
ATF_TESTS_C+=	libservice_api_test
ATF_TESTS_C+=	service_ambient_test
ATF_TESTS_C+=	reclaim_msg_test
ATF_TESTS_C+=	ambient_lookup_test

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
CFLAGS.service_ambient_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.service_ambient_test+=	-I${SRCTOP}/sys
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libchannel
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapability
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.libservice_api_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.libservice_api_test+=	-I${SRCTOP}/sys

# reclaim_msg_test is header-only: the pure message-shape validator in
# reclaim_msg.h plus the wire struct from serviced_svc_proto.h.  No daemon
# objects, no live plane, no LIBADD beyond the ATF runtime.
CFLAGS.reclaim_msg_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.reclaim_msg_test+=	-I${SRCTOP}/lib/libauthorityrt

# ambient_lookup_test is header-only: the pure fail-soft registration decision
# in ambient_lookup.h.  No daemon objects, no live plane, no LIBADD beyond ATF.
CFLAGS.ambient_lookup_test+=	-I${SRCTOP}/lib/libservice

${PACKAGE}FILES+=	capd_test_harness.sh

all:
	${INSTALL} -m 0444 \
	    ${SRCTOP}/usr.sbin/authorityd/tests/capd_test_harness.sh ${.OBJDIR}/

.include <bsd.test.mk>

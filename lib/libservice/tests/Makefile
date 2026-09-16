PACKAGE=	libservice-tests
TESTSDIR=	${TESTSBASE}/lib/libservice
NO_SHARED=	no
NO_SHARED.capd_test_guardian=	yes
NO_SHARED.libservice_api_test=	yes
NO_SHARED.service_ambient_test=	yes
NO_SHARED.ambient_lookup_test=	yes
NO_SHARED.anoint_wire_test=	yes

.PATH: ${SRCTOP}/usr.sbin/capsule/tests

ATF_TESTS_SH+=	libservice_test
ATF_TESTS_SH+=	worker_contract_test
.PATH: ${SRCTOP}/usr.sbin/switchboard
SRCS.libservice_api_test= libservice_api_test.c
CFLAGS.libservice_api_test+= -I${SRCTOP}/usr.sbin/switchboard
ATF_TESTS_C+=	libservice_api_test
ATF_TESTS_C+=	service_ambient_test
.PATH: ${SRCTOP}/lib/libservice
ATF_TESTS_C+=	ambient_lookup_test
ATF_TESTS_C+=	anoint_wire_test

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


# anoint_wire_test: IPC anointments v1 wire/identity contract (proto 13,
# identity + metadata layouts, authagent ELEVATE, service_elevate argument
# validation).  Needs no live plane; the sender-ABI case uses a channel pair
# when /dev/mac_capability is present and skips otherwise.
LIBADD.anoint_wire_test+=	service
LIBADD.anoint_wire_test+=	channel
CFLAGS.anoint_wire_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.anoint_wire_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.anoint_wire_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.anoint_wire_test+=	-I${SRCTOP}/sys

# ambient_lookup_test is header-only: the pure fail-soft registration decision
# in ambient_lookup.h.  No daemon objects, no live plane, no LIBADD beyond ATF.
CFLAGS.ambient_lookup_test+=	-I${SRCTOP}/lib/libservice

${PACKAGE}FILES+=	capd_test_harness.sh

ATF_TESTS_SH_SED_worker_contract_test+=	-e 's,@SRCTOP@,${SRCTOP},g'

# service_ambient_observability_test: the service_ambient DTrace provider's
# elevate-start/-done contract around service_elevate(3) (source-tree greps).
ATF_TESTS_SH+=	service_ambient_observability_test
ATF_TESTS_SH_SED_service_ambient_observability_test+= \
	-e 's,@SRCTOP@,${SRCTOP},g'

all:
	${INSTALL} -m 0444 \
	    ${SRCTOP}/usr.sbin/capsule/tests/capd_test_harness.sh ${.OBJDIR}/

LIBADD.capd_service_fixture+= capsulert

.include <bsd.test.mk>

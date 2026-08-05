PACKAGE=	rebootd-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/rebootd
CFLAGS+=	-I${SRCTOP}/lib/librebootctl

.PATH: ${SRCTOP}/usr.sbin/oracled/tests
.PATH: ${SRCTOP}/usr.sbin/serviced/tests

ATF_TESTS_SH=	rebootd_test bundle_test
ATF_TESTS_SH_SED_rebootd_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_rebootd_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'
ATF_TESTS_C+=	ops_test policy_test provider_test state_test store_test

.PATH: ${SRCTOP}/usr.sbin/rebootd
CFLAGS.ops_test+=	-I${SRCTOP}/usr.sbin/rebootd
SRCS.ops_test=	ops_test.c rebootd_ops.c
CFLAGS.policy_test+=	-I${SRCTOP}/usr.sbin/rebootd
SRCS.policy_test=	policy_test.c rebootd_policy.c
CFLAGS.state_test+=	-I${SRCTOP}/usr.sbin/rebootd
SRCS.state_test=	state_test.c rebootd_state.c
CFLAGS.store_test+=	-I${SRCTOP}/usr.sbin/rebootd
CFLAGS.store_test+=	-I${SRCTOP}/lib/libfilesystemcmp
SRCS.store_test=	store_test.c rebootd_store.c rebootd_state.c
CFLAGS.provider_test+=	-DREBOOTD_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/sys
CFLAGS.provider_test+=	-I${SRCTOP}/usr.sbin/rebootd
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libnotifycmp
SRCS.provider_test=	provider_test.c rebootd_main.c rebootd_ops.c
LIBADD.provider_test+=	channel notifycmp rebootctl service
NO_SHARED.provider_test=	yes

PROGS+=		capd_test_guardian
PROGS+=		capd_protocol_fixture
BINDIR=		${TESTSDIR}

LIBADD.capd_protocol_fixture+=	service
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libkldmgr
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/librebootctl

FILES+=		capd_test_harness.sh
FILESDIR=	${TESTSDIR}

.include <bsd.test.mk>

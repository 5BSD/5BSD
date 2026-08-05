PACKAGE=	kldmgrd-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/kldmgrd
CFLAGS+=	-I${SRCTOP}/lib/libkldmgr

.PATH: ${SRCTOP}/usr.sbin/oracled/tests
.PATH: ${SRCTOP}/usr.sbin/serviced/tests

ATF_TESTS_SH=	kldmgrd_test bundle_test
ATF_TESTS_SH_SED_kldmgrd_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'
ATF_TESTS_C+=	ops_test policy_test provider_test

.PATH: ${SRCTOP}/usr.sbin/kldmgrd
CFLAGS.ops_test+=	-I${SRCTOP}/usr.sbin/kldmgrd
SRCS.ops_test=	ops_test.c kldmgrd_ops.c
CFLAGS.policy_test+=	-I${SRCTOP}/usr.sbin/kldmgrd
SRCS.policy_test=	policy_test.c kldmgrd_policy.c
CFLAGS.provider_test+=	-DKLDMGRD_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/sys
CFLAGS.provider_test+=	-I${SRCTOP}/usr.sbin/kldmgrd
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
SRCS.provider_test=	provider_test.c kldmgrd_main.c kldmgrd_ops.c
LIBADD.provider_test+=	channel kldmgr service
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

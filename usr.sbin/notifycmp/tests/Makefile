PACKAGE=	notifycmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/notifycmp
NO_SHARED=

CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	broker_test
SRCS.broker_test=	broker_test.c broker.c
CFLAGS.broker_test+=	-I${.CURDIR}/..
CFLAGS.broker_test+=	-I${SRCTOP}/lib/libnotifycmp
LIBADD.broker_test+=	notifycmp pthread service
.PATH:	${.CURDIR}/..

ATF_TESTS_C+=	transport_test
SRCS.transport_test=	transport_test.c transport.c
CFLAGS.transport_test+=	-I${.CURDIR}/..
CFLAGS.transport_test+=	-I${SRCTOP}/lib/libnotifycmp
LIBADD.transport_test+=	notifycmp pthread service

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c
CFLAGS.policy_test+=	-I${.CURDIR}/..
CFLAGS.policy_test+=	-I${SRCTOP}/lib/libnotifycmp
CFLAGS.policy_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.policy_test+=	notifycmp ucl

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

.include <bsd.test.mk>

PACKAGE=	bsdnotify-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/bsdnotify
NO_SHARED=

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libnotify

ATF_TESTS_C+=	broker_test
SRCS.broker_test=	broker_test.c broker.c
CFLAGS.broker_test+=	-I${.CURDIR}/..
LIBADD.broker_test+=	notify pthread service
.PATH:	${.CURDIR}/..

ATF_TESTS_C+=	transport_test
SRCS.transport_test=	transport_test.c transport.c
CFLAGS.transport_test+=	-I${.CURDIR}/..
LIBADD.transport_test+=	notify pthread service

ATF_TESTS_C+=	dispatcher_test
SRCS.dispatcher_test=	dispatcher_test.c broker.c transport.c
CFLAGS.dispatcher_test+=	-I${.CURDIR}/..
CFLAGS.dispatcher_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.dispatcher_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.dispatcher_test+=	-I${SRCTOP}/sys
CFLAGS.dispatcher_test+=	-Wno-unused-function
LIBADD.dispatcher_test+=	auditcmp channel notify pthread service

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c
CFLAGS.policy_test+=	-I${.CURDIR}/..
CFLAGS.policy_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.policy_test+=	notify ucl

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

.include <bsd.test.mk>

PACKAGE=	localnetwork-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localnetwork

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

ATF_TESTS_C+=	session_test
SRCS.session_test=	session_test.c session.c

ATF_TESTS_C+=	io_test
SRCS.io_test=	io_test.c io.c session.c

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c networkcmp.c io.c policy.c session.c
CFLAGS.provider_test+=	-DNETWORKCMP_TESTING -DWITH_CASPER
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp channel networkcmp pthread service
NO_SHARED.provider_test=	yes

.include <bsd.test.mk>

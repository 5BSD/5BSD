PACKAGE=	localnetwork-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localnetwork

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c policy.c
CFLAGS.config_test+=	-I${SRCTOP}/sys
LIBADD.config_test=	ucl

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c networkcmp.c config.c policy.c resolver.c
CFLAGS.provider_test+=	-DNETWORKCMP_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp channel networkcmp pthread service ucl
NO_SHARED.provider_test=	yes

.include <bsd.test.mk>

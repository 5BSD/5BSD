PACKAGE=	localcrypto-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localcrypto

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/sys
.PATH:		${.CURDIR}/..

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c localcrypto.c policy.c
CFLAGS.provider_test+=	-DLOCALCRYPTO_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libcryptocmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libcryptodesc
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp channel cryptocmp cryptodesc service
NO_SHARED.provider_test=	yes

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

.include <bsd.test.mk>

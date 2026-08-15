PACKAGE=	localcrypto-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localcrypto

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/sys
.PATH:		${.CURDIR}/..

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

.include <bsd.test.mk>

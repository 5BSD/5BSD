PACKAGE=	localdevice-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localdevice

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libdevicecmp -I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
.PATH:		${.CURDIR}/..

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c
LIBADD.policy_test=	ucl
NO_SHARED.policy_test=	yes

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c localdevice.c policy.c
CFLAGS.provider_test+=	-DLOCALDEVICE_TESTING
CFLAGS.provider_test+=	-I${.CURDIR}/..
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libdevicecmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	channel devicecmp service ucl
NO_SHARED.provider_test=	yes

.include <bsd.test.mk>

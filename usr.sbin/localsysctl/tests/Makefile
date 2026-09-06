PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localsysctl

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test=	ucl

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c localsysctl.c config.c
CFLAGS.provider_test+=	-DSYSCTLCMP_TESTING
CFLAGS.provider_test+=	-I${.CURDIR}/..
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	channel sysctlcmp service ucl
NO_SHARED.provider_test=	yes

.include <bsd.test.mk>

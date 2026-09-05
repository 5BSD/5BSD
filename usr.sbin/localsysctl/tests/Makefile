PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localsysctl

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test=	ucl

.include <bsd.test.mk>

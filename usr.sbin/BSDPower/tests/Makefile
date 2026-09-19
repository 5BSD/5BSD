PACKAGE=	runtime-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDPower

CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDPower
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

.PATH:	${SRCTOP}/usr.sbin/BSDPower

.include <bsd.test.mk>

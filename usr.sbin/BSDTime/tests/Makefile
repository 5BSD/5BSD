PACKAGE=	runtime-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDTime

CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDTime
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

.PATH:	${SRCTOP}/usr.sbin/BSDTime

.include <bsd.test.mk>

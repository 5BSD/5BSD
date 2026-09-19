PACKAGE=	libpowercmp-tests
TESTSDIR=	${TESTSBASE}/lib/libpowercmp

CFLAGS+=	-I${SRCTOP}/lib/libpowercmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	protocol_test
SRCS.protocol_test=	protocol_test.c powercmp.c
NO_SHARED.protocol_test=	yes
LIBADD.protocol_test+=	service

.PATH: ${SRCTOP}/lib/libpowercmp

.include <bsd.test.mk>

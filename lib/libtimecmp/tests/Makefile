PACKAGE=	libtimecmp-tests
TESTSDIR=	${TESTSBASE}/lib/libtimecmp

CFLAGS+=	-I${SRCTOP}/lib/libtimecmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	protocol_test
SRCS.protocol_test=	protocol_test.c timecmp.c
NO_SHARED.protocol_test=	yes
LIBADD.protocol_test+=	service

.PATH: ${SRCTOP}/lib/libtimecmp

.include <bsd.test.mk>

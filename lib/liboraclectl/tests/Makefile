PACKAGE=	liboraclectl-tests
TESTSDIR=	${TESTSBASE}/lib/liboraclectl

ATF_TESTS_C+=	oraclectl_test

CFLAGS+=	-I${SRCTOP}/lib/liboraclectl
CFLAGS+=	-I${SRCTOP}/lib/liboraclert
LIBADD+=	oraclectl
NO_SHARED=	yes

.include <bsd.test.mk>

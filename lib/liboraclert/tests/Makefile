PACKAGE=	tests

ATF_TESTS_C=	claim_parse_test

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/liboraclert
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		oraclert

.include <bsd.test.mk>

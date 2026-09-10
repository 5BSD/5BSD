PACKAGE=	libcapsulert-tests

ATF_TESTS_C=	claim_parse_test

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capsulert
LDFLAGS+=	-Wl,-rpath,${OBJTOP}/lib/libcapsulert

.include <bsd.test.mk>

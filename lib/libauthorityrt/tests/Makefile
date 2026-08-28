PACKAGE=	libauthorityrt-tests

ATF_TESTS_C=	claim_parse_test

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		authorityrt
LDFLAGS+=	-Wl,-rpath,${OBJTOP}/lib/libauthorityrt

.include <bsd.test.mk>

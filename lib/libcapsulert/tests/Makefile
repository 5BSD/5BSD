PACKAGE=	libcapsulert-tests

ATF_TESTS_C=	claim_parse_test storage_namespace_test

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capsulert

# Build-tree lookup belongs to test execution, never the installed ELF.
TESTS_LD_LIBRARY_PATH+= ${OBJTOP}/lib/libcapsulert

.include <bsd.test.mk>

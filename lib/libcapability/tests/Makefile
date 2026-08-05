PACKAGE=	libcapability-tests
TESTSDIR=	${TESTSBASE}/lib/libcapability

ATF_TESTS_C+=	libcapability_test
CFLAGS+=	-I${SRCTOP}/lib/libcapability
CFLAGS+=	-I${SRCTOP}/sys
LIBADD+=	capability
NO_SHARED=	yes

.include <bsd.test.mk>

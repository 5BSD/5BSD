PACKAGE=	libauthorityctl-tests
TESTSDIR=	${TESTSBASE}/lib/libauthorityctl

ATF_TESTS_C+=	authorityctl_test

CFLAGS+=	-I${SRCTOP}/lib/libauthorityctl
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
LIBADD+=	authorityctl
NO_SHARED=	yes

.include <bsd.test.mk>

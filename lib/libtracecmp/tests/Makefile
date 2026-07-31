PACKAGE=	libtracecmp-tests
TESTSDIR=	${TESTSBASE}/lib/libtracecmp
NO_SHARED=

ATF_TESTS_C+=	tracecmp_test
SRCS.tracecmp_test=	tracecmp_test.c tracecmp.c
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/libservice
LIBADD.tracecmp_test=	service
.PATH:	${.CURDIR}/..

.include <bsd.test.mk>

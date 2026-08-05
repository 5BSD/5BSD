PACKAGE=	libtracecmp-tests
TESTSDIR=	${TESTSBASE}/lib/libtracecmp
NO_SHARED=

ATF_TESTS_C+=	tracecmp_test
SRCS.tracecmp_test=	tracecmp_test.c tracecmp_test_impl.c
LIBADD.tracecmp_test=	dtrace service
CFLAGS.tracecmp_test+=	-DTRACECMP_TESTING

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	tracecmp_test_impl.c
LIBADD.client_lifecycle_test=	dtrace pthread

CFLAGS+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common

.include <bsd.test.mk>

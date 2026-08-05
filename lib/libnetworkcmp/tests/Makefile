PACKAGE=	libnetworkcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libnetworkcmp
NO_SHARED=

ATF_TESTS_C+=	networkcmp_test

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	networkcmp_client_impl.c
LIBADD.client_lifecycle_test+=	pthread
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libservice

SRCS.networkcmp_test=	networkcmp_test.c networkcmp_test_impl.c
LIBADD.networkcmp_test+=	pthread service
CFLAGS.networkcmp_test+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.networkcmp_test+=	-I${SRCTOP}/lib/libservice

.include <bsd.test.mk>

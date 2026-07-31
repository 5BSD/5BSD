PACKAGE=	libnetworkcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libnetworkcmp
NO_SHARED=

ATF_TESTS_C+=	networkcmp_test

LIBADD.networkcmp_test+=	networkcmp
CFLAGS.networkcmp_test+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.networkcmp_test+=	-I${SRCTOP}/lib/libservice

.include <bsd.test.mk>

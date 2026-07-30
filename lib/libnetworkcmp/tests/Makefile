PACKAGE=	libnetworkcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libnetworkcmp

ATF_TESTS_C+=	networkcmp_test

LIBADD.networkcmp_test+=	networkcmp
CFLAGS.networkcmp_test+=	-I${SRCTOP}/lib/libnetworkcmp

.include <bsd.test.mk>

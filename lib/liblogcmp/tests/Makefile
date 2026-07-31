PACKAGE=	liblogcmp-tests
TESTSDIR=	${TESTSBASE}/lib/liblogcmp
NO_SHARED=

ATF_TESTS_C+=	logcmp_test
SRCS.logcmp_test=	logcmp_test.c logcmp.c
CFLAGS.logcmp_test+=	-I${.CURDIR}/..
CFLAGS.logcmp_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.logcmp_test+=	-I${SRCTOP}/lib/libshmring
LIBADD.logcmp_test+=	pthread service shmring
.PATH:	${.CURDIR}/..

.include <bsd.test.mk>

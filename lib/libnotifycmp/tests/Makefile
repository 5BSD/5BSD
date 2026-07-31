PACKAGE=	libnotifycmp-tests
TESTSDIR=	${TESTSBASE}/lib/libnotifycmp
NO_SHARED=

ATF_TESTS_C+=	notifycmp_test
SRCS.notifycmp_test=	notifycmp_test.c notifycmp.c
CFLAGS.notifycmp_test+=	-I${.CURDIR}/..
CFLAGS.notifycmp_test+=	-I${SRCTOP}/lib/libservice
LIBADD.notifycmp_test+=	pthread service
.PATH:	${.CURDIR}/..

.include <bsd.test.mk>

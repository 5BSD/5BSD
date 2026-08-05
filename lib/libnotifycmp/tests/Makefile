PACKAGE=	libnotifycmp-tests
TESTSDIR=	${TESTSBASE}/lib/libnotifycmp
NO_SHARED=

ATF_TESTS_C+=	notifycmp_test
SRCS.notifycmp_test=	notifycmp_test.c notifycmp.c
CFLAGS.notifycmp_test+=	-I${.CURDIR}/..
CFLAGS.notifycmp_test+=	-I${SRCTOP}/lib/libservice
LIBADD.notifycmp_test+=	pthread service

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c \
	notifycmp_client_impl.c fake_service.c
CFLAGS.client_lifecycle_test+=	-I${.CURDIR}/..
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libservice
LIBADD.client_lifecycle_test+=	pthread
.PATH:	${.CURDIR}/..

.include <bsd.test.mk>

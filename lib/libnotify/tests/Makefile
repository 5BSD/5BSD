PACKAGE=	libnotify-tests
TESTSDIR=	${TESTSBASE}/lib/libnotify
NO_SHARED=

ATF_TESTS_C+=	notify_test
SRCS.notify_test=	notify_test.c notify.c
CFLAGS.notify_test+=	-I${.CURDIR}/..
CFLAGS.notify_test+=	-I${SRCTOP}/lib/libservice
LIBADD.notify_test+=	pthread service

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c \
	notify_client_impl.c fake_service.c
CFLAGS.client_lifecycle_test+=	-I${.CURDIR}/..
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libservice
LIBADD.client_lifecycle_test+=	pthread
.PATH:	${.CURDIR}/..

.include <bsd.test.mk>

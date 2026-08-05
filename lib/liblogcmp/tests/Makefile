PACKAGE=	liblogcmp-tests
TESTSDIR=	${TESTSBASE}/lib/liblogcmp
NO_SHARED=

ATF_TESTS_C+=	logcmp_test
SRCS.logcmp_test=	logcmp_test.c logcmp.c logcmp_wakeup.c
CFLAGS.logcmp_test+=	-I${.CURDIR}/..
CFLAGS.logcmp_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.logcmp_test+=	-I${SRCTOP}/lib/libshmring
LIBADD.logcmp_test+=	pthread service shmring

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c logcmp_client_impl.c \
	logcmp_wakeup.c fake_service.c
CFLAGS.client_lifecycle_test+=	-I${.CURDIR}/..
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libshmring
LIBADD.client_lifecycle_test+=	pthread shmring
.PATH:	${.CURDIR}/..

.include <bsd.test.mk>

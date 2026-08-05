PACKAGE=	librebootctl-tests
TESTSDIR=	${TESTSBASE}/lib/librebootctl
NO_SHARED=

ATF_TESTS_C+=	rebootctl_test
SRCS.rebootctl_test=	rebootctl_test.c rebootctl.c
LIBADD.rebootctl_test=	service

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	rebootctl.c
LIBADD.client_lifecycle_test=	pthread

CFLAGS+=	-I${SRCTOP}/lib/librebootctl
CFLAGS+=	-I${SRCTOP}/lib/libservice

.PATH: ${SRCTOP}/lib/librebootctl

.include <bsd.test.mk>

PACKAGE=	libkldmgr-tests
TESTSDIR=	${TESTSBASE}/lib/libkldmgr
NO_SHARED=

ATF_TESTS_C+=	kldmgr_test
SRCS.kldmgr_test=	kldmgr_test.c kldmgr.c
LIBADD.kldmgr_test=	service

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	kldmgr.c
LIBADD.client_lifecycle_test=	pthread

CFLAGS+=	-I${SRCTOP}/lib/libkldmgr
CFLAGS+=	-I${SRCTOP}/lib/libservice

.PATH: ${SRCTOP}/lib/libkldmgr

.include <bsd.test.mk>

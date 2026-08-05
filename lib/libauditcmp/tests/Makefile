PACKAGE=	libauditcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libauditcmp

CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	auditcmp_test
SRCS.auditcmp_test=	auditcmp_test.c auditcmp.c
NO_SHARED.auditcmp_test=	yes
LIBADD.auditcmp_test+=	service

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c auditcmp.c
NO_SHARED.client_lifecycle_test=	yes
LIBADD.client_lifecycle_test+=	pthread

.PATH: ${SRCTOP}/lib/libauditcmp

.include <bsd.test.mk>

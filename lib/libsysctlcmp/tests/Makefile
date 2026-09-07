PACKAGE=	libsysctlcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libsysctlcmp

CFLAGS+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	sysctlcmp_test
ATF_TESTS_C+=	client_strings_test
SRCS.client_strings_test=	client_strings_test.c
NO_SHARED.client_strings_test=	yes
SRCS.sysctlcmp_test=	sysctlcmp_test.c sysctlcmp.c
NO_SHARED.sysctlcmp_test=	yes
LIBADD.sysctlcmp_test+=	service

.PATH: ${SRCTOP}/lib/libsysctlcmp

.include <bsd.test.mk>

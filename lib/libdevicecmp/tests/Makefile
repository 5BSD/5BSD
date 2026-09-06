PACKAGE=libdevicecmp-tests
TESTSDIR=${TESTSBASE}/lib/libdevicecmp

CFLAGS+=-I${SRCTOP}/lib/libdevicecmp
CFLAGS+=-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=devicecmp_api_test
SRCS.devicecmp_api_test=devicecmp_api_test.c devicecmp.c
NO_SHARED.devicecmp_api_test=yes
LIBADD.devicecmp_api_test=service pthread

.PATH:${SRCTOP}/lib/libdevicecmp

.include <bsd.test.mk>

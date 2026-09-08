PACKAGE=libdevicecmp-tests
TESTSDIR=${TESTSBASE}/lib/libdevicecmp

CFLAGS+=-I${SRCTOP}/lib/libdevicecmp
CFLAGS+=-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=devicecmp_api_test

ATF_TESTS_C+=client_protocol_test
SRCS.client_protocol_test=client_protocol_test.c
NO_SHARED.client_protocol_test=yes
LIBADD.client_protocol_test=pthread
SRCS.devicecmp_api_test=devicecmp_api_test.c devicecmp.c
NO_SHARED.devicecmp_api_test=yes
LIBADD.devicecmp_api_test=service pthread

.PATH:${SRCTOP}/lib/libdevicecmp

.include <bsd.test.mk>

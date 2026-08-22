PACKAGE=libcryptocmp-tests
TESTSDIR=${TESTSBASE}/lib/libcryptocmp

CFLAGS+=-I${SRCTOP}/lib/libcryptocmp
CFLAGS+=-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=cryptocmp_api_test
SRCS.cryptocmp_api_test=cryptocmp_api_test.c cryptocmp.c
NO_SHARED.cryptocmp_api_test=yes
LIBADD.cryptocmp_api_test=service pthread

ATF_TESTS_C+=client_protocol_test
SRCS.client_protocol_test=client_protocol_test.c fake_service.c cryptocmp.c
NO_SHARED.client_protocol_test=yes
LIBADD.client_protocol_test=pthread

.PATH:${SRCTOP}/lib/libcryptocmp

.include <bsd.test.mk>

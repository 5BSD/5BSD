PACKAGE=libcryptocmp-tests
TESTSDIR=${TESTSBASE}/lib/libcryptocmp

CFLAGS+=-I${SRCTOP}/lib/libcryptocmp
CFLAGS+=-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=cryptocmp_api_test
SRCS.cryptocmp_api_test=cryptocmp_api_test.c cryptocmp.c
NO_SHARED.cryptocmp_api_test=yes
LIBADD.cryptocmp_api_test=service pthread

.PATH:${SRCTOP}/lib/libcryptocmp

.include <bsd.test.mk>

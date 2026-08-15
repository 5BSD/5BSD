PACKAGE=libcryptodesc-tests
TESTSDIR=${TESTSBASE}/lib/libcryptodesc

CFLAGS+=-I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/sys

ATF_TESTS_C+=cryptodesc_api_test
SRCS.cryptodesc_api_test=cryptodesc_api_test.c cryptodesc.c
NO_SHARED.cryptodesc_api_test=yes

.PATH:${SRCTOP}/lib/libcryptodesc

.include <bsd.test.mk>

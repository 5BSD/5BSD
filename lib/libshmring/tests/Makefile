PACKAGE=	libshmring-tests
TESTSDIR=	${TESTSBASE}/lib/libshmring
NO_SHARED=

ATF_TESTS_C+=	shmring_test

LIBADD.shmring_test+=	shmring
CFLAGS.shmring_test+=	-I${SRCTOP}/lib/libshmring

.include <bsd.test.mk>

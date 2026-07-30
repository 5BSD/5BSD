PACKAGE=	libshmring-tests
TESTSDIR=	${TESTSBASE}/lib/libshmring

ATF_TESTS_C+=	shmring_test

LIBADD.shmring_test+=	shmring
CFLAGS.shmring_test+=	-I${SRCTOP}/lib/libshmring

.include <bsd.test.mk>

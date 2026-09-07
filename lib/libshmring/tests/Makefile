PACKAGE=	libshmring-tests
TESTSDIR=	${TESTSBASE}/lib/libshmring
NO_SHARED=

ATF_TESTS_C+=	shmring_test
PROGS+=		shmringbench
BINDIR_shmringbench=	${TESTSDIR}
${PACKAGE}FILES+=	README.benchmark

LIBADD.shmring_test+=	shmring

LIBADD.shmringbench+=	shmring pthread
CFLAGS.shmringbench+=	-I${SRCTOP}/lib/libshmring
CFLAGS.shmring_test+=	-I${SRCTOP}/lib/libshmring

.include <bsd.test.mk>

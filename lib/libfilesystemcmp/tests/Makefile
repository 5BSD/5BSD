PACKAGE=	libfilesystemcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libfilesystemcmp

ATF_TESTS_C+=	filesystemcmp_test

LIBADD.filesystemcmp_test+=	filesystemcmp
CFLAGS.filesystemcmp_test+=	-I${SRCTOP}/lib/libfilesystemcmp

.include <bsd.test.mk>

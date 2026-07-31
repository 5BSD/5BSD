PACKAGE=	libfilesystemcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libfilesystemcmp
NO_SHARED=

ATF_TESTS_C+=	filesystemcmp_test path_test

LIBADD.filesystemcmp_test+=	filesystemcmp
CFLAGS.filesystemcmp_test+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS.filesystemcmp_test+=	-I${SRCTOP}/lib/libservice

SRCS.path_test=	path_test.c ../filesystemcmp_path.c
LIBADD.path_test+=	pthread
CFLAGS.path_test+=	-I${SRCTOP}/lib/libfilesystemcmp

.include <bsd.test.mk>

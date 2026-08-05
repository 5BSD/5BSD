PACKAGE=	libfilesystemcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libfilesystemcmp
NO_SHARED=

ATF_TESTS_C+=	filesystemcmp_test path_test

ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	filesystemcmp_client_impl.c
LIBADD.client_lifecycle_test+=	pthread
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS.client_lifecycle_test+=	-I${SRCTOP}/lib/libservice

SRCS.filesystemcmp_test=	filesystemcmp_test.c filesystemcmp_test_impl.c \
	filesystemcmp_path_impl.c
LIBADD.filesystemcmp_test+=	pthread service
CFLAGS.filesystemcmp_test+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS.filesystemcmp_test+=	-I${SRCTOP}/lib/libservice

SRCS.path_test=	path_test.c filesystemcmp_path_impl.c
LIBADD.path_test+=	pthread
CFLAGS.path_test+=	-I${SRCTOP}/lib/libfilesystemcmp

.include <bsd.test.mk>

PACKAGE=	tzfs-tests
TESTSDIR=	${TESTSBASE}/lib/libbsdfilesystem

ATF_TESTS_C=	bsdfilesystem_test
SRCS.bsdfilesystem_test=	bsdfilesystem_test.c
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/sys

.include <bsd.test.mk>

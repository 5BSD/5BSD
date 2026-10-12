PACKAGE=	tzfs-tests
TESTSDIR=	${TESTSBASE}/lib/libbsdfilesystem

# bsdfilesystem_test compiles ../bsdfilesystem.c against the transport double
# in this directory (filesystem_transact.h), found before any other include.
ATF_TESTS_C=	bsdfilesystem_test
SRCS.bsdfilesystem_test=	bsdfilesystem_test.c
CFLAGS.bsdfilesystem_test+=	-I${.CURDIR}
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.bsdfilesystem_test+=	-I${SRCTOP}/sys

.include <bsd.test.mk>

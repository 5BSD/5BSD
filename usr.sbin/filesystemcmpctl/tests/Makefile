PACKAGE=	localfilesystem-tests

ATF_TESTS_SH=	filesystemcmpctl_test

PROGS+=		filesystemcmpctl_test_bin
PROGS+=		filesystemcmpctl_success_bin
BINDIR_filesystemcmpctl_test_bin=	${TESTSDIR}
SRCS.filesystemcmpctl_test_bin=	filesystemcmpctl.c
NO_SHARED.filesystemcmpctl_test_bin=	yes
CFLAGS.filesystemcmpctl_test_bin+=	-I${SRCTOP}/lib/libfilesystemcmp
LIBADD.filesystemcmpctl_test_bin+=	filesystemcmp

BINDIR_filesystemcmpctl_success_bin=	${TESTSDIR}
SRCS.filesystemcmpctl_success_bin=	filesystemcmpctl_success_impl.c \
		fake_filesystemcmp.c
NO_SHARED.filesystemcmpctl_success_bin=	yes
CFLAGS.filesystemcmpctl_success_bin+=	-I${SRCTOP}/lib/libfilesystemcmp

.PATH:	${SRCTOP}/usr.sbin/filesystemcmpctl

.include <bsd.test.mk>

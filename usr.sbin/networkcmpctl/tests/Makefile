PACKAGE=	localnetwork-tests

ATF_TESTS_SH=	networkcmpctl_test

PROGS+=		networkcmpctl_test_bin
PROGS+=		networkcmpctl_success_bin
BINDIR_networkcmpctl_test_bin=	${TESTSDIR}
SRCS.networkcmpctl_test_bin=	networkcmpctl.c
NO_SHARED.networkcmpctl_test_bin=	yes
CFLAGS.networkcmpctl_test_bin+=	-I${SRCTOP}/lib/libnetworkcmp
LIBADD.networkcmpctl_test_bin+=	networkcmp

BINDIR_networkcmpctl_success_bin=	${TESTSDIR}
SRCS.networkcmpctl_success_bin=	networkcmpctl_success_impl.c \
		fake_networkcmp.c
NO_SHARED.networkcmpctl_success_bin=	yes
CFLAGS.networkcmpctl_success_bin+=	-I${SRCTOP}/lib/libnetworkcmp

.PATH:	${SRCTOP}/usr.sbin/networkcmpctl

.include <bsd.test.mk>

PACKAGE=	bsdnetwork-tests

ATF_TESTS_SH=	networkcmpctl_test

PROGS+=		networkcmpctl_test_bin
PROGS+=		networkcmpctl_success_bin
PROGS+=		no_ambient_exec
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

# no_ambient_exec clears the inherited discovery route for the child.
BINDIR_no_ambient_exec=	${TESTSDIR}
NO_SHARED.no_ambient_exec=	yes
CFLAGS.no_ambient_exec+=	-I${SRCTOP}/lib/libservice
LIBADD.no_ambient_exec+=	service

.PATH:	${SRCTOP}/usr.sbin/networkcmpctl ${SRCTOP}/usr.sbin/notifyctl/tests

.include <bsd.test.mk>

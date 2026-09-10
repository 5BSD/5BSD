PACKAGE=	tzfs-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/tzfsctl

ATF_TESTS_SH=	tzfsctl_test

PROGS+=	tzfsctl_success_bin
BINDIR_tzfsctl_success_bin=	${TESTSDIR}
SRCS.tzfsctl_success_bin=	tzfsctl_success_impl.c fake_tzfsd.c
NO_SHARED.tzfsctl_success_bin=	yes
CFLAGS.tzfsctl_success_bin+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.tzfsctl_success_bin+=	-I${SRCTOP}/lib/libtzfsd
CFLAGS.tzfsctl_success_bin+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.tzfsctl_success_bin+=	-I${SRCTOP}/sys

.PATH: ${SRCTOP}/usr.sbin/tzfsctl

.include <bsd.test.mk>

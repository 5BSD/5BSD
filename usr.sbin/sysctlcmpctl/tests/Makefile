PACKAGE=	libsysctlcmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/sysctlcmpctl

ATF_TESTS_SH=	sysctlcmpctl_test

PROGS+=	sysctlcmpctl_success_bin
BINDIR_sysctlcmpctl_success_bin=	${TESTSDIR}
SRCS.sysctlcmpctl_success_bin=	sysctlcmpctl_success_impl.c fake_sysctlcmp.c
NO_SHARED.sysctlcmpctl_success_bin=	yes
CFLAGS.sysctlcmpctl_success_bin+=	-I${SRCTOP}/lib/libsysctlcmp

.PATH: ${SRCTOP}/usr.sbin/sysctlcmpctl

.include <bsd.test.mk>

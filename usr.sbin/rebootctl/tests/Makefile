PACKAGE=	rebootd-tests
ATF_TESTS_SH=	rebootctl_test
PROGS=	rebootctl_test_bin
BINDIR_rebootctl_test_bin=	${TESTSDIR}
SRCS.rebootctl_test_bin=	rebootctl_test_impl.c rebootd_policy.c fake_rebootctl.c
CFLAGS.rebootctl_test_bin+=	-I${SRCTOP}/lib/librebootctl
CFLAGS.rebootctl_test_bin+=	-I${SRCTOP}/usr.sbin/rebootd
NO_SHARED.rebootctl_test_bin=	yes
.PATH:	${SRCTOP}/usr.sbin/rebootd
.include <bsd.test.mk>

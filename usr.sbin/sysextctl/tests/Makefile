PACKAGE=	sysextctl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/sysextctl
ATF_TESTS_SH=	sysextctl_test
PROGS+=	sysextctl_test_bin
BINDIR_sysextctl_test_bin=	${TESTSDIR}
SRCS.sysextctl_test_bin=	sysextctl.c fake_service.c
CFLAGS+=	-I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libcapsulert
.PATH: ${SRCTOP}/usr.sbin/sysextctl
.include <bsd.test.mk>

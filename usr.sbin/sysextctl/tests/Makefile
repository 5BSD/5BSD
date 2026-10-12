PACKAGE=	sysextctl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/sysextctl
ATF_TESTS_SH=	sysextctl_test
PROGS+=	sysextctl_test_bin
BINDIR_sysextctl_test_bin=	${TESTSDIR}
# sysextctl over a scripted libextensioncmp (fake_service.c).
SRCS.sysextctl_test_bin=	sysextctl.c fake_service.c
CFLAGS+=	-I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libextensioncmp
.PATH: ${SRCTOP}/usr.sbin/sysextctl
.include <bsd.test.mk>

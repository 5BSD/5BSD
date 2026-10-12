PACKAGE=	sysextctl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/sysextctl
ATF_TESTS_SH=	sysextctl_test
PROGS+=	sysextctl_test_bin
BINDIR_sysextctl_test_bin=	${TESTSDIR}
SRCS.sysextctl_test_bin=	sysextctl.c fake_service.c extension_session.c
.PATH: ${SRCTOP}/lib/libextensioncmp
CFLAGS+=	-I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libextensioncmp
.PATH: ${SRCTOP}/usr.sbin/sysextctl
.include <bsd.test.mk>

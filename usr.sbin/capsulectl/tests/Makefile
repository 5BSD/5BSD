PACKAGE=	capsulectl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/capsulectl

ATF_TESTS_SH=	capsulectl_test

PROGS+=	capsulectl_test_bin
PROGS+=	capsulectl_success_bin
PROGS+=	no_ambient_exec
BINDIR_capsulectl_test_bin=	${TESTSDIR}
SRCS.capsulectl_test_bin=	capsulectl.c
NO_SHARED.capsulectl_test_bin=	yes
CFLAGS.capsulectl_test_bin+=	-I${SRCTOP}/lib/libservice
CFLAGS.capsulectl_test_bin+=	-I${SRCTOP}/lib/libcapsulert
LIBADD.capsulectl_test_bin+=	service

BINDIR_capsulectl_success_bin=	${TESTSDIR}
SRCS.capsulectl_success_bin=	capsulectl_success_impl.c fake_service.c
NO_SHARED.capsulectl_success_bin=	yes
CFLAGS.capsulectl_success_bin+=	-I${SRCTOP}/lib/libservice
CFLAGS.capsulectl_success_bin+=	-I${SRCTOP}/lib/libcapsulert

# no_ambient_exec clears the inherited discovery route for the child.
BINDIR_no_ambient_exec=	${TESTSDIR}
NO_SHARED.no_ambient_exec=	yes
CFLAGS.no_ambient_exec+=	-I${SRCTOP}/lib/libservice
LIBADD.no_ambient_exec+=	service

.PATH: ${SRCTOP}/usr.sbin/capsulectl ${SRCTOP}/usr.sbin/notifyctl/tests

.include <bsd.test.mk>

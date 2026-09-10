PACKAGE=	capsulectl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/capsulectl

ATF_TESTS_SH=	capsulectl_test

PROGS+=	capsulectl_test_bin
PROGS+=	capsulectl_success_bin
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

.PATH: ${SRCTOP}/usr.sbin/capsulectl

.include <bsd.test.mk>

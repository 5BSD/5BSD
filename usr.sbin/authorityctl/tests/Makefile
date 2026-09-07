PACKAGE=	authorityctl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/authorityctl

ATF_TESTS_SH=	authorityctl_test

PROGS+=	authorityctl_test_bin
PROGS+=	authorityctl_success_bin
BINDIR_authorityctl_test_bin=	${TESTSDIR}
SRCS.authorityctl_test_bin=	authorityctl.c
NO_SHARED.authorityctl_test_bin=	yes
CFLAGS.authorityctl_test_bin+=	-I${SRCTOP}/lib/libservice
CFLAGS.authorityctl_test_bin+=	-I${SRCTOP}/lib/libauthorityrt
LIBADD.authorityctl_test_bin+=	service

BINDIR_authorityctl_success_bin=	${TESTSDIR}
SRCS.authorityctl_success_bin=	authorityctl_success_impl.c fake_service.c
NO_SHARED.authorityctl_success_bin=	yes
CFLAGS.authorityctl_success_bin+=	-I${SRCTOP}/lib/libservice
CFLAGS.authorityctl_success_bin+=	-I${SRCTOP}/lib/libauthorityrt

.PATH: ${SRCTOP}/usr.sbin/authorityctl

.include <bsd.test.mk>

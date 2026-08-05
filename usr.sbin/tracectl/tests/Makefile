PACKAGE=	traced-tests
ATF_TESTS_SH=	tracectl_test
PROGS=	tracectl_test_bin
BINDIR_tracectl_test_bin=	${TESTSDIR}
SRCS.tracectl_test_bin=	tracectl_test_impl.c tracecmp_policy.c
CFLAGS.tracectl_test_bin+=	-I${SRCTOP}/usr.sbin/traced
NO_SHARED.tracectl_test_bin=	yes
.PATH:	${SRCTOP}/usr.sbin/traced
.include <bsd.test.mk>

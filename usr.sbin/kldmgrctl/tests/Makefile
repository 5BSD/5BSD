PACKAGE=	kldmgrd-tests
ATF_TESTS_SH=	kldmgrctl_test
PROGS=	kldmgrctl_test_bin
BINDIR_kldmgrctl_test_bin=	${TESTSDIR}
SRCS.kldmgrctl_test_bin=	kldmgrctl_test_impl.c kldmgrd_policy.c fake_kldmgr.c
CFLAGS.kldmgrctl_test_bin+=	-I${SRCTOP}/lib/libkldmgr
CFLAGS.kldmgrctl_test_bin+=	-I${SRCTOP}/usr.sbin/kldmgrd
NO_SHARED.kldmgrctl_test_bin=	yes
.PATH:	${SRCTOP}/usr.sbin/kldmgrd
.include <bsd.test.mk>

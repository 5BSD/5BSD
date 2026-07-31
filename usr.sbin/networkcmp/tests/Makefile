PACKAGE=	networkcmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/networkcmp

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

ATF_TESTS_C+=	session_test
SRCS.session_test=	session_test.c session.c

ATF_TESTS_C+=	io_test
SRCS.io_test=	io_test.c io.c session.c

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

.include <bsd.test.mk>

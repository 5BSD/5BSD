PACKAGE=	logcmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/logcmp
NO_SHARED=

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring

ATF_TESTS_C+=	session_test
SRCS.session_test=	session_test.c session.c
LIBADD.session_test+=	logcmp shmring
.PATH:	${.CURDIR}/..

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

.include <bsd.test.mk>

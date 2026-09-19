PACKAGE=	traced-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDTrace
.PATH:		${SRCTOP}/usr.sbin/BSDTrace

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_C+=	policy_test
ATF_TESTS_C+=	session_test
CFLAGS.policy_test+=	-I${SRCTOP}/usr.sbin/BSDTrace
SRCS.policy_test=	policy_test.c tracecmp_policy.c
CFLAGS.session_test+=	-DTRACECMP_TESTING
CFLAGS.session_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.session_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.session_test+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS.session_test+=	-I${SRCTOP}/usr.sbin/BSDTrace
CFLAGS.session_test+=	-I${SRCTOP}/sys
SRCS.session_test=	session_test.c tracecmp.c
LIBADD.session_test=	bsm channel service tracecmp
NO_SHARED.session_test=	yes
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

.include <bsd.test.mk>

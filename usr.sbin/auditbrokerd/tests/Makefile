PACKAGE=	auditbrokerd-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/auditbrokerd
.PATH:		${SRCTOP}/usr.sbin/auditbrokerd

# Common daemon sources included by the tests use the public protocol API.
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
# auditcmp.c (shared across the test programs) uses <libservice.h>; the base
# compile of it needs the include too, not just the per-program CFLAGS below.
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	policy_test rate_test submit_test
ATF_TESTS_C+=	session_test
ATF_TESTS_SH+=	bundle_test
SRCS.policy_test=	policy_test.c auditcmp_policy.c
CFLAGS.policy_test+=	-I${SRCTOP}/usr.sbin/auditbrokerd
CFLAGS.policy_test+=	-I${SRCTOP}/sys
# rate_test drives the parent per-label admission bucket (in auditcmp.c) via the
# AUDITCMP_TESTING hooks, so it compiles the daemon TU in its test configuration.
SRCS.rate_test=	rate_test.c auditcmp.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.rate_test+=	-DAUDITCMP_TESTING
CFLAGS.rate_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.rate_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.rate_test+=	-I${SRCTOP}/usr.sbin/auditbrokerd
CFLAGS.rate_test+=	-I${SRCTOP}/sys
LIBADD.rate_test=	auditcmp channel service
NO_SHARED.rate_test=	yes
SRCS.submit_test=	submit_test.c auditcmp_submit.c
CFLAGS.submit_test+=	-I${SRCTOP}/usr.sbin/auditbrokerd
CFLAGS.session_test+=	-DAUDITCMP_TESTING
CFLAGS.session_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.session_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.session_test+=	-I${SRCTOP}/usr.sbin/auditbrokerd
CFLAGS.session_test+=	-I${SRCTOP}/sys
SRCS.session_test=	session_test.c auditcmp.c auditcmp_rate.c auditcmp_submit.c
LIBADD.session_test=	auditcmp bsm channel service
NO_SHARED.session_test=	yes
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

.include <bsd.test.mk>

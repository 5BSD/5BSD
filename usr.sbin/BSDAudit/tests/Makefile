PACKAGE=	bsdaudit-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDAudit
.PATH:		${SRCTOP}/usr.sbin/BSDAudit

# Common daemon sources included by the tests use the public protocol APIs.
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
# auditcmp.c (shared across the test programs) uses <libservice.h>; the base
# compile of it needs the include too, not just the per-program CFLAGS below.
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	policy_test rate_test submit_test
ATF_TESTS_C+=	session_test
ATF_TESTS_SH+=	bundle_test
SRCS.policy_test=	policy_test.c auditcmp_policy.c
CFLAGS.policy_test+=	-I${SRCTOP}/usr.sbin/BSDAudit
CFLAGS.policy_test+=	-I${SRCTOP}/sys
# rate_test drives the parent per-label admission bucket (in auditcmp.c) via the
# AUDITCMP_TESTING hooks, so it compiles the daemon TU in its test configuration.
SRCS.rate_test=	rate_test.c auditcmp.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.rate_test+=	-DAUDITCMP_TESTING
CFLAGS.rate_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.rate_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.rate_test+=	-I${SRCTOP}/usr.sbin/BSDAudit
CFLAGS.rate_test+=	-I${SRCTOP}/sys
LIBADD.rate_test=	auditcmp channel service
NO_SHARED.rate_test=	yes
SRCS.submit_test=	submit_test.c auditcmp_submit.c
CFLAGS.submit_test+=	-I${SRCTOP}/usr.sbin/BSDAudit
CFLAGS.session_test+=	-DAUDITCMP_TESTING
CFLAGS.session_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.session_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.session_test+=	-I${SRCTOP}/usr.sbin/BSDAudit
CFLAGS.session_test+=	-I${SRCTOP}/sys
SRCS.session_test=	session_test.c auditcmp.c auditcmp_rate.c auditcmp_submit.c
LIBADD.session_test=	auditcmp bsm channel service
NO_SHARED.session_test=	yes
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	contrib/openbsm/etc/audit_event \
		contrib/openbsm/libbsm/bsm_wrappers.c \
		sys/bsm/audit_kevents.h \
		sys/kern/syscalls.master \
		sys/security/audit/audit_syscalls.c \
		usr.sbin/BSDAudit/auditcmp.c \
		usr.sbin/BSDAudit/auditcmp_policy.c \
		usr.sbin/BSDAudit/auditcmp_policy.h \
		usr.sbin/BSDAudit/bsdaudit_provider.d \
		usr.sbin/BSDAudit/capbundle/bsdaudit.ucl
.include "${SRCTOP}/tests/srctree.mk"

ATF_TESTS_C+= shutdown_test
SRCS.shutdown_test= shutdown_test.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.shutdown_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys
LIBADD.shutdown_test= auditcmp bsm channel service logcmp
NO_SHARED.shutdown_test= yes

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys
LIBADD.lifecycle_test= auditcmp bsm channel service logcmp
NO_SHARED.lifecycle_test= yes

ATF_TESTS_C+= bootstrap_test
SRCS.bootstrap_test= bootstrap_test.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.bootstrap_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys
LIBADD.bootstrap_test= auditcmp bsm channel service logcmp
NO_SHARED.bootstrap_test= yes

.include <bsd.test.mk>

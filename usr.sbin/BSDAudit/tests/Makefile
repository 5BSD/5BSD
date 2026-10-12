PACKAGE=	bsdaudit-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDAudit
# Production bindings for objects shared between programs (built with the
# global flags); next_peer uses its own bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.auditcmp} -I${SRCTOP}/lib/libfidl/include
.endif
.PATH:		${SRCTOP}/usr.sbin/BSDAudit

# Common daemon sources included by the tests use the public protocol APIs.
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
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
LIBADD.rate_test=	auditcmp fidl_bsd channel service
NO_SHARED.rate_test=	yes
SRCS.submit_test=	submit_test.c auditcmp_submit.c
CFLAGS.submit_test+=	-I${SRCTOP}/usr.sbin/BSDAudit
CFLAGS.session_test+=	-DAUDITCMP_TESTING
CFLAGS.session_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.session_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.session_test+=	-I${SRCTOP}/usr.sbin/BSDAudit
CFLAGS.session_test+=	-I${SRCTOP}/sys
SRCS.session_test=	session_test.c auditcmp.c auditcmp_rate.c auditcmp_submit.c
LIBADD.session_test=	auditcmp bsm fidl_bsd channel service
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
LIBADD.shutdown_test= auditcmp bsm fidl_bsd channel service logcmp
NO_SHARED.shutdown_test= yes

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys
LIBADD.lifecycle_test= auditcmp bsm fidl_bsd channel service logcmp
NO_SHARED.lifecycle_test= yes

ATF_TESTS_C+= bootstrap_test
SRCS.bootstrap_test= bootstrap_test.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.bootstrap_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys
LIBADD.bootstrap_test= auditcmp bsm fidl_bsd channel service logcmp
NO_SHARED.bootstrap_test= yes

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/auditcmp_next.fidl at bsd:2 (its own bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.evolution_test+= -DAUDITCMP_TESTING -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/libservice -I${SRCTOP}/usr.sbin/BSDAudit -I${SRCTOP}/sys
LIBADD.evolution_test= auditcmp bsm fidl_bsd channel service
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.auditcmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.auditcmp_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
NO_SHARED.next_peer= yes
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh);
# libchannel is linked shared so its USDT request probes reach dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_provider.c auditcmp_rate.c auditcmp_submit.c
CFLAGS.latency_bench+= -DAUDITCMP_TESTING -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/libservice -I${SRCTOP}/usr.sbin/BSDAudit -I${SRCTOP}/sys \
	-I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= auditcmp bsm fidl_bsd channel service

# Production bindings for everything except next_peer.
.for t in rate_test session_test shutdown_test lifecycle_test bootstrap_test evolution_test latency_bench
CFLAGS.${t}+= -I${FIDLGEN.auditcmp}
.endfor

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdaudit-tests/fuchsia

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	auditcmp
FIDL_SCHEMAS.auditcmp=	lib/libauditcmp/auditcmp.fidl
FIDL_LIBRARY.auditcmp=	bsd.audit.v1
FIDL_BINDINGS+=	auditcmp_next
FIDL_SCHEMAS.auditcmp_next=	usr.sbin/BSDAudit/tests/evolution/auditcmp_next.fidl
FIDL_LIBRARY.auditcmp_next=	bsd.audit.v1
FIDL_FLAGS.auditcmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

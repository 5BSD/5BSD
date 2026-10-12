PACKAGE=	bsdtrace-provider-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDTrace
# Production bindings for objects shared between programs (built with the
# global flags); next_peer uses its own bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.tracecmp} -I${SRCTOP}/lib/libfidl/include
.endif
.PATH:		${SRCTOP}/usr.sbin/BSDTrace
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include

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
LIBADD.session_test=	bsm tracecmp fidl_bsd channel service
NO_SHARED.session_test=	yes
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	lib/libtracecmp/tracecmp.c \
		lib/libtracecmp/tracecmp.fidl \
		lib/libtracecmp/tracecmp_provider.d \
		usr.sbin/BSDTrace/bsdtrace_provider.d \
		usr.sbin/BSDTrace/tracecmp.c \
		usr.sbin/BSDTrace/tracecmp_policy.h
.include "${SRCTOP}/tests/srctree.mk"

ATF_TESTS_C+= shutdown_test
SRCS.shutdown_test= shutdown_test.c tracecmp_policy.c
CFLAGS.shutdown_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice
CFLAGS.shutdown_test+= -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/liblogcmp
CFLAGS.shutdown_test+= -I${SRCTOP}/sys
LIBADD.shutdown_test= bsm tracecmp fidl_bsd channel service logcmp
NO_SHARED.shutdown_test= yes

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c tracecmp_policy.c
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/liblogcmp
CFLAGS.lifecycle_test+= -I${SRCTOP}/sys
LIBADD.lifecycle_test= bsm tracecmp fidl_bsd channel service logcmp
NO_SHARED.lifecycle_test= yes

ATF_TESTS_C+= bootstrap_test
SRCS.bootstrap_test= bootstrap_test.c tracecmp_policy.c
CFLAGS.bootstrap_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice
CFLAGS.bootstrap_test+= -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/liblogcmp
CFLAGS.bootstrap_test+= -I${SRCTOP}/sys
LIBADD.bootstrap_test= bsm tracecmp fidl_bsd channel service logcmp
NO_SHARED.bootstrap_test= yes


ATF_TESTS_C+= quota_test
CFLAGS.quota_test+= -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys -ffunction-sections -fdata-sections
LDFLAGS.quota_test+= -Wl,--gc-sections
NO_SHARED.quota_test= yes

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/tracecmp_next.fidl at bsd:2 (its own generated
# bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c tracecmp_policy.c
CFLAGS.evolution_test+= -DTRACECMP_TESTING -I${SRCTOP}/usr.sbin/BSDTrace \
	-I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/sys \
	-I${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common
LIBADD.evolution_test= bsm tracecmp dtrace fidl_bsd channel service logcmp
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.tracecmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.tracecmp_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
NO_SHARED.next_peer= yes
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh):
# the real client and per-session server; libchannel is linked shared so
# its USDT request probes are visible to dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_provider.c tracecmp_policy.c
CFLAGS.latency_bench+= -DTRACECMP_TESTING -I${SRCTOP}/usr.sbin/BSDTrace \
	-I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/sys \
	-I${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common \
	-I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= bsm tracecmp dtrace fidl_bsd channel service logcmp

# Production bindings for everything except next_peer.
.for t in session_test shutdown_test lifecycle_test bootstrap_test quota_test evolution_test latency_bench
CFLAGS.${t}+= -I${FIDLGEN.tracecmp}
.endfor

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdtrace-provider-tests/fuchsia

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	tracecmp
FIDL_SCHEMAS.tracecmp=	lib/libfidl/tests/zx.fidl \
	lib/libtracecmp/tracecmp.fidl
FIDL_LIBRARY.tracecmp=	bsd.trace.v1
FIDL_BINDINGS+=	tracecmp_next
FIDL_SCHEMAS.tracecmp_next=	lib/libfidl/tests/zx.fidl \
	usr.sbin/BSDTrace/tests/evolution/tracecmp_next.fidl
FIDL_LIBRARY.tracecmp_next=	bsd.trace.v1
FIDL_FLAGS.tracecmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

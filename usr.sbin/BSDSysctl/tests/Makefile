PACKAGE=	libsysctlcmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDSysctl
# Production bindings for objects shared between programs (built with the
# global flags); next_peer uses its own bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.sysctlcmp} -I${SRCTOP}/lib/libfidl/include
.endif

.PATH: ${.CURDIR}/.. ${.CURDIR}/evolution

CFLAGS+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_SH+=	observability_test
ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test=	ucl

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c bsdsysctl.c config.c interfaces.c
CFLAGS.provider_test+=	-DSYSCTLCMP_TESTING
CFLAGS.provider_test+=	-I${.CURDIR}/..
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	sysctlcmp fidl_bsd channel service ucl
NO_SHARED.provider_test=	yes
TEST_METADATA.provider_test+= timeout="120"

ATF_TESTS_SH_SED_observability_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	usr.sbin/BSDSysctl/capbundle/sysctl.conf \
		cddl/usr.sbin/bsdinstruments/profiles/capability-services.d \
		usr.sbin/BSDSysctl/bsdsysctl.c \
		usr.sbin/BSDSysctl/bsdsysctl_provider.d
.include "${SRCTOP}/tests/srctree.mk"

# The production reactor with real channels and clients.
ATF_TESTS_C+=	reactor_test
SRCS.reactor_test=	reactor_test.c config.c interfaces.c
CFLAGS.reactor_test+=	-I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libsysctlcmp
CFLAGS.reactor_test+=	-I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
LIBADD.reactor_test=	sysctlcmp fidl_bsd channel service ucl
NO_SHARED.reactor_test=	yes
TEST_METADATA.reactor_test+= timeout="120"

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/sysctlcmp_next.fidl at bsd:2 (its own bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c config.c interfaces.c
CFLAGS.evolution_test+= -DSYSCTLCMP_TESTING -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
LIBADD.evolution_test= sysctlcmp fidl_bsd channel service ucl
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.sysctlcmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.sysctlcmp_next}
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
SRCS.latency_bench= latency_bench.c latency_bench_provider.c config.c interfaces.c
CFLAGS.latency_bench+= -DSYSCTLCMP_TESTING -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/libservice -I${SRCTOP}/sys -I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= sysctlcmp fidl_bsd channel service ucl

# Production bindings for everything except next_peer.
.for t in provider_test reactor_test evolution_test latency_bench
CFLAGS.${t}+= -I${FIDLGEN.sysctlcmp} -I${SRCTOP}/lib/libfidl/include
.endfor

# Static tests embed upstream codec and UCL code.
FILESGROUPS+= FIDL_NOTICE UCL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libsysctlcmp-tests/fuchsia-bsdsysctl
UCL_NOTICE= ${SRCTOP}/contrib/libucl/COPYING
UCL_NOTICEDIR= /usr/share/licenses/libsysctlcmp-tests/libucl-bsdsysctl

ATF_TESTS_C+= interfaces_test
SRCS.interfaces_test= interfaces_test.c interfaces.c
CFLAGS.interfaces_test+= -I${SRCTOP}/lib/libsysctlcmp
NO_SHARED.interfaces_test= yes

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	sysctlcmp
FIDL_SCHEMAS.sysctlcmp=	lib/libsysctlcmp/sysctlcmp.fidl
FIDL_LIBRARY.sysctlcmp=	bsd.sysctl.v1
FIDL_BINDINGS+=	sysctlcmp_next
FIDL_SCHEMAS.sysctlcmp_next=	usr.sbin/BSDSysctl/tests/evolution/sysctlcmp_next.fidl
FIDL_LIBRARY.sysctlcmp_next=	bsd.sysctl.v1
FIDL_FLAGS.sysctlcmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

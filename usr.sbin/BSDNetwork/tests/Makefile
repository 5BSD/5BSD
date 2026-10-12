PACKAGE=	bsdnetwork-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDNetwork
# Production bindings for objects shared between programs (built with the
# global flags); next_peer uses its own bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.networkcmp} -I${SRCTOP}/lib/libfidl/include
.endif

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_C+=	resolver_test
SRCS.resolver_test=	resolver_test.c
LIBADD.resolver_test=	filesystemcmp service

# Actual recovery code, broker-open mock, real fork/Capsicum and descriptor I/O.
ATF_TESTS_C+=	resolver_recovery_test
CFLAGS.resolver_recovery_test+= -ffunction-sections -fdata-sections
LDFLAGS.resolver_recovery_test+= -Wl,--gc-sections

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c policy.c
CFLAGS.config_test+=	-I${SRCTOP}/sys
LIBADD.config_test=	ucl

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c networkcmp.c config.c policy.c resolver.c
CFLAGS.provider_test+=	-DNETWORKCMP_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp channel fidl_bsd networkcmp pthread filesystemcmp service ucl
NO_SHARED.provider_test=	yes

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	usr.sbin/BSDFilesystem/bsdfilesystem.ucl \
		usr.sbin/BSDNetwork/bsdnetwork_provider.d \
		usr.sbin/BSDNetwork/networkcmp.c \
		usr.sbin/BSDNetwork/resolver.c
.include "${SRCTOP}/tests/srctree.mk"

ATF_TESTS_C+= state_test
CFLAGS.state_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libnotify
CFLAGS.state_test+= -I${SRCTOP}/lib/libsysctlcmp -I${SRCTOP}/sys
LIBADD.state_test+= networkcmp fidl_bsd notify channel filesystemcmp service pthread
NO_SHARED.state_test= yes

ATF_TESTS_C+= state_plane_test
CFLAGS.state_plane_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libnotify
CFLAGS.state_plane_test+= -I${SRCTOP}/lib/libsysctlcmp -I${SRCTOP}/sys
LIBADD.state_plane_test+= networkcmp fidl_bsd notify channel filesystemcmp service pthread
NO_SHARED.state_plane_test= yes

ATF_TESTS_C+= state_sampler_test
CFLAGS.state_sampler_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libnotify
CFLAGS.state_sampler_test+= -I${SRCTOP}/lib/libsysctlcmp -I${SRCTOP}/sys
LIBADD.state_sampler_test+= networkcmp fidl_bsd notify channel filesystemcmp service pthread
NO_SHARED.state_sampler_test= yes

ATF_TESTS_C+= coalesce_test
SRCS.coalesce_test= coalesce_test.c config.c policy.c resolver.c
CFLAGS.coalesce_test+= -I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel
CFLAGS.coalesce_test+= -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/sys
LIBADD.coalesce_test+= auditcmp channel fidl_bsd networkcmp pthread filesystemcmp service ucl
NO_SHARED.coalesce_test= yes

ATF_TESTS_C+= connect_deadline_test
SRCS.connect_deadline_test= connect_deadline_test.c config.c policy.c resolver.c
CFLAGS.connect_deadline_test+= -I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel
CFLAGS.connect_deadline_test+= -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/sys
LIBADD.connect_deadline_test+= auditcmp channel fidl_bsd networkcmp pthread filesystemcmp service ucl
NO_SHARED.connect_deadline_test= yes


# Actual admission logic and real procdesc teardown; unused daemon paths drop.
ATF_TESTS_C+= worker_test
SRCS.worker_test= worker_test.c service_runtime.c
.PATH: ${SRCTOP}/lib/libservice
CFLAGS.worker_test+= ${CFLAGS.provider_test:N-DNETWORKCMP_TESTING} \
    -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/lib/libnotify \
    -I${SRCTOP}/lib/libsysctlcmp -ffunction-sections -fdata-sections
LIBADD.worker_test+= filesystemcmp service
LDFLAGS.worker_test+= -Wl,--gc-sections
NO_SHARED.worker_test= yes

# The state reactor runs over real capability channels (plane-on tier).
TEST_METADATA.state_test+= required_user="root"

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/networkcmp_next.fidl at bsd:2 (its own bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c config.c policy.c resolver.c
CFLAGS.evolution_test+= ${CFLAGS.provider_test}
LIBADD.evolution_test= ${LIBADD.provider_test}
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.networkcmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.networkcmp_next}
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
SRCS.latency_bench= latency_bench.c latency_bench_provider.c config.c policy.c resolver.c
CFLAGS.latency_bench+= ${CFLAGS.provider_test} -I${SRCTOP}/lib/libnetworkcmp \
	-I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= auditcmp channel fidl_bsd networkcmp pthread filesystemcmp service ucl

# Production bindings for everything except next_peer.
.for t in provider_test state_test state_plane_test state_sampler_test \
    coalesce_test connect_deadline_test worker_test evolution_test latency_bench
CFLAGS.${t}+= -I${FIDLGEN.networkcmp}
.endfor

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdnetwork-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	networkcmp
FIDL_SCHEMAS.networkcmp=	lib/libfidl/tests/zx.fidl \
	lib/libnetworkcmp/networkcmp.fidl
FIDL_LIBRARY.networkcmp=	bsd.network.v1
FIDL_BINDINGS+=	networkcmp_next
FIDL_SCHEMAS.networkcmp_next=	lib/libfidl/tests/zx.fidl \
	usr.sbin/BSDNetwork/tests/evolution/networkcmp_next.fidl
FIDL_LIBRARY.networkcmp_next=	bsd.network.v1
FIDL_FLAGS.networkcmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.PATH: ${.CURDIR}/evolution

.include <bsd.test.mk>

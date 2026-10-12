PACKAGE=	waspnest-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDVM
.PATH:		${SRCTOP}/usr.sbin/BSDVM

ATF_TESTS_C+=	registry_test
ATF_TESTS_C+=	provider_test

# The tests compile bsdvm.c itself with -DVMD_TESTING, which #ifndef-guards out
# main()/vmd_serve() and exposes the accept-loop statics (window registry,
# request validation, backlog clamp, per-client worker) as vmd_test_* wrappers.
# bsdvm.c is shared between the test programs, so it is built once with the
# common CFLAGS below rather than per-test CFLAGS.<name>.
CFLAGS+=	-DVMD_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDVM
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/sys
# Production bindings for everything except next_peer, which uses its own
# bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.vmcmp}
.endif

SRCS.registry_test=	registry_test.c bsdvm.c
LIBADD.registry_test=	vmcmp service channel pthread fidl_bsd
NO_SHARED.registry_test=	yes

# The real bsd.vm.v1 server in a forked child, driven by the generated client
# bindings and by hand-built frames.
SRCS.provider_test=	provider_test.c bsdvm.c
LIBADD.provider_test=	vmcmp service channel pthread fidl_bsd
NO_SHARED.provider_test=	yes
TEST_METADATA.provider_test+= timeout="120"

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c
LIBADD.lifecycle_test= vmcmp service channel pthread fidl_bsd
NO_SHARED.lifecycle_test= yes

ATF_TESTS_C+= serve_test
SRCS.serve_test= serve_test.c
LIBADD.serve_test= vmcmp service channel pthread fidl_bsd
NO_SHARED.serve_test= yes

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/vmcmp_next.fidl at bsd:2 (its own generated bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c
CFLAGS.evolution_test+= -I${SRCTOP}/lib/libvmcmp
LIBADD.evolution_test= vmcmp service channel pthread fidl_bsd
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.vmcmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.vmcmp_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
NO_SHARED.next_peer= yes
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh): the
# real client and per-session server in one process pair.  libchannel is
# linked shared so its USDT request probes are visible to dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_provider.c
CFLAGS.latency_bench+= -I${SRCTOP}/lib/libvmcmp \
	-I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= vmcmp service channel pthread fidl_bsd

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/waspnest-tests/fuchsia

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	vmcmp
FIDL_SCHEMAS.vmcmp=	lib/libfidl/tests/zx.fidl \
	lib/libvmcmp/vmcmp.fidl
FIDL_LIBRARY.vmcmp=	bsd.vm.v1
FIDL_BINDINGS+=	vmcmp_next
FIDL_SCHEMAS.vmcmp_next=	lib/libfidl/tests/zx.fidl \
	usr.sbin/BSDVM/tests/evolution/vmcmp_next.fidl
FIDL_LIBRARY.vmcmp_next=	bsd.vm.v1
FIDL_FLAGS.vmcmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

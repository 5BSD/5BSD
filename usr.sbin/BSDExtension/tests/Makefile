PACKAGE=	bsdextension-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDExtension
.PATH:		${SRCTOP}/usr.sbin/BSDExtension

# These suites link the bsdextension object compiled with -DBSDEXTENSION_TESTING: main()
# and the accept loop are compiled out, the pure-logic functions gain external
# linkage, and the test-only sysext_test_serve() entry point is exposed.  See
# usr.sbin/BSDExtension/bsdextension.h.  There is no runtime behavioural difference from a
# production build.
#
# bsdextension.c is shared by the test programs, so it is compiled once with the
# global flags below (per-program CFLAGS.<prog> would not reach a shared
# source).
CFLAGS+=	-DBSDEXTENSION_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDExtension
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libextensioncmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
# Production bindings for everything except next_peer, which uses its own
# bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.extensioncmp}
.endif
LIBADD+=	extensioncmp fidl_bsd service channel ucl pthread capreclaim logcmp
NO_SHARED=	yes

# allowlist_test: pure unit — the allow-list / name-validation / config-loader
# regression.  No capability plane, no kldload, no privilege.
ATF_TESTS_C+=		allowlist_test
SRCS.allowlist_test=	allowlist_test.c bsdextension.c policy.c reclaim.c

# provider_test: drives the real bsd.extension.v1 server over a public capability
# channel via sysext_test_serve(), with libextensioncmp and hand-built frames.
# Requires the channel syscall, but no privilege.
ATF_TESTS_C+= inherited_session_test
SRCS.inherited_session_test= inherited_session_test.c
TEST_METADATA.inherited_session_test+= timeout="15"

ATF_TESTS_C+=		provider_test
SRCS.provider_test=	provider_test.c bsdextension.c policy.c reclaim.c

# reclaim_test: pure unit — the module -> bundle owner map and the destroy
# decisions (shared module kept, found-already-loaded never unloaded, busy
# module retried) with the kldunload seam stubbed.  No plane, no privilege.
ATF_TESTS_C+=		reclaim_test
SRCS.reclaim_test=	reclaim_test.c bsdextension.c policy.c reclaim.c

ATF_TESTS_C+= policy_test
SRCS.policy_test= policy_test.c bsdextension.c policy.c reclaim.c

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/extensioncmp_next.fidl at bsd:2 (its own bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c policy.c \
	reclaim.c
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.extensioncmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.extensioncmp_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh): the
# real client and per-session worker in one process pair.  libchannel is
# linked shared so its USDT request probes are visible to dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_provider.c policy.c \
	reclaim.c
CFLAGS.latency_bench+= -I${SRCTOP}/tools/build/fuchsia
NO_SHARED.latency_bench= no

# Static tests embed upstream codec and UCL code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdextension-tests/fuchsia

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	extensioncmp
FIDL_SCHEMAS.extensioncmp=	lib/libextensioncmp/extensioncmp.fidl
FIDL_LIBRARY.extensioncmp=	bsd.extension.v1
FIDL_BINDINGS+=	extensioncmp_next
FIDL_SCHEMAS.extensioncmp_next=	\
	usr.sbin/BSDExtension/tests/evolution/extensioncmp_next.fidl
FIDL_LIBRARY.extensioncmp_next=	bsd.extension.v1
FIDL_FLAGS.extensioncmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

PACKAGE=	bsdnamespace-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDNamespace
.PATH:		${SRCTOP}/usr.sbin/BSDNamespace

ATF_TESTS_C+=	jailname_test
ATF_TESTS_C+=	provider_test
ATF_TESTS_C+=	reclaim_test

# The suites compile the daemon translation unit with -DBSDNAMESPACE_TESTING, which
# guards out main()/bsdnamespace_serve() and exposes the pure decision logic and the
# per-client bsd.namespace.v1 worker (see bsdnamespace_test.h).  jail_name_from_label
# needs SHA-256 (libmd); the descriptor helpers pull in libjail; the worker path
# uses the FIDL runtime over libchannel and the worker authority-drop path uses
# libservice.
CFLAGS+=	-DBSDNAMESPACE_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDNamespace
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libjail
CFLAGS+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
# Production bindings for everything except next_peer, which uses its own
# bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.namespacecmp}
.endif

_NSLIBS=	namespacecmp filesystemcmp fidl_bsd md jail channel service capreclaim \
		logcmp sysctlcmp

SRCS.jailname_test=	jailname_test.c bsdnamespace.c reclaim.c
LIBADD.jailname_test=	${_NSLIBS}
NO_SHARED.jailname_test=	yes

# The real bsd.namespace.v1 server in a forked child, driven by the generated
# client bindings and by hand-built frames.
SRCS.provider_test=	provider_test.c bsdnamespace.c reclaim.c
LIBADD.provider_test=	${_NSLIBS}
NO_SHARED.provider_test=	yes
TEST_METADATA.provider_test+= timeout="300"

SRCS.reclaim_test=	reclaim_test.c bsdnamespace.c reclaim.c
LIBADD.reclaim_test=	${_NSLIBS}
NO_SHARED.reclaim_test=	yes

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/namespacecmp_next.fidl at bsd:2 (its own bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c reclaim.c
CFLAGS.evolution_test+= -I${SRCTOP}/lib/libnamespacecmp
LIBADD.evolution_test= ${_NSLIBS} pthread
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.namespacecmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.namespacecmp_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
NO_SHARED.next_peer= yes
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh): the
# real client and per-session worker in one process pair.  libchannel is
# linked shared so its USDT request probes are visible to dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_provider.c reclaim.c
CFLAGS.latency_bench+= -I${SRCTOP}/lib/libnamespacecmp \
	-I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= ${_NSLIBS} pthread

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdnamespace-tests/fuchsia

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	namespacecmp
FIDL_SCHEMAS.namespacecmp=	lib/libfidl/tests/zx.fidl \
	lib/libnamespacecmp/namespacecmp.fidl
FIDL_LIBRARY.namespacecmp=	bsd.namespace.v1
FIDL_BINDINGS+=	namespacecmp_next
FIDL_SCHEMAS.namespacecmp_next=	lib/libfidl/tests/zx.fidl \
	usr.sbin/BSDNamespace/tests/evolution/namespacecmp_next.fidl
FIDL_LIBRARY.namespacecmp_next=	bsd.namespace.v1
FIDL_FLAGS.namespacecmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

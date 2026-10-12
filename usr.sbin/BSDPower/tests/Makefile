PACKAGE=	runtime-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDPower
# Production bindings for objects shared between programs (built with the
# global flags); next_peer uses its own bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.powercmp} -I${SRCTOP}/lib/libfidl/include
.endif

CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDPower
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

# FIDL provider tests compile BSDPower.c with -DBSDPOWER_TESTING (main()
# guarded out) and drive the real bsd.power.v1 server over a mac_capability
# channel with the real libpowercmp client.
POWER_FIDL_CFLAGS= -I${SRCTOP}/lib/libpowercmp \
	-I${SRCTOP}/lib/libfidl/include -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
POWER_FIDL_LIBADD= powercmp fidl_bsd channel service ucl

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c BSDPower.c config.c

ATF_TESTS_C+= lease_test
SRCS.lease_test= lease_test.c config.c
CFLAGS.lease_test+= -Wno-unused-function

ATF_TESTS_C+= reactor_test
SRCS.reactor_test= reactor_test.c reactor_impl.c config.c
LDFLAGS.reactor_test+= -Wl,--wrap=service_listener_fd \
    -Wl,--wrap=service_listener_accept -Wl,--wrap=service_provider_quiescing \
    -Wl,--wrap=service_provider_quiesce_complete

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/powercmp_next.fidl at bsd:2 (its own generated
# bindings; it must not see the production ones).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c config.c

# lease_test defines BSDPOWER_TESTING itself before including BSDPower.c.
.for test in provider_test reactor_test evolution_test
CFLAGS.${test}+= -DBSDPOWER_TESTING
.endfor
.for test in provider_test lease_test reactor_test evolution_test
CFLAGS.${test}+= ${POWER_FIDL_CFLAGS:N-DBSDPOWER_TESTING}
CFLAGS.${test}+= -I${FIDLGEN.powercmp}
LIBADD.${test}= ${POWER_FIDL_LIBADD}
NO_SHARED.${test}= yes
TEST_METADATA.${test}+= timeout="120"
.endfor
TEST_METADATA.reactor_test+= timeout="180"

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh):
# the real client and per-session server in one process pair.  libchannel is
# linked shared so its USDT request probes are visible to dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_provider.c config.c
CFLAGS.latency_bench+= -DBSDPOWER_TESTING ${POWER_FIDL_CFLAGS} \
	-I${FIDLGEN.powercmp} -I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= powercmp fidl_bsd channel service ucl

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.powercmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.powercmp_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
NO_SHARED.next_peer= yes
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# Static tests embed upstream codec and UCL code.
FILESGROUPS+= FIDL_NOTICE UCL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdpower-tests/fuchsia
UCL_NOTICE= ${SRCTOP}/contrib/libucl/COPYING
UCL_NOTICEDIR= /usr/share/licenses/bsdpower-tests/libucl

.PATH:	${SRCTOP}/usr.sbin/BSDPower ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	powercmp
FIDL_SCHEMAS.powercmp=	lib/libpowercmp/powercmp.fidl
FIDL_LIBRARY.powercmp=	bsd.power.v1
FIDL_BINDINGS+=	powercmp_next
FIDL_SCHEMAS.powercmp_next=	usr.sbin/BSDPower/tests/evolution/powercmp_next.fidl
FIDL_LIBRARY.powercmp_next=	bsd.power.v1
FIDL_FLAGS.powercmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

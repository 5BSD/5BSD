PACKAGE=	bsddevice-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDDevice
# Production bindings for objects shared between programs (built with the
# global flags); next_peer uses its own bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.devicecmp} -I${SRCTOP}/lib/libfidl/include
.endif

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libdevicecmp -I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include -I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
.PATH:		${.CURDIR}/..

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c
LIBADD.policy_test=	ucl
NO_SHARED.policy_test=	yes

# The real bsd.device.v1 server in a forked child, driven by the generated
# client bindings and by hand-built frames.
ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c bsddevice.c policy.c
CFLAGS.provider_test+=	-DBSDDEVICE_TESTING
LIBADD.provider_test=	devicecmp fidl_bsd channel service ucl
NO_SHARED.provider_test=	yes
TEST_METADATA.provider_test+= timeout="120"

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c policy.c
LIBADD.lifecycle_test= devicecmp fidl_bsd channel service ucl
NO_SHARED.lifecycle_test= yes

ATF_TESTS_C+= quota_test
CFLAGS.quota_test+= -ffunction-sections -fdata-sections
LDFLAGS.quota_test+= -Wl,--gc-sections
NO_SHARED.quota_test= yes

# Schema evolution: the real bsd:1 provider paired with next_peer, built from
# evolution/devicecmp_next.fidl at bsd:2 (its own generated bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c policy.c
CFLAGS.evolution_test+= -DBSDDEVICE_TESTING
LIBADD.evolution_test= devicecmp fidl_bsd channel service ucl
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.devicecmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.devicecmp_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
NO_SHARED.next_peer= yes
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# Production bindings for everything except next_peer.
.for t in provider_test lifecycle_test quota_test evolution_test
CFLAGS.${t}+= -I${FIDLGEN.devicecmp}
.endfor

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh):
# the real client and per-session server in one process pair.  libchannel is
# linked shared so its USDT request probes are visible to dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_provider.c policy.c
CFLAGS.latency_bench+= -DBSDDEVICE_TESTING \
	-I${FIDLGEN.devicecmp} -I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= devicecmp fidl_bsd channel service ucl pthread

# Static tests embed upstream codec and UCL code.
FILESGROUPS+= FIDL_NOTICE UCL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsddevice-tests/fuchsia
UCL_NOTICE= ${SRCTOP}/contrib/libucl/COPYING
UCL_NOTICEDIR= /usr/share/licenses/bsddevice-tests/libucl

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	devicecmp
FIDL_SCHEMAS.devicecmp=	lib/libfidl/tests/zx.fidl \
	lib/libdevicecmp/devicecmp.fidl
FIDL_LIBRARY.devicecmp=	bsd.device.v1
FIDL_BINDINGS+=	devicecmp_next
FIDL_SCHEMAS.devicecmp_next=	lib/libfidl/tests/zx.fidl \
	usr.sbin/BSDDevice/tests/evolution/devicecmp_next.fidl
FIDL_LIBRARY.devicecmp_next=	bsd.device.v1
FIDL_FLAGS.devicecmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

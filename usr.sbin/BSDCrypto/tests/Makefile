PACKAGE=	bsdcrypto-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDCrypto
# Production bindings for objects shared between programs (built with the
# global flags); next_peer uses its own bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.cryptocmp} -I${SRCTOP}/lib/libfidl/include
.endif

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include -I${SRCTOP}/lib/libchannel
.PATH:		${.CURDIR}/..

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c bsdcrypto.c policy.c
CFLAGS.provider_test+=	-DBSDCRYPTO_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libcryptocmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libcryptodesc
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp cryptocmp fidl_bsd channel cryptodesc service
NO_SHARED.provider_test=	yes
TEST_METADATA.provider_test+= timeout="180"

ATF_TESTS_SH+=	bundle_test

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	usr.sbin/BSDCrypto/Makefile \
		usr.sbin/BSDCrypto/bsdcrypto.c
.include "${SRCTOP}/tests/srctree.mk"

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c policy.c
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/libservice
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/liblogcmp
LIBADD.lifecycle_test= auditcmp cryptocmp fidl_bsd channel cryptodesc service logcmp capreclaim
NO_SHARED.lifecycle_test= yes


ATF_TESTS_C+= quota_test
CFLAGS.quota_test+= -I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys -I${SRCTOP}/lib/libcapreclaim -ffunction-sections -fdata-sections
LDFLAGS.quota_test+= -Wl,--gc-sections
NO_SHARED.quota_test= yes

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/cryptocmp_next.fidl at bsd:2 (its own bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c evolution_test_provider.c policy.c
CFLAGS.evolution_test+= -DBSDCRYPTO_TESTING -I${SRCTOP}/lib/libauditcmp \
	-I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/libservice
LIBADD.evolution_test= auditcmp cryptocmp fidl_bsd channel cryptodesc service
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.cryptocmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.cryptocmp_next}
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
SRCS.latency_bench= latency_bench.c latency_bench_provider.c policy.c
CFLAGS.latency_bench+= -DBSDCRYPTO_TESTING -I${SRCTOP}/lib/libauditcmp \
	-I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/libservice \
	-I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= auditcmp cryptocmp fidl_bsd channel cryptodesc service

# Production bindings for everything except next_peer.
.for t in provider_test lifecycle_test quota_test evolution_test latency_bench
CFLAGS.${t}+= -I${FIDLGEN.cryptocmp}
.endfor

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdcrypto-tests/fuchsia

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	cryptocmp
FIDL_SCHEMAS.cryptocmp=	lib/libfidl/tests/zx.fidl \
	lib/libcryptocmp/cryptocmp.fidl
FIDL_LIBRARY.cryptocmp=	bsd.crypto.v1
FIDL_BINDINGS+=	cryptocmp_next
FIDL_SCHEMAS.cryptocmp_next=	lib/libfidl/tests/zx.fidl \
	usr.sbin/BSDCrypto/tests/evolution/cryptocmp_next.fidl
FIDL_LIBRARY.cryptocmp_next=	bsd.crypto.v1
FIDL_FLAGS.cryptocmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

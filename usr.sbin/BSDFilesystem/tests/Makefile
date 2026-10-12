PACKAGE=	tzfs-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDFilesystem
.PATH:		${SRCTOP}/usr.sbin/BSDFilesystem

ATF_TESTS_C+=	namespace_test
ATF_TESTS_C+=	provider_test

# Both tests link the daemon's request-loop translation unit compiled with the
# BSDFILESYSTEM_TESTING hook, which exposes the file-private pure-logic functions and a
# single-channel serve entrypoint.  layout.c/nvwalk.c/config.c provide the
# symbols request.c references (bsdfilesystem_ensure_path, bsdfilesystem_destroy_tree,
# bsdfilesystem_session_begin, bsdfilesystem_nvl_names, and the config defaults); no ZFS work is
# performed by the cases we actually run.
BSDFILESYSTEM_SRCS=	request.c layout.c nvwalk.c config.c oes_factory.c oes_session.c
BSDFILESYSTEM_LIBADD=	trustedzfs ucl nvpair service channel md capreclaim logcmp \
			filesystemcmp oes fidl_bsd

# Shared daemon sources are compiled once with the same flags for both tests, so
# the include path and the BSDFILESYSTEM_TESTING hook live in the global CFLAGS rather
# than per-program (a per-program CFLAGS.<name> does not reach a source file
# shared across programs).
CFLAGS+=	-DBSDFILESYSTEM_TESTING \
		-I${SRCTOP}/usr.sbin/BSDFilesystem \
		-I${SRCTOP}/lib/libcapsulert \
		-I${SRCTOP}/lib/libtrustedzfs \
		-I${SRCTOP}/lib/libcapreclaim \
		-I${SRCTOP}/lib/liblogcmp \
		-I${SRCTOP}/lib/libservice \
		-I${SRCTOP}/lib/libchannel \
		-I${SRCTOP}/lib/libfidl/include \
		-I${FIDLGEN.oes_broker} \
		-I${SRCTOP}/sys \
		-I${SRCTOP}/contrib/libucl/include

# Production bindings for everything except next_peer, which uses its own
# bsd:2 bindings.
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.filesystemcmp}
.endif

SRCS.namespace_test=	namespace_test.c ${BSDFILESYSTEM_SRCS}
LIBADD.namespace_test=	${BSDFILESYSTEM_LIBADD}
NO_SHARED.namespace_test=	yes

SRCS.provider_test=	provider_test.c ${BSDFILESYSTEM_SRCS}
LIBADD.provider_test=	${BSDFILESYSTEM_LIBADD}
NO_SHARED.provider_test=	yes

ATF_TESTS_C+= oes_factory_test
SRCS.oes_factory_test= oes_factory_test.c oes_factory.c
LIBADD.oes_factory_test= service
NO_SHARED.oes_factory_test= yes

ATF_TESTS_C+= oes_factory_failure_test
NO_SHARED.oes_factory_failure_test= yes

ATF_TESTS_C+= oes_session_test
CFLAGS.oes_session_test+= -I${SRCTOP}/lib/liboes
LIBADD.oes_session_test= oes fidl_bsd channel service
NO_SHARED.oes_session_test= yes

ATF_TESTS_C+= oes_handoff_test
SRCS.oes_handoff_test= oes_handoff_test.c oes_session.c oes_factory.c
CFLAGS+= -I${SRCTOP}/lib/liboes
LIBADD.oes_handoff_test= oes fidl_bsd channel service
NO_SHARED.oes_handoff_test= yes

ATF_TESTS_C+= manifest_test
CFLAGS.manifest_test+= -I${SRCTOP}/lib/libcapbundle
LIBADD.manifest_test= capbundle
NO_SHARED.manifest_test= yes
# bsd.test.mk installs the ${PACKAGE}FILES group into ${TESTSDIR}; a plain
# FILES group is not in FILESGROUPS here and was never installed.  Name the
# capbundle unit explicitly: the .PATH above also has the daemon's
# configuration file of the same name.
${PACKAGE}FILES+= ${.CURDIR}/../capbundle/bsdfilesystem.ucl

ATF_TESTS_C+= cleanup_test
SRCS.cleanup_test= cleanup_test.c layout.c nvwalk.c config.c
LIBADD.cleanup_test= ${BSDFILESYSTEM_LIBADD}
NO_SHARED.cleanup_test= yes
.for symbol in tzfs_openat tzfs_info tzfs_list_children tzfs_list_snapshots tzfs_snap_destroy tzfs_destroy
LDFLAGS.cleanup_test+= -Wl,--wrap=${symbol}
.endfor


ATF_TESTS_C+= quota_test
CFLAGS.quota_test+= -I${SRCTOP}/lib/libfidl/include -I${FIDLGEN.filesystemcmp} -I${FIDLGEN.oes_broker} -I${SRCTOP}/lib/libcapsulert -I${SRCTOP}/lib/libtrustedzfs -I${SRCTOP}/lib/libcapreclaim -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys -I${SRCTOP}/lib/liboes -I${SRCTOP}/contrib/libucl/include -ffunction-sections -fdata-sections
LDFLAGS.quota_test+= -Wl,--gc-sections
NO_SHARED.quota_test= yes

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c layout.c nvwalk.c config.c oes_factory.c oes_session.c
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/liboes -ffunction-sections -fdata-sections
LDFLAGS.lifecycle_test+= -Wl,--gc-sections
LIBADD.lifecycle_test= ${BSDFILESYSTEM_LIBADD}
NO_SHARED.lifecycle_test= yes

# Schema evolution: the real bsd:1 client and provider paired with next_peer,
# built from evolution/filesystemcmp_next.fidl at bsd:2 (its own bindings).
ATF_TESTS_C+= evolution_test
SRCS.evolution_test= evolution_test.c ${BSDFILESYSTEM_SRCS}
LIBADD.evolution_test= ${BSDFILESYSTEM_LIBADD} pthread
NO_SHARED.evolution_test= yes
TEST_METADATA.evolution_test+= timeout="120"

PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.filesystemcmp_next}
CFLAGS.next_peer+= -I${FIDLGEN.filesystemcmp_next}
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
SRCS.latency_bench= latency_bench.c ${BSDFILESYSTEM_SRCS}
CFLAGS.latency_bench+= -I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= ${BSDFILESYSTEM_LIBADD} pthread

# Static tests embed upstream codec and UCL code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/tzfs-tests/fuchsia

.PATH: ${.CURDIR}/evolution

# Bindings generated at build time (fidl-bindings.mk); the generated code is
# linked from libfilesystemcmp and liboes.
FIDL_BINDINGS+=	filesystemcmp oes_broker
FIDL_SCHEMAS.filesystemcmp=	lib/libfidl/tests/zx.fidl \
	lib/libfilesystemcmp/filesystemcmp.fidl
FIDL_LIBRARY.filesystemcmp=	bsd.filesystem.v1
FIDL_SCHEMAS.oes_broker=	lib/libfidl/tests/zx.fidl \
	lib/liboes/oes_broker.fidl
FIDL_LIBRARY.oes_broker=	bsd.oes.v1
FIDL_BINDINGS+=	filesystemcmp_next
FIDL_SCHEMAS.filesystemcmp_next=	lib/libfidl/tests/zx.fidl \
	usr.sbin/BSDFilesystem/tests/evolution/filesystemcmp_next.fidl
FIDL_LIBRARY.filesystemcmp_next=	bsd.filesystem.v1
FIDL_FLAGS.filesystemcmp_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

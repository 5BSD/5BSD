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
BSDFILESYSTEM_LIBADD=	trustedzfs ucl nvpair service channel md capreclaim logcmp

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
		-I${SRCTOP}/sys \
		-I${SRCTOP}/contrib/libucl/include

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
LIBADD.oes_session_test= channel service
NO_SHARED.oes_session_test= yes

ATF_TESTS_C+= oes_handoff_test
SRCS.oes_handoff_test= oes_handoff_test.c oes_session.c oes_factory.c
CFLAGS+= -I${SRCTOP}/lib/liboes
LIBADD.oes_handoff_test= channel service
NO_SHARED.oes_handoff_test= yes

ATF_TESTS_C+= manifest_test
CFLAGS.manifest_test+= -I${SRCTOP}/lib/libcapbundle
LIBADD.manifest_test= capbundle
NO_SHARED.manifest_test= yes
.PATH: ${.CURDIR}/../capbundle
FILES+= bsdfilesystem.ucl
FILESDIR= ${TESTSDIR}

ATF_TESTS_C+= cleanup_test
SRCS.cleanup_test= cleanup_test.c layout.c nvwalk.c config.c
LIBADD.cleanup_test= ${BSDFILESYSTEM_LIBADD}
NO_SHARED.cleanup_test= yes
.for symbol in tzfs_openat tzfs_info tzfs_list_children tzfs_list_snapshots tzfs_snap_destroy tzfs_destroy
LDFLAGS.cleanup_test+= -Wl,--wrap=${symbol}
.endfor

.include <bsd.test.mk>

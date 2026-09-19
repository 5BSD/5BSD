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
BSDFILESYSTEM_SRCS=	request.c layout.c nvwalk.c config.c
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

.include <bsd.test.mk>

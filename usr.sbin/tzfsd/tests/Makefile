PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/usr.sbin/tzfsd
.PATH:		${SRCTOP}/usr.sbin/tzfsd

ATF_TESTS_C+=	namespace_test
ATF_TESTS_C+=	provider_test

# Both tests link the daemon's request-loop translation unit compiled with the
# TZFSD_TESTING hook, which exposes the file-private pure-logic functions and a
# single-channel serve entrypoint.  layout.c/nvwalk.c/config.c provide the
# symbols request.c references (tzfsd_ensure_path, tzfsd_destroy_tree,
# tzfsd_session_begin, tzfsd_nvl_names, and the config defaults); no ZFS work is
# performed by the cases we actually run.
TZFSD_SRCS=	request.c layout.c nvwalk.c config.c
TZFSD_LIBADD=	trustedzfs ucl nvpair service channel md

# Shared daemon sources are compiled once with the same flags for both tests, so
# the include path and the TZFSD_TESTING hook live in the global CFLAGS rather
# than per-program (a per-program CFLAGS.<name> does not reach a source file
# shared across programs).
CFLAGS+=	-DTZFSD_TESTING \
		-I${SRCTOP}/usr.sbin/tzfsd \
		-I${SRCTOP}/lib/libauthorityrt \
		-I${SRCTOP}/lib/libtrustedzfs \
		-I${SRCTOP}/lib/libservice \
		-I${SRCTOP}/lib/libchannel \
		-I${SRCTOP}/sys \
		-I${SRCTOP}/contrib/libucl/include

SRCS.namespace_test=	namespace_test.c ${TZFSD_SRCS}
LIBADD.namespace_test=	${TZFSD_LIBADD}
NO_SHARED.namespace_test=	yes

SRCS.provider_test=	provider_test.c ${TZFSD_SRCS}
LIBADD.provider_test=	${TZFSD_LIBADD}
NO_SHARED.provider_test=	yes

.include <bsd.test.mk>

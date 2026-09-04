PACKAGE=	sysextd-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/sysextd
.PATH:		${SRCTOP}/usr.sbin/sysextd

# Both suites link the sysextd object compiled with -DSYSEXTD_TESTING: main()
# and the accept loop are compiled out, the pure-logic functions gain external
# linkage, and the test-only sysext_test_serve() entry point is exposed.  See
# usr.sbin/sysextd/sysextd.h.  There is no runtime behavioural difference from a
# production build.
#
# sysextd.c is shared by both test programs, so it is compiled once with the
# global flags below (per-program CFLAGS.<prog> would not reach a shared
# source).
CFLAGS+=	-DSYSEXTD_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/sysextd
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD+=	service channel ucl
NO_SHARED=	yes

# allowlist_test: pure unit — the allow-list / name-validation / config-loader
# regression.  No capability plane, no kldload, no privilege.
ATF_TESTS_C+=		allowlist_test
SRCS.allowlist_test=	allowlist_test.c sysextd.c

# provider_test: plane — drives the real request handler over a real channel via
# sysext_test_serve().  Requires /dev/mac_capability + the stack kmods and root.
ATF_TESTS_C+=		provider_test
SRCS.provider_test=	provider_test.c sysextd.c

.include <bsd.test.mk>

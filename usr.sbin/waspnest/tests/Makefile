PACKAGE=	waspnest-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/waspnest
.PATH:		${SRCTOP}/usr.sbin/waspnest

ATF_TESTS_C+=	registry_test
ATF_TESTS_C+=	provider_test

# Both tests compile waspnest.c itself with -DVMD_TESTING, which #ifndef-guards out
# main()/vmd_serve() and exposes the accept-loop statics (window registry,
# request validation, backlog clamp, per-client worker) as vmd_test_* wrappers.
# waspnest.c is shared between the two test programs, so it is built once with the
# common CFLAGS below rather than per-test CFLAGS.<name>.
CFLAGS+=	-DVMD_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/waspnest
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys

SRCS.registry_test=	registry_test.c waspnest.c
LIBADD.registry_test=	service channel pthread
NO_SHARED.registry_test=	yes

SRCS.provider_test=	provider_test.c waspnest.c
LIBADD.provider_test=	service channel pthread
NO_SHARED.provider_test=	yes

.include <bsd.test.mk>

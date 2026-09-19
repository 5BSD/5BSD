PACKAGE=	warden-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDNamespace
.PATH:		${SRCTOP}/usr.sbin/BSDNamespace

ATF_TESTS_C+=	jailname_test
ATF_TESTS_C+=	provider_test
ATF_TESTS_C+=	reclaim_test

# Both suites compile the daemon translation unit with -DWARDEN_TESTING, which
# guards out main()/warden_serve() and exposes the pure decision logic and the
# per-client channel worker (see warden_test.h).  jail_name_from_label needs
# SHA-256 (libmd); the descriptor helpers pull in libjail; the worker path uses
# libchannel and the worker authority-drop path uses libservice.
CFLAGS+=	-DWARDEN_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDNamespace
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

SRCS.jailname_test=	jailname_test.c warden.c reclaim.c
LIBADD.jailname_test=	md jail channel service capreclaim logcmp
NO_SHARED.jailname_test=	yes

SRCS.provider_test=	provider_test.c warden.c reclaim.c
LIBADD.provider_test=	md jail channel service capreclaim logcmp
NO_SHARED.provider_test=	yes

SRCS.reclaim_test=	reclaim_test.c warden.c reclaim.c
LIBADD.reclaim_test=	md jail channel service capreclaim logcmp
NO_SHARED.reclaim_test=	yes

.include <bsd.test.mk>

PACKAGE=	warden-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/warden
.PATH:		${SRCTOP}/usr.sbin/warden

ATF_TESTS_C+=	jailname_test
ATF_TESTS_C+=	provider_test

# Both suites compile the daemon translation unit with -DWARDEN_TESTING, which
# guards out main()/warden_serve() and exposes the pure decision logic and the
# per-client channel worker (see warden_test.h).  jail_name_from_label needs
# SHA-256 (libmd); the descriptor helpers pull in libjail; the worker path uses
# libchannel.  No libservice: warden_serve (its only consumer) is compiled out.
CFLAGS+=	-DWARDEN_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/warden
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

SRCS.jailname_test=	jailname_test.c warden.c
LIBADD.jailname_test=	md jail channel
NO_SHARED.jailname_test=	yes

SRCS.provider_test=	provider_test.c warden.c
LIBADD.provider_test=	md jail channel service
NO_SHARED.provider_test=	yes

.include <bsd.test.mk>

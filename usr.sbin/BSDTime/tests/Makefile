PACKAGE=	runtime-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDTime

CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDTime
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

# Plane provider test: compiles BSDTime.c with -DBSDTIME_TESTING (main() guarded
# out) and drives the real per-session channel worker over a mac_capability
# channel.  Needs libtimecmp (protocol), libchannel (transport), libservice (the
# gate + session), and libucl (config).
ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c BSDTime.c config.c
CFLAGS.provider_test+=	-DBSDTIME_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libtimecmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	timecmp channel service ucl
NO_SHARED.provider_test=	yes

.PATH:	${SRCTOP}/usr.sbin/BSDTime

.include <bsd.test.mk>

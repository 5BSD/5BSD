PACKAGE=	runtime-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDPower

CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDPower
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

# Plane provider test: compiles BSDPower.c with -DBSDPOWER_TESTING (main()
# guarded out) and drives the real per-session channel worker over a
# mac_capability channel.  Needs libpowercmp (protocol), libchannel
# (transport), libservice (the session), and libucl (config).
ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c BSDPower.c config.c
CFLAGS.provider_test+=	-DBSDPOWER_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libpowercmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	powercmp channel service ucl
NO_SHARED.provider_test=	yes

.PATH:	${SRCTOP}/usr.sbin/BSDPower

.include <bsd.test.mk>

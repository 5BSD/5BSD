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

ATF_TESTS_C+= lease_test
SRCS.lease_test= lease_test.c config.c
CFLAGS.lease_test+= -I${SRCTOP}/lib/libpowercmp -I${SRCTOP}/lib/libservice
CFLAGS.lease_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys -Wno-unused-function
LIBADD.lease_test= powercmp channel service ucl
NO_SHARED.lease_test= yes


ATF_TESTS_C+= reactor_test
SRCS.reactor_test= reactor_test.c reactor_impl.c config.c
CFLAGS.reactor_test+= -DBSDPOWER_TESTING -I${SRCTOP}/lib/libpowercmp
CFLAGS.reactor_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
LIBADD.reactor_test= powercmp channel service ucl
NO_SHARED.reactor_test= yes
LDFLAGS.reactor_test+= -Wl,--wrap=service_listener_fd \
    -Wl,--wrap=service_listener_accept -Wl,--wrap=service_provider_quiescing \
    -Wl,--wrap=service_provider_quiesce_complete

.include <bsd.test.mk>

PACKAGE=	bsdtime-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDTime

CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDTime
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

# Drive the real C provider and C client with simulated gate writes on the host.
# The separate gate_test requires an explicitly selected disposable VM.
ATF_TESTS_C+= provider_test gate_test
CFLAGS+= -I${SRCTOP}/lib/libtimecmp -I${SRCTOP}/lib/libtimecmp/generated
CFLAGS+= -I${SRCTOP}/lib/libfidl/include -I${SRCTOP}/lib/libchannel
CFLAGS+= -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
# Explicit-duration auxiliary program; ordinary Kyua runs remain bounded.
PROGS+= resource_soak
BINDIR_resource_soak= ${TESTSDIR}
MAN.resource_soak=
.for test in provider_test gate_test resource_soak
SRCS.${test}= ${test}.c BSDTime.c config.c
CFLAGS.${test}+= -DBSDTIME_TESTING
LIBADD.${test}= timecmp fidl_bsd channel service ucl
NO_SHARED.${test}= yes
.endfor
TEST_METADATA.provider_test+= timeout="120"
TEST_METADATA.gate_test+= timeout="120"
LDFLAGS.resource_soak+= -Wl,--wrap=service_system_settime,--wrap=service_system_adjtime,--wrap=syslog
LIBADD.resource_soak+= pthread
LDFLAGS.provider_test+= -Wl,--wrap=service_system_settime,--wrap=service_system_adjtime

# Static provider tests embed upstream codec and UCL code.
FILESGROUPS+= FIDL_NOTICE UCL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdtime-tests/fuchsia
UCL_NOTICE= ${SRCTOP}/contrib/libucl/COPYING
UCL_NOTICEDIR= /usr/share/licenses/bsdtime-tests/libucl

.PATH: ${SRCTOP}/usr.sbin/BSDTime
.include <bsd.test.mk>

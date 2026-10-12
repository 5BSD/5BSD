PACKAGE=	libsysctlcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libsysctlcmp

CFLAGS+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS+=	-I${FIDLGEN.sysctlcmp}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

# Retained legacy record ABI plus client argument checks.
ATF_TESTS_C+=	sysctlcmp_test
SRCS.sysctlcmp_test=	sysctlcmp_test.c sysctlcmp_legacy.c
NO_SHARED.sysctlcmp_test=	yes
LIBADD.sysctlcmp_test+=	sysctlcmp fidl_bsd channel service

# The client against a scripted bsd.sysctl.v1 server.
ATF_TESTS_C+=	client_strings_test
SRCS.client_strings_test=	client_strings_test.c
NO_SHARED.client_strings_test=	yes
LIBADD.client_strings_test+=	sysctlcmp fidl_bsd channel service
TEST_METADATA.client_strings_test+= required_user="root" timeout="120"

.PATH: ${SRCTOP}/lib/libsysctlcmp

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libsysctlcmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	sysctlcmp
FIDL_SCHEMAS.sysctlcmp=	lib/libsysctlcmp/sysctlcmp.fidl
FIDL_LIBRARY.sysctlcmp=	bsd.sysctl.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

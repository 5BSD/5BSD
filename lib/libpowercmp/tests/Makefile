PACKAGE=	libpowercmp-tests
TESTSDIR=	${TESTSBASE}/lib/libpowercmp

CFLAGS+=	-I${SRCTOP}/lib/libpowercmp
CFLAGS+=	-I${FIDLGEN.powercmp}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

# Retained legacy validator ABI.
ATF_TESTS_C+=	protocol_test
SRCS.protocol_test=	protocol_test.c powercmp_legacy.c
NO_SHARED.protocol_test=	yes

.PATH: ${SRCTOP}/lib/libpowercmp

# The real client against a scripted bsd.power.v1 server.
ATF_TESTS_C+= client_test
NO_SHARED.client_test= yes
LIBADD.client_test+= powercmp fidl_bsd channel service
TEST_METADATA.client_test+= required_user="root" timeout="120"

# Includes ../powercmp.c with service_open faked.
ATF_TESTS_C+= constructor_test
NO_SHARED.constructor_test= yes
LIBADD.constructor_test+= powercmp fidl_bsd channel service

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libpowercmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	powercmp
FIDL_SCHEMAS.powercmp=	lib/libpowercmp/powercmp.fidl
FIDL_LIBRARY.powercmp=	bsd.power.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

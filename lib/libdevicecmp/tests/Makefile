PACKAGE=libdevicecmp-tests
TESTSDIR=${TESTSBASE}/lib/libdevicecmp

CFLAGS+=-I${SRCTOP}/lib/libdevicecmp
CFLAGS+=-I${FIDLGEN.devicecmp}
CFLAGS+=-I${SRCTOP}/lib/libfidl/include
CFLAGS+=-I${SRCTOP}/lib/libchannel
CFLAGS+=-I${SRCTOP}/lib/libservice
CFLAGS+=-I${SRCTOP}/sys

ATF_TESTS_C+=devicecmp_api_test
SRCS.devicecmp_api_test=devicecmp_api_test.c
NO_SHARED.devicecmp_api_test=yes
LIBADD.devicecmp_api_test=devicecmp fidl_bsd channel service pthread

# Includes ../devicecmp.c with service_open faked to reach a scripted server.
ATF_TESTS_C+=client_protocol_test
SRCS.client_protocol_test=client_protocol_test.c
NO_SHARED.client_protocol_test=yes
LIBADD.client_protocol_test=devicecmp fidl_bsd channel service pthread
TEST_METADATA.client_protocol_test+= required_user="root" timeout="120"

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libdevicecmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	devicecmp
FIDL_SCHEMAS.devicecmp=	lib/libfidl/tests/zx.fidl \
	lib/libdevicecmp/devicecmp.fidl
FIDL_LIBRARY.devicecmp=	bsd.device.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

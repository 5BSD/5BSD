PACKAGE=libcryptocmp-tests
TESTSDIR=${TESTSBASE}/lib/libcryptocmp

CFLAGS+=-I${SRCTOP}/lib/libcryptocmp
CFLAGS+=-I${FIDLGEN.cryptocmp}
CFLAGS+=-I${SRCTOP}/lib/libfidl/include
CFLAGS+=-I${SRCTOP}/lib/libchannel
CFLAGS+=-I${SRCTOP}/lib/libservice
CFLAGS+=-I${SRCTOP}/sys

ATF_TESTS_C+=cryptocmp_api_test
SRCS.cryptocmp_api_test=cryptocmp_api_test.c cryptocmp.c
NO_SHARED.cryptocmp_api_test=yes
LIBADD.cryptocmp_api_test=cryptocmp fidl_bsd channel service pthread

# The client against a scripted bsd.crypto.v1 provider (fake_service.c
# replaces service_open() with a real channel to an in-process server).
ATF_TESTS_C+=client_protocol_test
SRCS.client_protocol_test=client_protocol_test.c fake_service.c cryptocmp.c
NO_SHARED.client_protocol_test=yes
LIBADD.client_protocol_test=cryptocmp fidl_bsd channel pthread
TEST_METADATA.client_protocol_test+= required_user="root" timeout="120"

.PATH:${SRCTOP}/lib/libcryptocmp

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libcryptocmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	cryptocmp
FIDL_SCHEMAS.cryptocmp=	lib/libfidl/tests/zx.fidl \
	lib/libcryptocmp/cryptocmp.fidl
FIDL_LIBRARY.cryptocmp=	bsd.crypto.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

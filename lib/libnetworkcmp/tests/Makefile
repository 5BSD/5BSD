PACKAGE=	libnetworkcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libnetworkcmp
NO_SHARED=

CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${FIDLGEN.networkcmp}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

# Retained pre-FIDL record rules and argument checks before transport.
ATF_TESTS_C+=	networkcmp_test
SRCS.networkcmp_test=	networkcmp_test.c networkcmp_test_impl.c
LIBADD.networkcmp_test+=	networkcmp fidl_bsd channel pthread service

# The shared process client against a scripted bsd.network.v1 provider.
ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	networkcmp_client_impl.c
LIBADD.client_lifecycle_test+=	networkcmp fidl_bsd channel pthread
TEST_METADATA.client_lifecycle_test+= required_user="root" timeout="120"

# The NetworkState client against a scripted provider.
ATF_TESTS_C+= state_client_test
LIBADD.state_client_test+= networkcmp fidl_bsd channel pthread
TEST_METADATA.state_client_test+= required_user="root" timeout="120"

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libnetworkcmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	networkcmp
FIDL_SCHEMAS.networkcmp=	lib/libfidl/tests/zx.fidl \
	lib/libnetworkcmp/networkcmp.fidl
FIDL_LIBRARY.networkcmp=	bsd.network.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

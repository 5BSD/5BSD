PACKAGE=	libtracecmp-tests
TESTSDIR=	${TESTSBASE}/lib/libtracecmp
NO_SHARED=

# Legacy record ABI, argument validation and buffer tuning.
ATF_TESTS_C+=	tracecmp_test
SRCS.tracecmp_test=	tracecmp_test.c tracecmp_test_impl.c tracecmp_legacy.c
LIBADD.tracecmp_test=	tracecmp dtrace service fidl_bsd channel
CFLAGS.tracecmp_test+=	-DTRACECMP_TESTING

# The client against a scripted bsd.trace.v1 provider over real channels.
ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	tracecmp_test_impl.c
LIBADD.client_lifecycle_test=	tracecmp dtrace fidl_bsd channel pthread
TEST_METADATA.client_lifecycle_test+= required_user="root" timeout="120"

CFLAGS+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS+=	-I${FIDLGEN.tracecmp}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common

.PATH: ${SRCTOP}/lib/libtracecmp

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libtracecmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	tracecmp
FIDL_SCHEMAS.tracecmp=	lib/libfidl/tests/zx.fidl \
	lib/libtracecmp/tracecmp.fidl
FIDL_LIBRARY.tracecmp=	bsd.trace.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

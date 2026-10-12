PACKAGE=	liblogcmp-tests
TESTSDIR=	${TESTSBASE}/lib/liblogcmp
NO_SHARED=

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${FIDLGEN.logcmp}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
CFLAGS+=	-I${SRCTOP}/sys

# Record rules (shared by both peers) and argument checks.
ATF_TESTS_C+=	logcmp_test
SRCS.logcmp_test=	logcmp_test.c logcmp.c logcmp_wakeup.c
LIBADD.logcmp_test+=	logcmp fidl_bsd channel pthread service shmring

# The process client against a scripted bsd.log.v1 provider over real
# channels; the provider maps and drains an attached ring.
ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c logcmp_client_impl.c \
	logcmp_wakeup.c fake_service.c
LIBADD.client_lifecycle_test+=	logcmp fidl_bsd channel pthread shmring
TEST_METADATA.client_lifecycle_test+= required_user="root" timeout="300"
.PATH:	${.CURDIR}/..

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/liblogcmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	logcmp
FIDL_SCHEMAS.logcmp=	lib/libfidl/tests/zx.fidl \
	lib/liblogcmp/logcmp.fidl
FIDL_LIBRARY.logcmp=	bsd.log.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

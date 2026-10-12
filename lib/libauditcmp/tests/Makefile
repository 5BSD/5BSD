PACKAGE=	libauditcmp-tests
TESTSDIR=	${TESTSBASE}/lib/libauditcmp

CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${FIDLGEN.auditcmp}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

# Retained legacy record rules (shared by both peers) and API checks.
ATF_TESTS_C+=	auditcmp_test
SRCS.auditcmp_test=	auditcmp_test.c auditcmp.c auditcmp_legacy.c
NO_SHARED.auditcmp_test=	yes
LIBADD.auditcmp_test+=	auditcmp fidl_bsd channel service pthread

# The client against a scripted bsd.audit.v1 provider over real channels.
ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c fake_service.c \
	auditcmp.c auditcmp_legacy.c
NO_SHARED.client_lifecycle_test=	yes
LIBADD.client_lifecycle_test+=	auditcmp fidl_bsd channel pthread
TEST_METADATA.client_lifecycle_test+= required_user="root" timeout="120"

.PATH: ${SRCTOP}/lib/libauditcmp

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libauditcmp-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	auditcmp
FIDL_SCHEMAS.auditcmp=	lib/libauditcmp/auditcmp.fidl
FIDL_LIBRARY.auditcmp=	bsd.audit.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

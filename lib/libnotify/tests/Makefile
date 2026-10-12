PACKAGE=	libnotify-tests
TESTSDIR=	${TESTSBASE}/lib/libnotify
NO_SHARED=

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${FIDLGEN.notify}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

# Retained record rules, topic rules and argument checks before transport.
ATF_TESTS_C+=	notify_test
SRCS.notify_test=	notify_test.c notify.c notify_legacy.c
LIBADD.notify_test+=	notify fidl_bsd channel pthread service

# The client against a scripted bsd.notify.v1 provider over real channels.
ATF_TESTS_C+=	client_lifecycle_test
SRCS.client_lifecycle_test=	client_lifecycle_test.c \
	notify_client_impl.c fake_service.c
LIBADD.client_lifecycle_test+=	notify fidl_bsd channel pthread
TEST_METADATA.client_lifecycle_test+= required_user="root" timeout="120"
ATF_TESTS_C+=	watch_test
LIBADD.watch_test+=	pthread

.PATH:	${.CURDIR}/..

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libnotify-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	notify
FIDL_SCHEMAS.notify=	lib/libnotify/notify.fidl
FIDL_LIBRARY.notify=	bsd.notify.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

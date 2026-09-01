.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	service
SHLIB_MAJOR=	2
MAN=	libservice.3
MLINKS+=	libservice.3 service_acquire.3
MLINKS+=	libservice.3 service_release.3
MLINKS+=	libservice.3 service_authorize_capabilities.3
MLINKS+=	libservice.3 service_enter_capability_mode.3
MLINKS+=	libservice.3 service_ready.3
MLINKS+=	libservice.3 service_provider_create.3
MLINKS+=	libservice.3 service_provider_destroy.3
MLINKS+=	libservice.3 service_provider_authorize_capabilities.3
MLINKS+=	libservice.3 service_provider_worker_channel.3
MLINKS+=	libservice.3 service_provider_protect.3
MLINKS+=	libservice.3 service_provider_expose.3
MLINKS+=	libservice.3 service_provider_expose_sendable.3
MLINKS+=	libservice.3 service_provider_expose_lazy.3
MLINKS+=	libservice.3 service_provider_enter_capability_mode.3
MLINKS+=	libservice.3 service_provider_ready.3
MLINKS+=	libservice.3 service_connect.3
MLINKS+=	libservice.3 service_supervisor_fd.3
MLINKS+=	libservice.3 service_supervisor_status.3
MLINKS+=	libservice.3 service_label.3
MLINKS+=	libservice.3 service_capability_open.3
MLINKS+=	libservice.3 service_storage_open.3
MLINKS+=	libservice.3 service_helper_open.3
MLINKS+=	libservice.3 service_listener_fd.3
MLINKS+=	libservice.3 service_listener_close.3
MLINKS+=	libservice.3 service_listener_accept.3
MLINKS+=	libservice.3 service_session_create.3
MLINKS+=	libservice.3 service_session_fail.3
MLINKS+=	libservice.3 service_session_close.3
MLINKS+=	libservice.3 service_session_call.3
MLINKS+=	libservice.3 service_session_receive_event.3
MLINKS+=	libservice.3 service_worker_protect.3
MLINKS+=	libservice.3 service_worker_drop_inherited_authority.3

SRCS=	libservice.c service_ambient.c service_client.c
INCS=	libservice.h
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs	# tzfs_mount() for service_storage_open()
LIBADD=	capability channel pthread trustedzfs

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapability
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt

.include <bsd.lib.mk>

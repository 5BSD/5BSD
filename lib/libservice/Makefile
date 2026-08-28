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
MLINKS+=	libservice.3 service_provider_expose_lazy.3
MLINKS+=	libservice.3 service_provider_enter_capability_mode.3
MLINKS+=	libservice.3 service_provider_ready.3
MLINKS+=	libservice.3 service_connect.3
MLINKS+=	libservice.3 service_supervisor_fd.3
MLINKS+=	libservice.3 service_supervisor_status.3
MLINKS+=	libservice.3 service_label.3
MLINKS+=	libservice.3 service_capability_open.3
MLINKS+=	libservice.3 service_local_component_open.3
MLINKS+=	libservice.3 service_listener_fd.3
MLINKS+=	libservice.3 service_listener_close.3
MLINKS+=	libservice.3 service_listener_accept.3
MLINKS+=	libservice.3 service_session_create.3
MLINKS+=	libservice.3 service_session_fail.3
MLINKS+=	libservice.3 service_session_close.3
MLINKS+=	libservice.3 service_session_call.3
MLINKS+=	libservice.3 service_session_receive_event.3
MLINKS+=	libservice.3 service_component_accept.3
MLINKS+=	libservice.3 service_component_name.3
MLINKS+=	libservice.3 service_component_interface.3
MLINKS+=	libservice.3 service_component_interface_version.3
MLINKS+=	libservice.3 service_component_client_label.3
MLINKS+=	libservice.3 service_component_instance_id.3
MLINKS+=	libservice.3 service_component_resource_count.3
MLINKS+=	libservice.3 service_component_take_resource.3
MLINKS+=	libservice.3 service_component_complete.3
MLINKS+=	libservice.3 service_component_fail.3
MLINKS+=	libservice.3 service_component_abort.3
MLINKS+=	libservice.3 service_worker_protect.3
MLINKS+=	libservice.3 service_worker_drop_inherited_authority.3

SRCS=	component_request.c libservice.c service_ambient.c service_client.c
INCS=	libservice.h
LIBADD=	capability channel pthread

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapability
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt

.include <bsd.lib.mk>

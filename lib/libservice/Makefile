.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	service
SHLIB_MAJOR=	2
MAN=	libservice.3 service_runtime.3
MLINKS+= service_runtime.3 service_bootstrap_parent.3
# Shared provider runtime policy entry points.
.for api in service_monotime_ms service_retry_init service_retry_ready \
    service_retry_result service_health_record service_budget_begin \
    service_budget_end service_budget_timeout service_drain_wait \
    service_channels_wait service_lease_set_create service_lease_set_destroy \
    service_lease_acquire service_lease_release service_lease_release_owner \
    service_lease_count service_processes_stop
MLINKS+= service_runtime.3 ${api}.3
.endfor
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
MLINKS+=	libservice.3 service_idle_shutdown.3
MLINKS+=	libservice.3 service_activation_socket.3

SRCS=	service_runtime.c libservice.c service_ambient.c service_client.c
# USDT probes for the ambient discovery path (private-vs-fallback visibility).
.if ${MK_DTRACE} != "no"
SRCS+=	service_ambient_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif
INCS=	service_runtime.h libservice.h libservice_session.h
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs	# tzfs_mount() for service_storage_open()
LIBADD=	capability channel pthread trustedzfs capsulert

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapability
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert

.include <bsd.lib.mk>

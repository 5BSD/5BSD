.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	service
# 4: IPC anointments v1 (docs/ipc-anointments-design.md).  Wire structs
# changed — switchboard proto 13 (svc_new_client_msg identity fields,
# svc_mint_domain_req anointment set), authagent proto 2, and the public
# service_identity / service_message_metadata field layouts.  Every peer
# (switchboard, authagentd, the capability daemons, login/su/sshd) must be
# rebuilt together; mixed versions are not supported.
SHLIB_MAJOR=	4
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
MLINKS+=	libservice.3 service_session_extension_load.3
MLINKS+=	libservice.3 service_session_extension_stat.3
MLINKS+=	libservice.3 service_session_extension_list.3
MLINKS+=	libservice.3 service_session_extension_reload.3
MLINKS+=	libservice.3 service_session_fail.3
MLINKS+=	libservice.3 service_session_close.3
MLINKS+=	libservice.3 service_session_call.3
MLINKS+=	libservice.3 service_session_receive_event.3
MLINKS+=	libservice.3 service_worker_protect.3
MLINKS+=	libservice.3 service_worker_drop_inherited_authority.3
MLINKS+=	libservice.3 service_idle_shutdown.3
MLINKS+=	libservice.3 service_storage_open_quota.3
MLINKS+=	libservice.3 service_storage_destroy.3
MLINKS+=	libservice.3 service_storage_list.3
MLINKS+=	libservice.3 service_open_config.3
MLINKS+=	libservice.3 service_open_isolated.3
MLINKS+=	libservice.3 service_enter_namespace.3
MLINKS+=	libservice.3 service_enter_namespace_ex.3
MLINKS+=	libservice.3 service_destroy_namespace.3
MLINKS+=	libservice.3 service_namespace_info.3
MLINKS+=	libservice.3 service_ensure_extension.3
MLINKS+=	libservice.3 service_extension_stat.3
MLINKS+=	libservice.3 service_extension_list.3
MLINKS+=	libservice.3 service_vsock_listen.3
MLINKS+=	libservice.3 service_vsock_connect.3
MLINKS+=	libservice.3 service_vsock_list.3
MLINKS+=	libservice.3 service_activation_socket.3

SRCS=	service_reclaim.c libservice.c service_ambient.c service_client.c service_extension.c
# USDT probes for the ambient discovery path (private-vs-fallback visibility).
.if ${MK_DTRACE} != "no"
SRCS+=	service_ambient_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif
INCS=	libservice.h
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs	# tzfs_mount() for service_storage_open()
LIBADD=	capability channel pthread trustedzfs capsulert

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapability
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert

.include <bsd.lib.mk>

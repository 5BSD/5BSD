PACKAGE=	mac_capability
.PATH: ${SRCTOP}/sys/dev/mac_capability

KMOD=	mac_capability
SRCS=	mac_capability_core.c mac_capability_dev.c mac_capability_kern.c mac_capability_label.c

EXPORT_SYMS=	mac_capability_service_create	\
		mac_capability_service_destroy	\
		mac_capability_reply		\
		mac_capability_notify		\
		mac_capability_forward		\
		mac_capability_instance_revoke	\
		mac_capability_instance_hold	\
		mac_capability_instance_rele	\
		mac_capability_instance_kick	\
		mac_capability_instance_set_priv	\
		mac_capability_instance_get_priv	\
		mac_capability_instance_get_badge	\
		mac_capability_mint_fp		\
		mac_capability_msg_data		\
		mac_capability_msg_datalen	\
		mac_capability_msg_fds		\
		mac_capability_msg_fcaps		\
		mac_capability_msg_nfds		\
		mac_capability_msg_badge		\
		mac_capability_msg_token		\
		mac_capability_msg_cred		\
		mac_capability_proc_nonce

.include <bsd.kmod.mk>

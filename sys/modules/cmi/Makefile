.PATH: ${SRCTOP}/sys/dev/cmi

KMOD=	cmi
SRCS=	cmi_core.c cmi_dev.c cmi_kern.c

EXPORT_SYMS=	cmi_service_create	\
		cmi_service_destroy	\
		cmi_reply		\
		cmi_notify		\
		cmi_instance_revoke	\
		cmi_instance_hold	\
		cmi_instance_rele	\
		cmi_instance_set_priv	\
		cmi_instance_get_priv	\
		cmi_instance_get_badge	\
		cmi_instance_get_id	\
		cmi_mint_fp		\
		cmi_msg_data		\
		cmi_msg_datalen	\
		cmi_msg_fds		\
		cmi_msg_fcaps		\
		cmi_msg_nfds		\
		cmi_msg_badge		\
		cmi_msg_token		\
		cmi_msg_cred		\
		cmi_msg_pid		\
		cmi_send

.include <bsd.kmod.mk>

.PATH: ${SRCTOP}/sys/dev/cap_rt

KMOD=	cap_rt
SRCS=	cap_rt_core.c cap_rt_dev.c cap_rt_kern.c

EXPORT_SYMS=	cap_rt_service_create	\
		cap_rt_service_destroy	\
		cap_rt_reply		\
		cap_rt_notify		\
		cap_rt_forward		\
		cap_rt_instance_revoke	\
		cap_rt_instance_hold	\
		cap_rt_instance_rele	\
		cap_rt_instance_set_priv	\
		cap_rt_instance_get_priv	\
		cap_rt_instance_get_badge	\
		cap_rt_mint_fp		\
		cap_rt_msg_data		\
		cap_rt_msg_datalen	\
		cap_rt_msg_fds		\
		cap_rt_msg_fcaps		\
		cap_rt_msg_nfds		\
		cap_rt_msg_badge		\
		cap_rt_msg_token		\
		cap_rt_msg_cred		\
		cap_rt_proc_nonce

.include <bsd.kmod.mk>

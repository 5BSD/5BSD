.PATH: ${SRCTOP}/sys/security/mac_abac

PACKAGE=	mac-abac
KMOD=	mac_abac
SRCS=	vnode_if.h \
	abac_cred.c \
	abac_kenv.c \
	abac_label.c \
	abac_match.c \
	abac_pipe.c \
	abac_posixsem.c \
	abac_posixshm.c \
	abac_proc.c \
	abac_rules.c \
	abac_socket.c \
	abac_syscall.c \
	abac_system.c \
	abac_sysv.c \
	abac_vnode.c \
	abac_dtrace.h \
	mac_abac.h \
	mac_abac.c

.include <bsd.kmod.mk>

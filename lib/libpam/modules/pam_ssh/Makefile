# PAM module for SSH

SSHDIR=	${SRCTOP}/crypto/openssh

PACKAGE=	ssh

LIB=		pam_ssh
MANNODEV=	pam_ssh.8
SRCS=		pam_ssh.c

WARNS?=	5
CFLAGS+= -I${SSHDIR} -include ssh_namespace.h
SRCS+=	 ssh_namespace.h

LIBADD=	ssh

.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	pam_ssh_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.lib.mk>

.PATH: ${SSHDIR}

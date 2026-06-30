.include <src.opts.mk>

PROG=	blued
SRCS=	blued.c att.c att_server.c config.c conn.c ctl.c gatt.c hci_util.c hci_log.c smp.c

PACKAGE=	bluetooth

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

LIBADD=	bluetooth crypto pthread service ucl util

.if ${MK_DTRACE} != "no"
SRCS+=		blued_provider.d
CFLAGS+=	-I${.OBJDIR}
CFLAGS+=	-DWITH_DTRACE
.endif

.if ${MK_AUDIT} != "no"
CFLAGS+=	-DUSE_BSM_AUDIT
LIBADD+=	bsm
.endif

MAN=	blued.8

CONFS=	blued.conf.sample
CONFSDIR=	${SHAREDIR}/examples/blued

DIRS=	BLUED_DBDIR
BLUED_DBDIR=	/var/db/blued
BLUED_DBDIR_MODE=	0700

WARNS?=	6

.include <bsd.prog.mk>

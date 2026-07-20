.include <src.opts.mk>

PROG=	blued
SRCS=	blued.c blued_event.c blued_central.c blued_peripheral.c hogp_report.c \
	att.c att_server.c att_server_dispatch.c att_server_notify.c \
	att_server_hash.c config.c conn.c blued_persist.c blued_devmgr.c \
	ctl.c ctl_conn.c ctl_gatt.c ctl_iso.c iso.c \
	adv_builder.c \
	gatt.c hci_util.c hci_adv.c hci_scan.c hci_conn.c hogp_boot.c \
	hci_privacy.c hci_misc.c hci_log.c \
	smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c

PACKAGE=	bluetooth

BLUED_CAP=	/Capabilities/System/Blued.cap
BLUED_CAP_BIN=	${BLUED_CAP}/bin
BLUED_CAP_ETC=	${BLUED_CAP}/etc

DIRS+=	BLUED_CAP BLUED_CAP_BIN BLUED_CAP_ETC
BLUED_CAPPACKAGE=	${PACKAGE}
BLUED_CAP_BINPACKAGE=	${PACKAGE}
BLUED_CAP_ETCPACKAGE=	${PACKAGE}

BINDIR=	${BLUED_CAP_BIN}
SYMLINKS=	${BLUED_CAP_BIN}/blued /usr/sbin/blued

FILESGROUPS+=	SERVICES
SERVICES=	blued.ucl
SERVICESDIR=	${BLUED_CAP_ETC}

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/lib/libble
CFLAGS+=	-I${SRCTOP}/lib/libservice

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

DIRS+=	BLUED_DBDIR
BLUED_DBDIR=	/var/db/blued
BLUED_DBDIR_MODE=	0700

WARNS?=	6

.include <bsd.prog.mk>

_proginstall: installdirs-BLUED_CAP_BIN

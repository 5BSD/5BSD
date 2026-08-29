.include <src.opts.mk>

PROG=	blued
PROGNAME=	Bluetooth
SRCS=	blued.c blued_event.c blued_central.c blued_peripheral.c hogp_report.c \
	att.c att_server.c att_server_dispatch.c att_server_notify.c \
	att_server_hash.c config.c conn.c blued_persist.c blued_devmgr.c \
	ctl.c ctl_conn.c ctl_gatt.c ctl_iso.c iso.c \
	adv_builder.c \
	gatt.c hci_util.c hci_adv.c hci_scan.c hci_conn.c hogp_boot.c \
	hci_privacy.c hci_misc.c hci_log.c \
	smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c

PACKAGE=	bluetooth

BLUED_CAP=	/Capabilities/System/Bluetooth.cap
BLUED_CAP_UNITS=	${BLUED_CAP}/Units
BLUED_CAP_UNIT=	${BLUED_CAP_UNITS}/blued.unit
BLUED_CAP_BIN=	${BLUED_CAP_UNIT}/bin
BLUED_CAP_CONFIG=	${BLUED_CAP_UNIT}/Config

DIRS+=	BLUED_CAP BLUED_CAP_UNITS BLUED_CAP_UNIT BLUED_CAP_BIN \
	BLUED_CAP_CONFIG
BLUED_CAPPACKAGE=	${PACKAGE}
BLUED_CAP_BINPACKAGE=	${PACKAGE}
BLUED_CAP_UNITSPACKAGE=	${PACKAGE}
BLUED_CAP_UNITPACKAGE=	${PACKAGE}
BLUED_CAP_CONFIGPACKAGE=	${PACKAGE}

BINDIR=	${BLUED_CAP_BIN}
SYMLINKS=	${BLUED_CAP_BIN}/blued /usr/sbin/blued

FILESGROUPS+=	CAP_BUNDLE CAP_UNIT CAP_CONFIG
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${BLUED_CAP}
CAP_BUNDLEMODE=	0444
CAP_UNIT=	blued.ucl
CAP_UNITDIR=	${BLUED_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_CONFIG=	blued.conf.sample
CAP_CONFIGDIR=	${BLUED_CAP_CONFIG}
CAP_CONFIGNAME=	blued.conf
CAP_CONFIGMODE=	0444

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

WARNS?=	6

.include <bsd.prog.mk>

_proginstall: installdirs-BLUED_CAP_BIN

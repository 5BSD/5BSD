.include <src.opts.mk>

PACKAGE=bsddevice
PROG=	BSDDevice
MAN=BSDDevice.8
SRCS=bsddevice.c policy.c
CFLAGS+=-I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libdevicecmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
CFLAGS+=-I${SRCTOP}/contrib/libucl/include
LIBADD=channel devicecmp service ucl
# Resolve every dynamic symbol at load (BIND_NOW) so nothing is bound lazily
# after the daemon has entered capability mode.
LDFLAGS+=	-Wl,-z,now

DIRS+=DEVICECMP_CAP DEVICECMP_CAP_UNITS DEVICECMP_CAP_UNIT DEVICECMP_CAP_BIN \
	DEVICECMP_CAP_CONFIG
DEVICECMP_CAP=/Capabilities/System/Device.cap
DEVICECMP_CAPPACKAGE=bsddevice
DEVICECMP_CAP_UNITS=${DEVICECMP_CAP}/Units
DEVICECMP_CAP_UNITSPACKAGE=bsddevice
DEVICECMP_CAP_UNIT=${DEVICECMP_CAP_UNITS}/bsddevice.unit
DEVICECMP_CAP_UNITPACKAGE=bsddevice
DEVICECMP_CAP_BIN=${DEVICECMP_CAP_UNIT}/bin
DEVICECMP_CAP_BINPACKAGE=bsddevice
DEVICECMP_CAP_CONFIG=${DEVICECMP_CAP_UNIT}/Config
DEVICECMP_CAP_CONFIGPACKAGE=bsddevice
BINDIR=${DEVICECMP_CAP_BIN}

FILESGROUPS+=CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=capbundle/Bundle.ucl
CAP_BUNDLEDIR=${DEVICECMP_CAP}
CAP_BUNDLEMODE=0444
CAP_BUNDLEPACKAGE=bsddevice
CAP_UNIT=capbundle/device.ucl
CAP_UNITDIR=${DEVICECMP_CAP_UNIT}
CAP_UNITNAME=Unit.ucl
CAP_UNITMODE=0444
CAP_UNITPACKAGE=bsddevice

# Default per-label device policy, in the unit's Config/ (service_config_open).
CONFS=capbundle/device.conf
CONFSNAME=device.conf
CONFSDIR=${DEVICECMP_CAP_CONFIG}
CONFSDIRPACKAGE=bsddevice
CONFSPACKAGE=bsddevice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=tests

.if ${MK_DTRACE} != "no"
SRCS+=	bsddevice_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-DEVICECMP_CAP_BIN

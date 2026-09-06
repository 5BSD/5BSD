.include <src.opts.mk>

PACKAGE=localdevice
PROG=localdevice
PROGNAME=	Device
MAN=localdevice.8
SRCS=localdevice.c policy.c
CFLAGS+=-I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libdevicecmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
CFLAGS+=-I${SRCTOP}/contrib/libucl/include
LIBADD=channel devicecmp service ucl
# Resolve every dynamic symbol at load (BIND_NOW) so nothing is bound lazily
# after the daemon has entered capability mode.
LDFLAGS+=	-Wl,-z,now

DIRS+=DEVICECMP_CAP DEVICECMP_CAP_UNITS DEVICECMP_CAP_UNIT DEVICECMP_CAP_BIN \
	DEVICECMP_CAP_CONFIG
DEVICECMP_CAP=/Capabilities/System/Device.cap
DEVICECMP_CAPPACKAGE=localdevice
DEVICECMP_CAP_UNITS=${DEVICECMP_CAP}/Units
DEVICECMP_CAP_UNITSPACKAGE=localdevice
DEVICECMP_CAP_UNIT=${DEVICECMP_CAP_UNITS}/localdevice.unit
DEVICECMP_CAP_UNITPACKAGE=localdevice
DEVICECMP_CAP_BIN=${DEVICECMP_CAP_UNIT}/bin
DEVICECMP_CAP_BINPACKAGE=localdevice
DEVICECMP_CAP_CONFIG=${DEVICECMP_CAP_UNIT}/Config
DEVICECMP_CAP_CONFIGPACKAGE=localdevice
BINDIR=${DEVICECMP_CAP_BIN}

FILESGROUPS+=CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=capbundle/Bundle.ucl
CAP_BUNDLEDIR=${DEVICECMP_CAP}
CAP_BUNDLEMODE=0444
CAP_BUNDLEPACKAGE=localdevice
CAP_UNIT=capbundle/device.ucl
CAP_UNITDIR=${DEVICECMP_CAP_UNIT}
CAP_UNITNAME=Unit.ucl
CAP_UNITMODE=0444
CAP_UNITPACKAGE=localdevice

# Default per-label device policy, in the unit's Config/ (service_config_open).
CONFS=capbundle/device.conf
CONFSNAME=device.conf
CONFSDIR=${DEVICECMP_CAP_CONFIG}
CONFSPACKAGE=localdevice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=tests
.include <bsd.prog.mk>

_proginstall: installdirs-DEVICECMP_CAP_BIN

.include <src.opts.mk>
PACKAGE= bsdpressure
PROG= BSDPressure
MAN= BSDPressure.8
SRCS= BSDPressure.c pressure.c
CFLAGS+= -I${SRCTOP}/lib/libnotify -I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libsysctlcmp
LIBADD= notify service sysctlcmp
LDFLAGS+= -Wl,-z,now
DIRS+= PRESSURE_CAP PRESSURE_UNITS PRESSURE_UNIT PRESSURE_BIN
PRESSURE_CAP= /Capabilities/System/Pressure.cap
PRESSURE_UNITS= ${PRESSURE_CAP}/Units
PRESSURE_UNIT= ${PRESSURE_UNITS}/bsdpressure.unit
PRESSURE_BIN= ${PRESSURE_UNIT}/bin
.for directory in PRESSURE_CAP PRESSURE_UNITS PRESSURE_UNIT PRESSURE_BIN
${directory}PACKAGE= ${PACKAGE}
.endfor
BINDIR= ${PRESSURE_BIN}
FILESGROUPS= BUNDLE UNIT
BUNDLE= capbundle/Bundle.ucl
BUNDLEDIR= ${PRESSURE_CAP}
BUNDLEMODE= 0444
BUNDLEPACKAGE= ${PACKAGE}
UNIT= capbundle/Unit.ucl
UNITDIR= ${PRESSURE_UNIT}
UNITMODE= 0444
UNITPACKAGE= ${PACKAGE}
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
_proginstall: installdirs-PRESSURE_BIN

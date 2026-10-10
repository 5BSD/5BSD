.include <src.opts.mk>
PACKAGE= bsdmemory
PROG= BSDMemory
MAN= BSDMemory.8
SRCS= BSDMemory.c pressure.c
CFLAGS+= -I${SRCTOP}/lib/libnotify -I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libsysctlcmp
LIBADD= notify service sysctlcmp
LDFLAGS+= -Wl,-z,now
DIRS+= MEMORY_CAP MEMORY_UNITS MEMORY_UNIT MEMORY_BIN
MEMORY_CAP= /Capabilities/System/Memory.cap
MEMORY_UNITS= ${MEMORY_CAP}/Units
MEMORY_UNIT= ${MEMORY_UNITS}/bsdmemory.unit
MEMORY_BIN= ${MEMORY_UNIT}/bin
.for directory in MEMORY_CAP MEMORY_UNITS MEMORY_UNIT MEMORY_BIN
${directory}PACKAGE= ${PACKAGE}
.endfor
BINDIR= ${MEMORY_BIN}
FILESGROUPS= BUNDLE UNIT
BUNDLE= capbundle/Bundle.ucl
BUNDLEDIR= ${MEMORY_CAP}
BUNDLEMODE= 0444
BUNDLEPACKAGE= ${PACKAGE}
UNIT= capbundle/Unit.ucl
UNITDIR= ${MEMORY_UNIT}
UNITMODE= 0444
UNITPACKAGE= ${PACKAGE}
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
_proginstall: installdirs-MEMORY_BIN

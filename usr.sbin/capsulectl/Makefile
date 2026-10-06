.include <src.opts.mk>

PACKAGE=	capsulectl
PROG=		capsulectl
MAN=		capsulectl.8

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert

LIBADD=		service

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

# Ordinary exec uses the same attributed image through the standard command path.
CONTROL_CAP= /Capabilities/System/CapsuleControl.cap
CONTROL_UNIT= ${CONTROL_CAP}/Units/capsulectl.unit
BINDIR= ${CONTROL_UNIT}/bin
DIRS+= CONTROL_CAP CONTROL_UNITS CONTROL_UNIT CONTROL_BIN
CONTROL_UNITS= ${CONTROL_CAP}/Units
CONTROL_BIN= ${BINDIR}
.for directory in CONTROL_CAP CONTROL_UNITS CONTROL_UNIT CONTROL_BIN
${directory}PACKAGE= ${PACKAGE}
.endfor
FILESGROUPS+= CONTROL_BUNDLE CONTROL_POLICY
CONTROL_BUNDLE= capbundle/Bundle.ucl
CONTROL_BUNDLEDIR= ${CONTROL_CAP}
CONTROL_BUNDLEPACKAGE= ${PACKAGE}
CONTROL_BUNDLEMODE= 0444
CONTROL_POLICY= capbundle/Unit.ucl
CONTROL_POLICYDIR= ${CONTROL_UNIT}
CONTROL_POLICYPACKAGE= ${PACKAGE}
CONTROL_POLICYMODE= 0444
SYMLINKS+= ${BINDIR}/${PROG} /usr/sbin/${PROG}

.include <bsd.prog.mk>

_proginstall: installdirs-CONTROL_BIN

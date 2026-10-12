.include <src.opts.mk>

PACKAGE=	bsdnetwork
PROG=		networkcmpctl
MAN=		networkcmpctl.8

CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
LIBADD=		networkcmp

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

# Approved software: the kernel attributes this image, which holds
# system.network.admin and so resolves system.Network.Admin.  Ordinary exec
# uses the same attributed image through the standard command path.
CONTROL_CAP= /Capabilities/System/NetworkControl.cap
CONTROL_UNIT= ${CONTROL_CAP}/Units/networkcmpctl.unit
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

CAPIMAGE_MANIFEST= ${CONTROL_POLICY}

.include <bsd.prog.mk>

_proginstall: installdirs-CONTROL_BIN

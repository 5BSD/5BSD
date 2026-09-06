.include <src.opts.mk>

PACKAGE=	authagentd
PROG=		authagentd
PROGNAME=	AuthAgent
MAN=		authagentd.8

SRCS=		authagentd.c
LIBADD=		service channel capability capbundle
# The mint decision resolves the principal's identity authoritatively inside
# the capsicum sandbox via in-process NSS over retained /etc/passwd and
# /etc/group descriptors (the Identity fold) -- no Casper zygote.
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/sys

# Install as the AuthAgent unit binary inside /Capabilities/System/AuthAgent.cap.
DIRS+=	AUTHAGENT_CAP AUTHAGENT_CAP_UNITS AUTHAGENT_CAP_UNIT AUTHAGENT_CAP_BIN
AUTHAGENT_CAP=	/Capabilities/System/AuthAgent.cap
AUTHAGENT_CAPPACKAGE=	authagentd
AUTHAGENT_CAP_UNITS=	${AUTHAGENT_CAP}/Units
AUTHAGENT_CAP_UNIT=	${AUTHAGENT_CAP_UNITS}/authagentd.unit
AUTHAGENT_CAP_BIN=	${AUTHAGENT_CAP_UNIT}/bin
AUTHAGENT_CAP_BINPACKAGE=	authagentd
AUTHAGENT_CAP_UNITPACKAGE=	authagentd
AUTHAGENT_CAP_UNITSPACKAGE=	authagentd

BINDIR=	${AUTHAGENT_CAP_BIN}

FILESGROUPS+=	AUTHAGENT_BUNDLE AUTHAGENT_UNIT
AUTHAGENT_BUNDLE=	capbundle/Bundle.ucl
AUTHAGENT_BUNDLEDIR=	${AUTHAGENT_CAP}
AUTHAGENT_BUNDLEPACKAGE=	authagentd
AUTHAGENT_BUNDLEMODE=	0444
AUTHAGENT_UNIT=	capbundle/authagentd.ucl
AUTHAGENT_UNITDIR=	${AUTHAGENT_CAP_UNIT}
AUTHAGENT_UNITNAME=	Unit.ucl
AUTHAGENT_UNITPACKAGE=	authagentd
AUTHAGENT_UNITMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-AUTHAGENT_CAP_BIN

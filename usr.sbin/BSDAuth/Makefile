.include <src.opts.mk>

PACKAGE=	bsdauth
PROG=	BSDAuth
MAN=		BSDAuth.8

# Install an explicit, administrator-editable SYSTEM-vs-USER policy.  Keeping
# it in this package makes bsdauth's security default visible on first boot;
# CONFS semantics preserve local changes across upgrades.
CONFS=		principal-policy.ucl
CONFSDIR=	/Capabilities/Config

SRCS=		bsdauth.c
# crypt: ELEVATE verifies the caller's password in-agent (capability mode
# permits crypt(3); PAM module stacks cannot run in the sandbox).
# auditcmp: BSM audit of ELEVATE and MINT outcomes through system.Audit
# (AUE_AUTHAGENT_ELEVATE / AUE_AUTHAGENT_MINT); the sandbox cannot reach the
# audit pipe itself.
LIBADD=		service channel capability capbundle crypt auditcmp
# The mint decision resolves the principal's identity authoritatively inside
# the capsicum sandbox via in-process NSS over retained /etc/passwd and
# /etc/group descriptors (the Identity fold) -- no Casper zygote.
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/sys

# Install as the AuthAgent unit binary inside /Capabilities/System/Auth.cap.
DIRS+=	AUTHAGENT_CAP AUTHAGENT_CAP_UNITS AUTHAGENT_CAP_UNIT AUTHAGENT_CAP_BIN
AUTHAGENT_CAP=	/Capabilities/System/Auth.cap
AUTHAGENT_CAPPACKAGE=	bsdauth
AUTHAGENT_CAP_UNITS=	${AUTHAGENT_CAP}/Units
AUTHAGENT_CAP_UNIT=	${AUTHAGENT_CAP_UNITS}/bsdauth.unit
AUTHAGENT_CAP_BIN=	${AUTHAGENT_CAP_UNIT}/bin
AUTHAGENT_CAP_BINPACKAGE=	bsdauth
AUTHAGENT_CAP_UNITPACKAGE=	bsdauth
AUTHAGENT_CAP_UNITSPACKAGE=	bsdauth

BINDIR=	${AUTHAGENT_CAP_BIN}

FILESGROUPS+=	AUTHAGENT_BUNDLE AUTHAGENT_UNIT
AUTHAGENT_BUNDLE=	capbundle/Bundle.ucl
AUTHAGENT_BUNDLEDIR=	${AUTHAGENT_CAP}
AUTHAGENT_BUNDLEPACKAGE=	bsdauth
AUTHAGENT_BUNDLEMODE=	0444
AUTHAGENT_UNIT=	capbundle/bsdauth.ucl
AUTHAGENT_UNITDIR=	${AUTHAGENT_CAP_UNIT}
AUTHAGENT_UNITNAME=	Unit.ucl
AUTHAGENT_UNITPACKAGE=	bsdauth
AUTHAGENT_UNITMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		bsdauth_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-AUTHAGENT_CAP_BIN

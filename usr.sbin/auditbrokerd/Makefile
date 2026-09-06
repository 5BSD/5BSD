.include <src.opts.mk>

PACKAGE=	auditbrokerd
PROG=		auditbrokerd
PROGNAME=	Audit
MAN=		auditbrokerd.8
SRCS=		auditcmp.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
LIBADD=		auditcmp bsm channel service logcmp
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=	AUDITCMP_CAP AUDITCMP_CAP_UNITS AUDITCMP_CAP_UNIT AUDITCMP_CAP_BIN
AUDITCMP_CAP=	/Capabilities/System/Audit.cap
AUDITCMP_CAPPACKAGE=	auditbrokerd
AUDITCMP_CAP_UNITS=	${AUDITCMP_CAP}/Units
AUDITCMP_CAP_UNIT=	${AUDITCMP_CAP_UNITS}/auditbrokerd.unit
AUDITCMP_CAP_BIN=	${AUDITCMP_CAP_UNIT}/bin
AUDITCMP_CAP_BINPACKAGE=	auditbrokerd
AUDITCMP_CAP_UNITPACKAGE=	auditbrokerd
AUDITCMP_CAP_UNITSPACKAGE=	auditbrokerd

BINDIR=	${AUDITCMP_CAP_BIN}

FILESGROUPS+=	AUDITCMP_BUNDLE AUDITCMP_UNIT
AUDITCMP_BUNDLE=	capbundle/Bundle.ucl
AUDITCMP_BUNDLEDIR=	${AUDITCMP_CAP}
AUDITCMP_BUNDLEMODE=	0444
AUDITCMP_UNIT=	capbundle/auditbrokerd.ucl
AUDITCMP_UNITDIR=	${AUDITCMP_CAP_UNIT}
AUDITCMP_UNITNAME=	Unit.ucl
AUDITCMP_UNITMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		auditbrokerd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-AUDITCMP_CAP_BIN

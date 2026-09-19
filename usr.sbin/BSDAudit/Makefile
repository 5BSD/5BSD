.include <src.opts.mk>

PACKAGE=	bsdaudit
PROG=	BSDAudit
MAN=		BSDAudit.8
SRCS=		auditcmp.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
LIBADD=		auditcmp bsm channel service logcmp
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=	AUDITCMP_CAP AUDITCMP_CAP_UNITS AUDITCMP_CAP_UNIT AUDITCMP_CAP_BIN
AUDITCMP_CAP=	/Capabilities/System/Audit.cap
AUDITCMP_CAPPACKAGE=	bsdaudit
AUDITCMP_CAP_UNITS=	${AUDITCMP_CAP}/Units
AUDITCMP_CAP_UNIT=	${AUDITCMP_CAP_UNITS}/bsdaudit.unit
AUDITCMP_CAP_BIN=	${AUDITCMP_CAP_UNIT}/bin
AUDITCMP_CAP_BINPACKAGE=	bsdaudit
AUDITCMP_CAP_UNITPACKAGE=	bsdaudit
AUDITCMP_CAP_UNITSPACKAGE=	bsdaudit

BINDIR=	${AUDITCMP_CAP_BIN}

FILESGROUPS+=	AUDITCMP_BUNDLE AUDITCMP_UNIT
AUDITCMP_BUNDLE=	capbundle/Bundle.ucl
AUDITCMP_BUNDLEDIR=	${AUDITCMP_CAP}
AUDITCMP_BUNDLEMODE=	0444
AUDITCMP_UNIT=	capbundle/bsdaudit.ucl
AUDITCMP_UNITDIR=	${AUDITCMP_CAP_UNIT}
AUDITCMP_UNITNAME=	Unit.ucl
AUDITCMP_UNITMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		bsdaudit_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-AUDITCMP_CAP_BIN

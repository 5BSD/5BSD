.include <src.opts.mk>

PACKAGE=	auditbrokerd
PROG=		auditbrokerd
MAN=		auditbrokerd.8
SRCS=		auditcmp.c auditcmp_policy.c auditcmp_rate.c auditcmp_submit.c
LIBADD=		auditcmp bsm channel service
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=	AUDITCMP_CAP AUDITCMP_CAP_BIN AUDITCMP_CAP_ETC
AUDITCMP_CAP=	/Capabilities/System/Audit.cap
AUDITCMP_CAPPACKAGE=	auditbrokerd
AUDITCMP_CAP_BIN=	/Capabilities/System/Audit.cap/bin
AUDITCMP_CAP_BINPACKAGE=	auditbrokerd
AUDITCMP_CAP_ETC=	/Capabilities/System/Audit.cap/etc
AUDITCMP_CAP_ETCPACKAGE=	auditbrokerd

BINDIR=	${AUDITCMP_CAP_BIN}

FILESGROUPS+=	AUDITCMP_MANIFEST
AUDITCMP_MANIFEST=	capbundle/auditbrokerd.ucl
AUDITCMP_MANIFESTDIR=	${AUDITCMP_CAP_ETC}
AUDITCMP_MANIFESTNAME=	auditbrokerd.ucl
AUDITCMP_MANIFESTMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		auditbrokerd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-AUDITCMP_CAP_BIN

SUBDIR=	distextract distfetch include partedit runconsoles scripts
SUBDIR_PARALLEL=
SUBDIR_DEPEND_distextract = include
SUBDIR_DEPEND_distfetch = include
SUBDIR_DEPEND_partedit = include
SCRIPTS= bsdinstall
MAN= bsdinstall.8
PACKAGE=	bsdinstall
HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

SCRIPTS+=	startbsdinstall
SCRIPTSDIR_startbsdinstall=	${LIBEXECDIR}/bsdinstall

UPDATE_DEPENDFILE= no

FILESDIR=	${SHAREDIR}/bsdinstall
FILES=		5BSD-base.conf

_BRANCH!=	${MAKE} -C ${SRCTOP}/release -V BRANCH
BRANCH?=	${_BRANCH:C/-p[0-9]+$//}
_REVISION!=	${MAKE} -C ${SRCTOP}/release -V REVISION
REVISION?=	${_REVISION}

.if ${BRANCH} == CURRENT || ${BRANCH} == STABLE
KEYSDIR=	pkg
SUBURL=		base_latest
.elif ${BRANCH} == RELEASE
KEYSDIR=	pkgbase-${REVISION:C/\.[0-9]+//}
SUBURL=		base_release_${REVISION:C/[0-9]+\.//}
.elif ${BRANCH:C/[0-9]+$//} == BETA || \
    ${BRANCH:C/[0-9]+$//} == RC
KEYSDIR=	pkgbase-${REVISION:C/\.[0-9]+//}
SUBURL= 	base_release_${REVISION:C/[0-9]+\.//}_${BRANCH:tl}
.else
.warning Invalid branch "${BRANCH}"
KEYSDIR=	pkg
SUBURL=		base_latest
.endif

5BSD-base.conf: ${SRCTOP}/usr.sbin/pkg/5BSD.conf.in
	sed "s|%%SUBURL%%|${SUBURL}|;s|%%KEYSDIR%%|${KEYSDIR}|" < ${.ALLSRC} > ${.TARGET}

.include <bsd.prog.mk>

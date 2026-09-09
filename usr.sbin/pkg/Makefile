PACKAGE=	pkg-bootstrap

.MAKEFLAGS: -W
_BRANCH!=	${MAKE} -C ${SRCTOP}/release -V BRANCH
BRANCH?=	${_BRANCH}
_REVISION!=	${MAKE} -C ${SRCTOP}/release -V REVISION
REVISION?=	${_REVISION}
.if ${BRANCH:MCURRENT} != ""
PKGCONFBRANCH?=	latest
.else
. if ${BRANCH:MBETA*} || ${BRANCH:MRC*} || ${BRANCH:MRELEASE*}
PKGCONFBRANCH?=	quarterly-release
. else
.  if ${MACHINE} != "amd64" && ${MACHINE} != "i386" && ${MACHINE} != "arm64"
PKGCONFBRANCH?=	quarterly
.  else
PKGCONFBRANCH?=	latest
.  endif
. endif
.endif
PKGCONF?=	FreeBSD.conf.${PKGCONFBRANCH}
CONFS=		${PKGCONF} 5BSD.conf
CONFSNAME_${PKGCONF}=	${PKGCONF:C/\.conf.+$/.conf/}
CONFSDIR=	/etc/pkg
CONFSMODE=	644

.if ${BRANCH} == CURRENT || ${BRANCH} == STABLE
BASEKEYSDIR=	pkg
BASESUBURL=	base_latest
.elif ${BRANCH} == RELEASE
BASEKEYSDIR=	pkgbase-${REVISION:C/\.[0-9]+//}
BASESUBURL=	base_release_${REVISION:C/[0-9]+\.//}
.elif ${BRANCH:C/[0-9]+$//} == BETA || \
    ${BRANCH:C/[0-9]+$//} == RC
BASEKEYSDIR=	pkgbase-${REVISION:C/\.[0-9]+//}
BASESUBURL=	base_release_${REVISION:C/[0-9]+\.//}_${BRANCH:tl}
.else
.warning Invalid branch "${BRANCH}"
BASEKEYSDIR=	pkg
BASESUBURL=	base_latest
.endif

5BSD.conf: 5BSD.conf.in
	sed "s|%%SUBURL%%|${BASESUBURL}|;s|%%KEYSDIR%%|${BASEKEYSDIR}|" \
	    < ${.ALLSRC} > ${.TARGET}
CLEANFILES+=	5BSD.conf

PROG=	pkg
SRCS=	pkg.c rsa.c dns_utils.c config.c ecc.c hash.c
MAN=	pkg.7

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive der fetch pkgecc ucl crypto ssl util md

CFLAGS+=-I${SRCTOP}/contrib/libder/libder
CFLAGS+=-I${SRCTOP}/crypto/libecc/include

.include <bsd.prog.mk>

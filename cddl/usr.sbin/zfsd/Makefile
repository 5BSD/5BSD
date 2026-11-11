.include <src.opts.mk>

.include "Makefile.common"

PACKAGE=	zfs
PROG_CXX=	zfsd
MAN=		zfsd.8

HAS_TESTS=
.if ${MK_GOOGLETEST} != "no"
SUBDIR.${MK_TESTS}+= tests
.endif

.include <bsd.prog.mk>

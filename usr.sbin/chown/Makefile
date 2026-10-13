.include <src.opts.mk>

PACKAGE= runtime
PROG=	chown
LINKS=	${BINDIR}/chown /usr/bin/chgrp
MAN=	chgrp.1 chown.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no"
SRCS+=	chown.c fileowner_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>

.include <src.opts.mk>

PACKAGE=	clibs
LIB=		squeue
SHLIB_MAJOR=	1

SRCS=		squeue_version.c
INCS=		squeue.h

MAN=		squeue.3

# The interface itself is inline in <squeue.h>; the library carries only the
# version accessors.
CFLAGS+=	-I${.CURDIR}

.include <bsd.lib.mk>

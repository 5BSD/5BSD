PACKAGE=runtime
PROG=	umount
SRCS=	umount.c vfslist.c mounttab.c
MAN=	umount.8

MOUNT=	${.CURDIR:H}/mount
UMNTALL= ${SRCTOP}/usr.sbin/rpc.umntall
CFLAGS+= -I${MOUNT} -I${UMNTALL}

.PATH: ${MOUNT} ${UMNTALL}


.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	umountop_provider.d
DTRACE_STATIC_ANCHOR= yes
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>

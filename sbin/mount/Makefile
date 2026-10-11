PACKAGE=runtime
PROG=	mount
SRCS=	mount.c mount_fs.c vfslist.c
MAN=	mount.8

LIBADD=	util xo


.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	mountop_provider.d
DTRACE_STATIC_ANCHOR= yes
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>

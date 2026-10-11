PACKAGE= nfs
PROG=	mountd
SRCS=	mountd.c
MAN=	exports.5 netgroup.5 mountd.8

WARNS?= 2

LIBADD=	util


.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	exports_provider.d
DTRACE_STATIC_ANCHOR= yes
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>

.include <src.opts.mk>

PACKAGE=	otel
PROG=		otelpfd
SRCS=		otelpfd.c pfstat.c
MAN=		otelpfd.8

CFLAGS+=	-I${SRCTOP}/lib/libotelexport
LIBADD=		otelexport

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

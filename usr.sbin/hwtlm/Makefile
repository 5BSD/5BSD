.include <src.opts.mk>

PACKAGE=	hwtlm
PROG=		hwtlm
SRCS=		main.c \
		rapl.c \
		sensors.c \
		format.c
MAN=		hwtlm.8

WARNS?=		6

CFLAGS+=	-I${SRCTOP}/lib/libotelexport

LIBADD=		otelexport m

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

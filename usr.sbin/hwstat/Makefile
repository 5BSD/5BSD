.include <src.opts.mk>

PACKAGE=	hwstat
PROG=		hwstat
SRCS=		main.c \
		rapl.c \
		sensors.c \
		metrics.c \
		format.c
MAN=		hwstat.8

WARNS?=		6

CFLAGS+=	-I${SRCTOP}/lib/libotelexport

LIBADD=		otelexport m

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

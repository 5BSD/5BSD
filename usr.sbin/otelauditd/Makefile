.include <src.opts.mk>

PACKAGE=	otel
PROG=		otelauditd
SRCS=		otelauditd.c auditrec.c
MAN=		otelauditd.8

CFLAGS+=	-I${SRCTOP}/lib/libotelexport
LIBADD=		otelexport bsm

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

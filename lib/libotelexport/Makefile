.include <src.opts.mk>

LIB=		otelexport
INTERNALLIB=

SRCS=		oe_util.c \
		oe_text.c \
		oe_jsonl.c \
		oe_collapsed.c \
		oe_http.c \
		oe_otlp.c

INCS=		otelexport.h

LIBADD=		z ssl crypto pthread

WARNS?=		6

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>

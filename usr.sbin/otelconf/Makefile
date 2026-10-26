.include <src.opts.mk>

PACKAGE=	otel
PROG=		otelconf
SRCS=		otelconf.c
MAN=		otelconf.8 otel.conf.5

CFLAGS+=	-I${SRCTOP}/lib/libotelexport
LIBADD=		otelexport

# /etc/otel.conf (local, preserved) and /etc/defaults/otel.conf.
CONFGROUPS=	CONFS DEFAULTS
CONFS=		otel.conf
CONFSPACKAGE=	otel
DEFAULTS=	otel.conf.defaults
DEFAULTSDIR=	/etc/defaults
DEFAULTSNAME=	otel.conf
DEFAULTSPACKAGE=	otel

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

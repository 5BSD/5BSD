.include <src.opts.mk>

PACKAGE=	newsyslog

CONFS=	newsyslog.conf
PROG=	newsyslog
MAN=	newsyslog.8 newsyslog.conf.5
SRCS=	newsyslog.c ptimes.c
LIBADD=	sbuf util

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
SUBDIR+=	newsyslog.conf.d


.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	logrotate_provider.d
DTRACE_STATIC_ANCHOR= yes
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>

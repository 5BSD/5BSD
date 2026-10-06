PACKAGE=cron
CONFS=	crontab
PROG=	cron
MAN=	cron.8
SRCS=	cron.c database.c do_command.c job.c user.c popen.c

CFLAGS+= -DLOGIN_CAP -DPAM

.include <src.opts.mk>

.if ${MK_DTRACE} != "no"
SRCS+=	cron_provider.d
CFLAGS+= -DWITH_DTRACE
.endif

LIBADD=	cron pam util

WARNS?=	2

.include <bsd.prog.mk>

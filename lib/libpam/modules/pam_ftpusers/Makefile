LIB=		pam_ftpusers
SRCS=		pam_ftpusers.c
MANNODEV=	pam_ftpusers.8

.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	pam_ftpusers_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.lib.mk>

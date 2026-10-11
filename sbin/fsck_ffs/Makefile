PACKAGE=ufs
PROG=	fsck_ffs
LINKS+=	${BINDIR}/fsck_ffs ${BINDIR}/fsck_ufs
LINKS+=	${BINDIR}/fsck_ffs ${BINDIR}/fsck_4.2bsd
MAN=	fsck_ffs.8
MLINKS=	fsck_ffs.8 fsck_ufs.8 fsck_ffs.8 fsck_4.2bsd.8
SRCS=	dir.c ea.c fsutil.c inode.c main.c pass1.c pass1b.c pass2.c pass3.c \
	pass4.c pass5.c setup.c suj.c utilities.c \
	globs.c
LIBADD=	ufs util
WARNS?=	2
CFLAGS+= -I${.CURDIR}

.PATH:	${SRCTOP}/sys/ufs/ffs


.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	ffscheck_provider.d
DTRACE_STATIC_ANCHOR= yes
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>

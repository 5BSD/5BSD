ELFTCDIR=	${SRCTOP}/contrib/elftoolchain

PROG=	elfctl

LIBADD=	elftc elf

CFLAGS+=-I${ELFTCDIR}/libelftc -I${ELFTCDIR}/common

# Use the target ELF definitions without importing target ABI headers into
# the host bootstrap tool. Keep the same isolated-header pattern as elfcopy.
SRCS=	elfctl.c sys/elf_common.h
CLEANDIRS+=	sys
CFLAGS+=	-I.
sys/elf_common.h: ${SRCTOP}/sys/sys/elf_common.h .NOMETA
	mkdir -p ${.OBJDIR}/sys
	ln -sf ${.ALLSRC} ${.TARGET}

.include <bsd.prog.mk>

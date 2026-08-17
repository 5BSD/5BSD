.include <src.opts.mk>

PACKAGE=	bsdtrace
PROG=		bsdtrace
SRCS=		bsdtrace.c \
		cmd_decode.c \
		cmd_exec.c \
		cmd_list.c \
		cmd_trace.c \
		decode.c \
		dwarf.c \
		elf.c \
		format.c \
		hwt.c \
		meta.c \
		resolve.c \
		symbols.c \
		trace.c
MAN=		bsdtrace.8

# Imported from ObservableBSD; not yet style(9).
WARNS?=		2

PTSRC=		${SRCTOP}/contrib/processor-trace
CFLAGS+=	-I${PTSRC}/libipt/include \
		-I${PTSRC}/libipt/internal/include \
		-I${PTSRC}/include
# Pick up the in-tree hwt(4) headers (sys/hwt.h, sys/hwt_record.h)
# so the tool tracks the kernel record ABI it is built with.
CFLAGS+=	-I${SRCTOP}/sys

# The PTWRITE helper header ships for use by traced programs.
INCS=		bsdtrace_ptwrite.h
INCSDIR=	${INCLUDEDIR}

LIBADD=		ipt elf dwarf z m

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

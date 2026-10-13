# $FreeBSD$

.include <src.opts.mk>

PROG=		dtracedctl
SRCS=		dtracedctl.c
MAN=		dtracedctl.8
WARNS?=		3

CFLAGS+=	-I${SRCTOP}/usr.sbin/dtraced

LIBADD=	dtrace ctf elf proc pthread crypto execinfo util

.if ${MK_DTRACE_OPTIMIZED} != "no" && ${MACHINE_ARCH} != mips && \
    ${MACHINE_ARCH} != mips64 && ${MACHINE_ARCH} != powerpc64 && \
    ${MACHINE_ARCH} != riscv64
CFLAGS+=	-flto
LDFLAGS+=	-flto
.endif

.include <bsd.prog.mk>

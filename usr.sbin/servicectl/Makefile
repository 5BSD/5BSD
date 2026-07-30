.include <src.opts.mk>

PACKAGE=servicectl
PROG=	servicectl
SRCS=	servicectl.c deps.c install.c verify.c
MAN=	servicectl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/liboraclectl
CFLAGS+=	-I${SRCTOP}/lib/liboraclert
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capbundle oraclectl ucl elf

.include <bsd.prog.mk>

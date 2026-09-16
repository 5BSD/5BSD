.include <src.opts.mk>

PACKAGE=switchboardctl
PROG=	switchboardctl
SRCS=	switchboardctl.c deps.c install.c verify.c graph.c
MAN=	switchboardctl.8
SCRIPTSDIR=	${LIBEXECDIR}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capbundle capsulert service ucl elf md

.include <bsd.prog.mk>

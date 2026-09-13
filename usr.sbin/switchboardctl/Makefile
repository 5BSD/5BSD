.include <src.opts.mk>

PACKAGE=switchboardctl
PROG=	switchboardctl
SRCS=	lifecycle.c switchboardctl.c deps.c install.c verify.c
MAN=	switchboardctl.8
SCRIPTS=	switchboard-pkg-reclaim.sh
SCRIPTSDIR=	${LIBEXECDIR}
SCRIPTSNAME_switchboard-pkg-reclaim.sh=	switchboard-pkg-reclaim

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capbundle capsulert service ucl elf md

.include <bsd.prog.mk>

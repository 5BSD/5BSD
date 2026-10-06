.include <src.opts.mk>

PACKAGE=	switchboardctl
PROG=		policyctl
MAN=		policyctl.8
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
LIBADD=		capbundle

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>

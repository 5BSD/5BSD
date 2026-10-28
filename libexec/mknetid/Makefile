PROG=	mknetid
SRCS=	mknetid.c hash.c parse_group.c

MAN=	netid.5 mknetid.8

WARNS?=	2

.include <src.opts.mk>

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>

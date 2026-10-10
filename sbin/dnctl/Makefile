.include <src.opts.mk>

PACKAGE= dummynet
PROG= dnctl
SRCS= main.c support.c common.c dummynet.c
LIBADD= util
MAN= dnctl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}= tests

.include <bsd.prog.mk>

CWARNFLAGS+= -Wno-cast-align

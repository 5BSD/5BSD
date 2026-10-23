.include <src.opts.mk>
PACKAGE= bsd-build
PROG= build-bsd
SRCS= build-bsd.c
LIBADD= md
LINKS= ${BINDIR}/build-bsd ${BINDIR}/bsd-build
MAN= bsd-build.8
MLINKS= bsd-build.8 build-bsd.8
FILESGROUPS+= EXAMPLES
EXAMPLES= bsd-build.conf.sample
EXAMPLESDIR= ${SHAREDIR}/examples/bsd-build
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>

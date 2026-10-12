.include <src.opts.mk>
PACKAGE= capsign
PROG= capsign
SRCS= capsign.c capsign_tree.c
MAN= capsign.8
LIBADD= capimage capbundle crypto
CFLAGS+= -I${SRCTOP}/lib/libcapimage -I${SRCTOP}/lib/libcapbundle
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>

.include <src.opts.mk>
PACKAGE= elfcache
PROGS= elfcache elfcache-seed
SRCS.elfcache= elfcache.c layout.c
SRCS.elfcache-seed= seed.c
MAN.elfcache= elfcache.8
MAN.elfcache-seed=
BINDIR.elfcache-seed= /usr/libexec
LIBADD.elfcache= capimage crypto
CFLAGS+= -I${SRCTOP}/lib/libcapimage -iquote${SRCTOP}/sys
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.progs.mk>

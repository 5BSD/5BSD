.include <src.opts.mk>

PACKAGE=runtime
PROG=	cat

.ifdef BOOTSTRAPPING
# For the bootstrap cat we disable all wide char support to allow building
# on Linux/macOS
CFLAGS+=-DBOOTSTRAP_CAT
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

# Temporary disable building cat with Casper.
#.if ${MK_CASPER} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
#LIBADD+=        casper
#LIBADD+=        cap_fileargs
#LIBADD+=        cap_net
#CFLAGS+=-DWITH_CASPER
#.endif
# Depend on Makefile to rebuild when WITH_CASPER changes
cat.o:	Makefile

SRCS=	cat.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	catio_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>

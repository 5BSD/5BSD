.include <src.opts.mk>

PROG=	cap_mkdb

.if defined(BOOTSTRAPPING)
# Construction must not inherit the host libc's compiled-database behavior.
.PATH: ${SRCTOP}/lib/libc/gen
SRCS= cap_mkdb.c getcap.c
CFLAGS+= -I${.CURDIR}/bootstrap -I${SRCTOP}/tools/build/libc-bootstrap
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>

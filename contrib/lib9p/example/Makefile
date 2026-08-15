PROG=	server
SRCS=	server.c
MAN=

CFLAGS=	-pthread -g -O0

LDFLAGS=-L..
# The source tree exposes the versioned shared object during an object build,
# while the unversioned linker symlink is an install artifact.  Name the
# shared object explicitly so a PIE example cannot fall back to lib9p.a.
LDADD=	../lib9p.so.1
LIBADD=	sbuf casper cap_pwd cap_grp

.include <bsd.prog.mk>

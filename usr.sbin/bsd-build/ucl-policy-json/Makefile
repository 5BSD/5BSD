PACKAGE= bsd-build
PROG= bsd-ucl-json
SRCS= ucl-policy-json.c
BINDIR= /usr/libexec/bsd-build
DIRS+= BINDIR
BINDIRPACKAGE= ${PACKAGE}
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
LIBADD= ucl
NO_SHARED= yes
MAN=
.include <bsd.prog.mk>

# The directory must exist before parallel program installation.
_proginstall: installdirs-BINDIR

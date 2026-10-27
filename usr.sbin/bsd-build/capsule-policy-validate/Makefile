PACKAGE= bsd-build
PROG= bsd-capsule-validate
SRCS= capsule-policy-validate.c config.c config_report.c
.PATH: ${SRCTOP}/usr.sbin/capsule
BINDIR= /usr/libexec/bsd-build
DIRS+= BINDIR
BINDIRPACKAGE= ${PACKAGE}
CFLAGS+= -I${SRCTOP}/usr.sbin/capsule -I${SRCTOP}/lib/libcapsulert
CFLAGS+= -I${SRCTOP}/lib/libcapbundle
CFLAGS+= -I${SRCTOP}/sys -I${SRCTOP}/contrib/libucl/include
LIBADD= capsulert ucl md
NO_SHARED= yes
MAN=
.include <bsd.prog.mk>
_proginstall: installdirs-BINDIR

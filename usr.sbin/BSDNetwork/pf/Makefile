PACKAGE= bsdnetwork
PROG= BSDPF
SRCS= bsdpf.c
MAN=
CFLAGS+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys -I${SRCTOP}/lib/liblogcmp
LDFLAGS+= -Wl,-z,now
LIBADD= channel service logcmp
BINDIR= /Capabilities/System/Network.cap/Units/pf.unit/bin
DIRS+= PF_UNIT PF_BIN
PF_UNIT= /Capabilities/System/Network.cap/Units/pf.unit
PF_BIN= ${BINDIR}
PF_UNITPACKAGE= bsdnetwork
PF_BINPACKAGE= bsdnetwork
FILES= pf.ucl
FILESDIR= ${PF_UNIT}
FILESNAME_pf.ucl= Unit.ucl
FILESMODE= 0444
.include <bsd.prog.mk>
_proginstall: installdirs-PF_BIN

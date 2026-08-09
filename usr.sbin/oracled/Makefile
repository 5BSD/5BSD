.include <src.opts.mk>

PACKAGE=oracled
PROG= oracled
MAN= oracled.8
SRCS= oracled.c bootstrap.c mac_capability_setup.c mac_capability_claims.c mac_capability_reload.c \
	mac_capability_status.c mac_capability_mint.c \
	mac_capability_coal.c commands.c config.c control.c event.c \
	oracle_init.c oracle_proto.c oracle_proto_claims.c proc.c
CONFS= oracled.conf

FILESGROUPS+= examples
examples= examples/desktop.conf \
	 examples/server.conf \
	 examples/embedded.conf \
	 examples/skyblue-broker.conf \
	 examples/dynamic_claims.d
examplesDIR= ${SHAREDIR}/examples/oracled
examplesPACKAGE= oracled

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/lib/libcapability
CFLAGS+= -I${SRCTOP}/lib/liboraclert
CFLAGS+= -I${SRCTOP}/lib/libcapbundle
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
LIBADD= capability crypt jail oraclert ucl util

.if ${MK_DTRACE} != "no"
SRCS+= oracled_provider.d
CFLAGS+= -I${.OBJDIR}
.endif

.include <bsd.prog.mk>

.include <src.opts.mk>

PACKAGE=oracled
PROG= oracled
MAN= oracled.8
SRCS= oracled.c bootstrap.c cap_rt_setup.c cap_rt_claims.c cap_rt_reload.c \
	cap_rt_status.c cap_rt_mint.c \
	cap_rt_coal.c claim_parse.c commands.c config.c control.c event.c \
	oracle_proto.c oracle_proto_claims.c proc.c
CONFS= oracled.conf

FILESDIR_examples= ${SHAREDIR}/examples/oracled
FILESGROUPS+= examples
examples= examples/desktop.conf \
	 examples/server.conf \
	 examples/embedded.conf \
	 examples/dynamic_claims.d

FILESDIR_system= ${SHAREDIR}/Capabilities/System
FILESGROUPS+= system
system= examples/kldmgrd.ucl \
	 examples/rebootd.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/lib/liboraclert
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
LIBADD= jail ucl util

.if ${MK_DTRACE} != "no"
SRCS+= oracled_provider.d
CFLAGS+= -I${.OBJDIR}
.endif

.include <bsd.prog.mk>

.include <src.opts.mk>

PACKAGE=oracled
PROG= oracled
MAN= oracled.8
SRCS= oracled.c bootstrap.c mac_capability_setup.c mac_capability_claims.c mac_capability_reload.c \
	mac_capability_status.c mac_capability_mint.c \
	mac_capability_coal.c commands.c config.c control.c event.c \
	oracle_init.c oracle_proto.c oracle_proto_claims.c proc.c
CONFS= oracled.conf

# Oracle is also the system's PID 1 implementation.  Keep the boot copy
# outside /usr: a fresh installation may have /usr on a separate filesystem
# that has not been mounted when the kernel starts init.  This is a second
# installed copy, rather than a hard link, so installation works when / and
# /usr are distinct filesystems.
ORACLE_INIT= oracle-init
ORACLE_INITDIR= /sbin
ORACLE_INITOWN= ${BINOWN}
ORACLE_INITGRP= ${BINGRP}
ORACLE_INITMODE= ${BINMODE}
ORACLE_INITPACKAGE= oracled

# Lua loader reads this directory after loader.conf.  bsdinstall and VM image
# generation also write the setting directly for loader implementations that
# do not support loader.conf.d.
ORACLE_INIT_LOADER= oracle-init.conf
ORACLE_INIT_LOADERDIR= /boot/loader.conf.d
ORACLE_INIT_LOADEROWN= ${BINOWN}
ORACLE_INIT_LOADERGRP= ${BINGRP}
ORACLE_INIT_LOADERMODE= 444
ORACLE_INIT_LOADERPACKAGE= oracled
FILESGROUPS+= ORACLE_INIT ORACLE_INIT_LOADER

oracle-init: ${PROG}
	${CP} ${.ALLSRC} ${.TARGET}
CLEANFILES+= oracle-init

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
CFLAGS+= -I${SRCTOP}/lib/libtzfsd
CFLAGS+= -I${SRCTOP}/lib/libservice
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
LIBADD= capability crypt jail oraclert tzfsd ucl util

.if ${MK_DTRACE} != "no"
SRCS+= oracled_provider.d
CFLAGS+= -I${.OBJDIR}
.endif

.include <bsd.prog.mk>

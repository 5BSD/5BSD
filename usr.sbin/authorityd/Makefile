.include <src.opts.mk>

PACKAGE=authorityd
PROG= authorityd
MAN= authorityd.8
SRCS= authorityd.c bootstrap.c mac_capability_setup.c mac_capability_claims.c mac_capability_reload.c \
	mac_capability_status.c mac_capability_mint.c \
	mac_capability_coal.c commands.c config.c control.c event.c \
	authority_init.c authority_proto.c authority_proto_claims.c proc.c
CONFS= authorityd.conf

# Authority is also the system's PID 1 implementation.  Keep the boot copy
# outside /usr: a fresh installation may have /usr on a separate filesystem
# that has not been mounted when the kernel starts init.  This is a second
# installed copy, rather than a hard link, so installation works when / and
# /usr are distinct filesystems.
AUTHORITY_INIT= authority-init
AUTHORITY_INITDIR= /sbin
AUTHORITY_INITOWN= ${BINOWN}
AUTHORITY_INITGRP= ${BINGRP}
AUTHORITY_INITMODE= ${BINMODE}
AUTHORITY_INITPACKAGE= authorityd

# Lua loader reads this directory after loader.conf.  bsdinstall and VM image
# generation also write the setting directly for loader implementations that
# do not support loader.conf.d.
AUTHORITY_INIT_LOADER= authority-init.conf
AUTHORITY_INIT_LOADERDIR= /boot/loader.conf.d
AUTHORITY_INIT_LOADEROWN= ${BINOWN}
AUTHORITY_INIT_LOADERGRP= ${BINGRP}
AUTHORITY_INIT_LOADERMODE= 444
AUTHORITY_INIT_LOADERPACKAGE= authorityd
FILESGROUPS+= AUTHORITY_INIT AUTHORITY_INIT_LOADER

authority-init: ${PROG}
	${CP} ${.ALLSRC} ${.TARGET}
CLEANFILES+= authority-init

FILESGROUPS+= examples
examples= examples/desktop.conf \
	 examples/server.conf \
	 examples/embedded.conf \
	 examples/broker.conf \
	 examples/dynamic_claims.d
examplesDIR= ${SHAREDIR}/examples/authorityd
examplesPACKAGE= authorityd

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/lib/libcapability
CFLAGS+= -I${SRCTOP}/lib/libauthorityrt
CFLAGS+= -I${SRCTOP}/lib/libcapbundle
CFLAGS+= -I${SRCTOP}/lib/libservice
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
LIBADD= capability crypt authorityrt ucl util

.if ${MK_DTRACE} != "no"
SRCS+= authorityd_provider.d
CFLAGS+= -I${.OBJDIR}
.endif

.include <bsd.prog.mk>

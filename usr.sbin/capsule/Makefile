.include <src.opts.mk>

PACKAGE=	capsule
PROG=		capsule
MAN=		capsule.8 capsule.conf.5
SRCS=		main.c bootstrap.c mac_capability_setup.c mac_capability_claims.c mac_capability_reload.c \
	mac_capability_status.c mac_capability_mint.c \
	mac_capability_coal.c commands.c config.c control.c event.c \
	capsule.c capsule_proto.c capsule_proto_claims.c proc.c
CONFS=		capsule-daemon.conf
CONFSNAME=	capsule.conf

# Capsule is also the system's PID 1 implementation: run as PID 1 it takes on
# the init personality in capsule.c.  The boot copy is installed as
# /sbin/capsule.  Keep it outside /usr: a fresh installation may have /usr on a
# separate filesystem that has not been mounted when the kernel starts init.
# This is a second installed copy, rather than a hard link, so installation works
# when / and /usr are distinct filesystems.
CAPSULE= capsule
CAPSULEDIR= /sbin
CAPSULEOWN= ${BINOWN}
CAPSULEGRP= ${BINGRP}
CAPSULEMODE= ${BINMODE}
CAPSULEPACKAGE= capsule

# The 5BSD loader defaults select Capsule first.  Keep this package fragment as
# an upgrade-safe declaration for installations whose bootloader defaults have
# not yet been updated; /sbin/init remains a recovery candidate in both places.
CAPSULE_LOADER= capsule-loader.conf
CAPSULE_LOADERNAME= capsule.conf
CAPSULE_LOADERDIR= /boot/loader.conf.d
CAPSULE_LOADEROWN= ${BINOWN}
CAPSULE_LOADERGRP= ${BINGRP}
CAPSULE_LOADERMODE= 444
CAPSULE_LOADERPACKAGE= capsule
FILESGROUPS+= CAPSULE CAPSULE_LOADER

FILESGROUPS+= examples
examples= examples/desktop.conf \
	 examples/server.conf \
	 examples/embedded.conf \
	 examples/broker.conf \
	 examples/dynamic_claims.d
examplesDIR= ${SHAREDIR}/examples/capsule
examplesPACKAGE= capsule

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/lib/libcapability
CFLAGS+= -I${SRCTOP}/lib/libcapsulert
CFLAGS+= -I${SRCTOP}/lib/libcapbundle
CFLAGS+= -I${SRCTOP}/lib/libservice
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
LIBADD= capability crypt capsulert ucl util

.if ${MK_DTRACE} != "no"
SRCS+= capsule_provider.d
CFLAGS+= -I${.OBJDIR}
.endif

.include <bsd.prog.mk>

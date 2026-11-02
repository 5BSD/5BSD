.PATH:  ${SRCTOP}/sys/dev/etherswitch

KMOD    = miiproxy

SRCS=	miiproxy.c
SRCS+=	bus_if.h device_if.h mdio_if.h miibus_if.h opt_platform.h
CFLAGS+= -I${SRCTOP}/sys/dev/etherswitch

# miivar.h includes the OFW interface when platform options enable FDT.
.if !empty(OPT_FDT)
SRCS+=	ofw_bus_if.h
.endif

.include <bsd.kmod.mk>

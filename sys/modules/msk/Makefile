.PATH: ${SRCTOP}/sys/dev/msk

KMOD=	if_msk
SRCS=	if_msk.c device_if.h bus_if.h pci_if.h
SRCS+=	miibus_if.h opt_platform.h

# miivar.h consumes the OFW interface when opt_platform.h enables FDT.
SRCS+=	ofw_bus_if.h

.include <bsd.kmod.mk>

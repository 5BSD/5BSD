.PATH: ${SRCTOP}/sys/dev/ale

KMOD=	if_ale
SRCS=	if_ale.c device_if.h bus_if.h pci_if.h miibus_if.h opt_platform.h

# miivar.h consumes the OFW interface when opt_platform.h enables FDT.
SRCS+=	ofw_bus_if.h

.include <bsd.kmod.mk>

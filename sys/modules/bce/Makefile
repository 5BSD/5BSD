.PATH:	${SRCTOP}/sys/dev/bce
KMOD=	if_bce
SRCS=	opt_platform.h opt_bce.h if_bce.c miibus_if.h miidevs.h device_if.h bus_if.h pci_if.h

#CFLAGS += -DBCE_DEBUG=0

# miivar.h consumes the OFW interface when opt_platform.h enables FDT.
SRCS+=	ofw_bus_if.h

.include <bsd.kmod.mk>

.PATH: ${SRCTOP}/sys/dev/usb/net

KMOD=	if_axge
SRCS+=	if_axge.c usbdevs.h
SRCS+=	bus_if.h device_if.h miibus_if.h usb_if.h \
	opt_bus.h opt_inet.h opt_usb.h opt_platform.h

# miivar.h requires the OFW interface when platform options enable FDT.
.if !empty(OPT_FDT)
SRCS+=	ofw_bus_if.h
.endif

.include <bsd.kmod.mk>

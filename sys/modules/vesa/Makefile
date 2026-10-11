KMOD=	vesa
SRCS=	opt_vga.h opt_vesa.h
SRCS+=	bus_if.h device_if.h pci_if.h

.PATH:	${SRCTOP}/sys/dev/fb
SRCS+=	vesa.c


.include <bsd.kmod.mk>

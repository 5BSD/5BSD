.PATH: ${SRCTOP}/sys/dev/ow

KMOD=	ow
SRCS=	ow.c
SRCS+=	own_if.c own_if.h owll_if.c owll_if.h bus_if.h device_if.h

# The own/owll method descriptors are used by separate consumer modules.
EXPORT_SYMS=	YES

.include <bsd.kmod.mk>

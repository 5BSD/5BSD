.PATH: ${SRCTOP}/sys/dev/mmc

KMOD=	mmc
SRCS=	bus_if.h device_if.h mmc_subr.c mmc.c mmcbr_if.h mmcbus_if.h

# MMC bus clients and bridge drivers consume this public API.
EXPORT_SYMS=	YES

.include <bsd.kmod.mk>

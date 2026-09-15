.PATH: ${SRCTOP}/sys/compat/linuxkpi/common/src

KMOD= linuxkpi_sdio
SRCS= linux_sdio.c sdio_if.h
SRCS+= ${LINUXKPI_GENSRCS}
CFLAGS+= ${LINUXKPI_INCLUDES}

# brcmfmac resolves this provider API when its module is loaded.
EXPORT_SYMS=	YES

.include <bsd.kmod.mk>

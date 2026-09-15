DEVDIR=	${SRCTOP}/sys/contrib/dev/broadcom/brcm80211/brcmutil

.PATH:	${DEVDIR}

BRCMUTIL_DEBUG=		1

KMOD=	brcmutil

SRCS=	d11.c utils.c

.if defined(BRCMUTIL_DEBUG) && ${BRCMUTIL_DEBUG} > 0
CFLAGS+=	-DDEBUG
.endif

# Other
SRCS+=	${LINUXKPI_GENSRCS}
SRCS+=	bus_if.h device_if.h pci_if.h vnode_if.h
SRCS+=	opt_wlan.h opt_inet6.h opt_inet.h

CFLAGS+=	-I${DEVDIR}
CFLAGS+=	-I${DEVDIR}/../include
CFLAGS+=	${LINUXKPI_INCLUDES}
#CFLAGS+=	-ferror-limit=0

CFLAGS+=	-DKBUILD_MODNAME='"brcmutil"'
CFLAGS+=	-DLINUXKPI_VERSION=70000

# brcmfmac resolves this provider API when its module is loaded.
EXPORT_SYMS=	YES

.include <bsd.kmod.mk>

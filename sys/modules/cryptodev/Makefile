.PATH:	${SRCTOP}/sys/opencrypto
KMOD	= cryptodev
SRCS	= cryptodev.c cryptodesc_kdf.c cryptodesc_ed25519.c
SRCS	+= bus_if.h device_if.h vnode_if.h

.include <bsd.kmod.mk>

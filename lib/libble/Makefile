.include <src.opts.mk>

LIB=		ble
SHLIB_MAJOR=	1

SRCS=		ble.c

INCS=		ble.h

PACKAGE=	bluetooth

LIBADD=		bluetooth service

# ble_open_plane(): the capability-plane hand-off (blued_plane.h, a private
# source contract shared with blued, not installed) over libservice.
CFLAGS+=	-I${SRCTOP}/lib/libservice

MAN=		libble.3

# ipc_proto.h is a private, shared source contract.  It is intentionally not
# listed in INCS and therefore is not installed as part of libble's public API.

WARNS?=		6

.include <bsd.lib.mk>

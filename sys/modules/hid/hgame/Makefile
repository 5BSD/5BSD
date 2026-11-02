.PATH: ${SRCTOP}/sys/dev/hid

KMOD=	hgame
SRCS=	hgame.c
SRCS+=	opt_kbd.h
SRCS+=	bus_if.h device_if.h

# Shared callbacks used by the PlayStation and Xbox controller modules.
EXPORT_SYMS=	hgame_hat_switch_cb hgame_dpad_cb hgame_final_cb

.include <bsd.kmod.mk>

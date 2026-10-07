PACKAGE=	bluetooth
PROG=	BSDBluetoothController
SRCS=	controller.c
MAN=
LIBADD=	bluetooth service channel
CFLAGS+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libchannel
BINDIR=	/Capabilities/System/Bluetooth.cap/Units/controller.unit/bin
DIRS+=	CONTROLLER_UNIT CONTROLLER_BIN
CONTROLLER_UNIT=	/Capabilities/System/Bluetooth.cap/Units/controller.unit
CONTROLLER_BIN=	${BINDIR}
CONTROLLER_UNITPACKAGE=	${PACKAGE}
CONTROLLER_BINPACKAGE=	${PACKAGE}
FILES=	controller.ucl
FILESDIR=	${CONTROLLER_UNIT}
FILESNAME_controller.ucl=	Unit.ucl
FILESMODE=	0444
.include <bsd.prog.mk>
_proginstall: installdirs-CONTROLLER_BIN

.include <src.opts.mk>

PACKAGE=	runtime
PROG=		vmd
MAN=		vmd.8

SRCS=		vmd.c

# vmd is a serviced-supervised unit: it ships as the VM.cap capability bundle
# and serviced launches it on demand, rather than living at /usr/sbin and being
# spawned by PID 1.  The binary is the unit's program.
DIRS+=		VM_CAP VM_CAP_UNITS VM_CAP_UNIT VM_CAP_BIN
VM_CAP=		/Capabilities/System/VM.cap
VM_CAPPACKAGE=	runtime
VM_CAP_UNITS=	${VM_CAP}/Units
VM_CAP_UNITSPACKAGE=	runtime
VM_CAP_UNIT=	${VM_CAP_UNITS}/vmd.unit
VM_CAP_UNITPACKAGE=	runtime
VM_CAP_BIN=	${VM_CAP_UNIT}/bin
VM_CAP_BINPACKAGE=	runtime

BINDIR=		${VM_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${VM_CAP}
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/vmd.ucl
CAP_UNITDIR=	${VM_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

# vmd_proto.h (libauthorityrt), AF_VSOCK/sockaddr_vm (sys/sys/vsock.h), and the
# socket-free service_provider transport (libservice over libchannel).
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys

LIBADD=		service channel

.include <bsd.prog.mk>

_proginstall: installdirs-VM_CAP_BIN

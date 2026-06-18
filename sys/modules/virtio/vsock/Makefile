.PATH: ${SRCTOP}/sys/dev/virtio/vsock

KMOD=	virtio_vsock

SRCS=	virtio_vsock.c
SRCS+=	virtio_bus_if.h virtio_if.h
SRCS+=	bus_if.h device_if.h

.include <bsd.kmod.mk>

# $FreeBSD$

.PATH: ${SRCTOP}/sys/dev/virtio/sound

KMOD=	virtio_snd
SRCS=	virtio_snd.c
SRCS+=	virtio_bus_if.h virtio_if.h
SRCS+=	bus_if.h device_if.h
SRCS+=	channel_if.h feeder_if.h mixer_if.h ac97_if.h

.include <bsd.kmod.mk>

#
# SPDX-License-Identifier: BSD-2-Clause
#

.PATH: ${SRCTOP}/sys/dev/virtio/input

KMOD=	virtio_input
SRCS=	virtio_input.c
SRCS+=	virtio_bus_if.h virtio_if.h
SRCS+=	bus_if.h device_if.h
SRCS+=	opt_evdev.h opt_kbd.h

.include <bsd.kmod.mk>

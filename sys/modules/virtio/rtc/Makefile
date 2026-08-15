#
# SPDX-License-Identifier: BSD-2-Clause
#

.PATH: ${SRCTOP}/sys/dev/virtio/rtc

KMOD=	virtio_rtc
SRCS=	virtio_rtc.c
SRCS+=	virtio_bus_if.h virtio_if.h
SRCS+=	bus_if.h clock_if.h device_if.h

.include <bsd.kmod.mk>

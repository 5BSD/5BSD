#
# SPDX-License-Identifier: BSD-2-Clause
#

.PATH: ${SRCTOP}/sys/dev/virtio/gpu

KMOD=	virtio_gpu
SRCS=	virtio_gpu.c
SRCS+=	virtio_bus_if.h virtio_if.h
SRCS+=	bus_if.h device_if.h fb_if.h
SRCS+=	opt_splash.h opt_syscons.h opt_teken.h

.include <bsd.kmod.mk>

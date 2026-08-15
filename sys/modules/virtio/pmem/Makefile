#
# SPDX-License-Identifier: BSD-2-Clause
#

.PATH: ${SRCTOP}/sys/dev/virtio/pmem

KMOD=	virtio_pmem
SRCS=	virtio_pmem.c
SRCS+=	virtio_bus_if.h virtio_if.h
SRCS+=	acpi_if.h bus_if.h device_if.h opt_acpi.h

.include <bsd.kmod.mk>

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _VIRTIO_PCI_MODERN_PROBES_H_
#define	_VIRTIO_PCI_MODERN_PROBES_H_

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define	DTRACE_PROBE(...)
#define	DTRACE_PROBE1(provider, name, a) ((void)(a))
#define	DTRACE_PROBE2(provider, name, a, b) ((void)(a), (void)(b))
#define	DTRACE_PROBE4(provider, name, a, b, c, d) \
	((void)(a), (void)(b), (void)(c), (void)(d))
#define	DTRACE_PROBE5(provider, name, a, b, c, d, e) \
	((void)(a), (void)(b), (void)(c), (void)(d), (void)(e))
#endif

#define	VIRTIO_PROBE_FEATURES(features)				\
	DTRACE_PROBE1(virtio, transport__features, features)
#define	VIRTIO_PROBE_STATUS(old_status, new_status)		\
	DTRACE_PROBE2(virtio, transport__status, old_status, new_status)
#define	VIRTIO_PROBE_QUEUE_ENABLE(queue, desc, driver, device, size) \
	DTRACE_PROBE5(virtio, transport__queue__enable, queue, desc, driver, \
	    device, size)
#define	VIRTIO_PROBE_QUEUE_NOTIFY(queue)			\
	DTRACE_PROBE1(virtio, transport__queue__notify, queue)
#define	VIRTIO_PROBE_CFG_WINDOW(bar, offset, length, is_write) \
	DTRACE_PROBE4(virtio, transport__cfg__window, bar, offset, length, \
	    is_write)
#define	VIRTIO_PROBE_CONFIG_CHANGED(generation)			\
	DTRACE_PROBE1(virtio, transport__config__changed, generation)
#define	VIRTIO_PROBE_RESET()					\
	DTRACE_PROBE(virtio, transport__reset)
#define	VIRTIO_PROBE_ERROR(reason)				\
	DTRACE_PROBE1(virtio, transport__error, reason)

#endif

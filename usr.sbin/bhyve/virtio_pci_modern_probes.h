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
#define	DTRACE_PROBE3(provider, name, a, b, c) \
	((void)(a), (void)(b), (void)(c))
#define	DTRACE_PROBE4(provider, name, a, b, c, d) \
	((void)(a), (void)(b), (void)(c), (void)(d))
#define	DTRACE_PROBE5(provider, name, a, b, c, d, e) \
	((void)(a), (void)(b), (void)(c), (void)(d), (void)(e))
#endif

#define	VIRTIO_PROBE_FEATURES(name, features)			\
	DTRACE_PROBE2(virtio, transport__features, name, features)
#define	VIRTIO_PROBE_STATUS(name, old_status, new_status)	\
	DTRACE_PROBE3(virtio, transport__status, name, old_status, new_status)
#define	VIRTIO_PROBE_QUEUE_ENABLE(name, queue, desc, used, size)	\
	DTRACE_PROBE5(virtio, transport__queue__enable, name, queue, desc, \
	    used, size)
#define	VIRTIO_PROBE_QUEUE_NOTIFY(name, queue)			\
	DTRACE_PROBE2(virtio, transport__queue__notify, name, queue)
#define	VIRTIO_PROBE_QUEUE_RESET_BEGIN(name, queue, generation)	\
	DTRACE_PROBE3(virtio, transport__queue__reset__begin, name, queue, \
	    generation)
#define	VIRTIO_PROBE_QUEUE_RESET_END(name, queue, generation)	\
	DTRACE_PROBE3(virtio, transport__queue__reset__end, name, queue, \
	    generation)
#define	VIRTIO_PROBE_QUEUE_RESET_FAIL(name, queue, generation, error) \
	DTRACE_PROBE4(virtio, transport__queue__reset__fail, name, queue, \
	    generation, error)
#define	VIRTIO_PROBE_CFG_WINDOW(name, bar, offset, length, is_write) \
	DTRACE_PROBE5(virtio, transport__cfg__window, name, bar, offset, \
	    length, is_write)
#define	VIRTIO_PROBE_CONFIG_CHANGED(name, generation)		\
	DTRACE_PROBE2(virtio, transport__config__changed, name, generation)
#define	VIRTIO_PROBE_RESET(name)					\
	DTRACE_PROBE1(virtio, transport__reset, name)
#define	VIRTIO_PROBE_ERROR(name, reason)				\
	DTRACE_PROBE2(virtio, transport__error, name, reason)

#endif

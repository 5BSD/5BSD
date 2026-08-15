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
#undef DTRACE_PROBE
#undef DTRACE_PROBE1
#undef DTRACE_PROBE2
#undef DTRACE_PROBE3
#undef DTRACE_PROBE4
#undef DTRACE_PROBE5
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
#define	VIRTIO_PROBE_DESCRIPTOR_CHAIN(name, queue, packed, indirect, count) \
	DTRACE_PROBE5(virtio, transport__descriptor__chain, name, queue, \
	    packed, indirect, count)
#define	VIRTIO_PROBE_EVENT_IDX(name, queue, event, produced, interrupt) \
	DTRACE_PROBE5(virtio, transport__event__idx, name, queue, event, \
	    produced, interrupt)
#define	VIRTIO_PROBE_PACKED_EVENT_IDX(name, queue, event, produced, interrupt) \
	DTRACE_PROBE5(virtio, transport__packed__event__idx, name, queue, \
	    event, produced, interrupt)
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
#define	VIRTIO_PROBE_SHARED_MEMORY(name, id, event, length, writable) \
	DTRACE_PROBE5(virtio, transport__shared__memory, name, id, event, \
	    length, writable)
#define	VIRTIO_PROBE_CONFIG_CHANGED(name, generation)		\
	DTRACE_PROBE2(virtio, transport__config__changed, name, generation)
#define	VIRTIO_PROBE_RESET(name)					\
	DTRACE_PROBE1(virtio, transport__reset, name)
#define	VIRTIO_PROBE_LIFECYCLE(name, operation, phase, error)	\
	DTRACE_PROBE4(virtio, transport__lifecycle, name, operation, phase, \
	    error)
#define	VIRTIO_PROBE_ERROR(name, reason)				\
	DTRACE_PROBE2(virtio, transport__error, name, reason)
#define	VIRTIO_PROBE_NET_RX_HASH(name, queue, hash, report, length) \
	DTRACE_PROBE5(virtio, net__rx__hash, name, queue, hash, report, length)
#define	VIRTIO_PROBE_BALLOON_REQUEST(name, queue, seen, rejected, error) \
	DTRACE_PROBE5(virtio, balloon__request, name, queue, seen, rejected, \
	    error)
#define	VIRTIO_PROBE_BALLOON_DISCARD(name, gpa, length, error)	\
	DTRACE_PROBE4(virtio, balloon__discard, name, gpa, length, error)
#define	VIRTIO_PROBE_BALLOON_UNDISCARD(name, gpa, length, error)	\
	DTRACE_PROBE4(virtio, balloon__undiscard, name, gpa, length, error)
#define	VIRTIO_PROBE_BALLOON_CONFIG(name, target, actual)	\
	DTRACE_PROBE3(virtio, balloon__config, name, target, actual)
#define	VIRTIO_PROBE_BALLOON_POISON(name, value)			\
	DTRACE_PROBE2(virtio, balloon__poison, name, value)
#define	VIRTIO_PROBE_BALLOON_STATS(name, event, present, entries, ignored) \
	DTRACE_PROBE5(virtio, balloon__stats, name, event, present, entries, \
	    ignored)
#define	VIRTIO_PROBE_BALLOON_HINT(name, event, command, gpa, result) \
	DTRACE_PROBE5(virtio, balloon__hint, name, event, command, gpa, result)
#define	VIRTIO_PROBE_RTC_REQUEST(name, type, input, output, status) \
	DTRACE_PROBE5(virtio, rtc__request, name, type, input, output, status)
#define	VIRTIO_PROBE_RTC_ALARM(name, clock, event, result) \
	DTRACE_PROBE4(virtio, rtc__alarm, name, clock, event, result)
#define	VIRTIO_PROBE_GPU_COMMAND(name, queue, command, used, error) \
	DTRACE_PROBE5(virtio, gpu__command, name, queue, command, used, error)
#define	VIRTIO_PROBE_IOMMU_REQUEST(name, queue, type, used, error) \
	DTRACE_PROBE5(virtio, iommu__request, name, queue, type, used, error)
#define	VIRTIO_PROBE_IOMMU_FAULT(name, endpoint, reason, address, direction) \
	DTRACE_PROBE5(virtio, iommu__fault, name, endpoint, reason, address, \
	    direction)
#define	VIRTIO_PROBE_IOMMU_TRANSLATE(name, endpoint, address, length, ok) \
	DTRACE_PROBE5(virtio, iommu__translate, name, endpoint, address, \
	    length, ok)
#define	VIRTIO_PROBE_IOMMU_CONFIG(name, offset, size, value, error) \
	DTRACE_PROBE5(virtio, iommu__config, name, offset, size, value, error)
#define	VIRTIO_PROBE_IOMMU_TOPOLOGY(name, bdf, endpoints) \
	DTRACE_PROBE3(virtio, iommu__topology, name, bdf, endpoints)
#define	VIRTIO_PROBE_MEM_REQUEST(name, type, address, blocks, result) \
	DTRACE_PROBE5(virtio, mem__request, name, type, address, blocks, result)
#define	VIRTIO_PROBE_ADMIN_COMMAND(group, opcode, member, status, qualifier) \
	DTRACE_PROBE5(virtio, admin__command, group, opcode, member, status, \
	    qualifier)
#define	VIRTIO_PROBE_ADMIN_SRIOV_LIFECYCLE(capable, enable, migration, \
	    numvfs, generation) \
	DTRACE_PROBE5(virtio, admin__sriov__lifecycle, capable, enable, \
	    migration, numvfs, generation)
#define	VIRTIO_PROBE_FS_REQUEST(name, queue, readable, writable, error) \
	DTRACE_PROBE5(virtio, fs__request, name, queue, readable, writable, \
	    error)
#define	VIRTIO_PROBE_FS_COMPLETE(name, queue, used, discarded) \
	DTRACE_PROBE4(virtio, fs__complete, name, queue, used, discarded)
#define	VIRTIO_PROBE_FS_LATENCY(name, queue, nanoseconds, used, result) \
	DTRACE_PROBE5(virtio, fs__latency, name, queue, nanoseconds, used, \
	    result)
#define	VIRTIO_PROBE_FS_BACKEND(name, operation, pending, error) \
	DTRACE_PROBE4(virtio, fs__backend, name, operation, pending, error)
#define	VIRTIO_PROBE_FS_QUEUE_RESET(name, queue, generation, error) \
	DTRACE_PROBE4(virtio, fs__queue__reset, name, queue, generation, error)
#define	VIRTIO_PROBE_FS_PRESSURE(name, queue, pending, outgoing, error) \
	DTRACE_PROBE5(virtio, fs__pressure, name, queue, pending, outgoing, \
	    error)
#define	VIRTIO_PROBE_SOUND_IO(name, queue, bytes, playback, capture) \
	DTRACE_PROBE5(virtio, sound__io, name, queue, bytes, playback, capture)
#define	VIRTIO_PROBE_CONSOLE_EMERGENCY_WRITE(name, value, delivered) \
	DTRACE_PROBE3(virtio, console__emergency__write, name, value, delivered)
#define	VIRTIO_PROBE_SCSI_EVENT(name, stage, event, sequence, result) \
	DTRACE_PROBE5(virtio, scsi__event, name, stage, event, sequence, result)
#define	VIRTIO_PROBE_PMEM_FLUSH(name, stage, request, epoch, result) \
	DTRACE_PROBE5(virtio, pmem__flush, name, stage, request, epoch, result)

#endif

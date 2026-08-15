/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT providers for bhyve VirtIO devices and transports.  Vsock
 * probes fire alongside WPRINTF/DPRINTF logs so an
 * operator can observe and aggregate connection lifecycle, flow control,
 * backpressure, and rejected malformed-input events live -- without enabling
 * debug logging or restarting bhyve.  The provider name matches the SDT
 * provider in
 * the guest kernel (sys/kern/uipc_vsock.c), so the whole stack is observable
 * under one "vsock" name (kernel vs userland distinguished by pid).
 */
provider vsock {
	/* Connection lifecycle */
	probe conn__request(uint32_t cid, uint32_t port);
	probe conn__established(uint32_t cid, uint32_t port);
	probe conn__reset(uint32_t cid, uint32_t port, uint32_t state);
	probe conn__shutdown(uint32_t cid, uint32_t port, uint32_t flags);

	/* Flow control */
	probe credit__stall(uint32_t cid, uint32_t port);
	probe credit__update(uint32_t cid, uint32_t port, uint32_t fwd_cnt);

	/* Backpressure / resource ceilings (the WPRINTF reset sites) */
	probe tx__overflow(uint32_t cid, uint32_t port, uint32_t bytes);
	probe reasm__overflow(uint32_t cid, uint32_t port, uint32_t bytes);
	probe pend__drop(uint32_t pend_count);
	probe rx__ringfull(uint32_t cid, uint32_t port);

	/* Input validation: malformed or inconsistent guest input rejected */
	probe desc__drop(const char *why);

	/* Resource watermark */
	probe conn__count(uint32_t nconns);

	/*
	 * Relay socket buffer sizing.  Fires when the device sizes a
	 * host<->app Unix relay socket's buffers to one advertised window.
	 * got < want means the host's kern.ipc.maxsockbuf refused the full
	 * request and the single-record ceiling is lower than intended.
	 */
	probe relay__bufsize(uint32_t port, uint32_t want, uint32_t got);
};

/* Generic virtio transport probes, shared by present and future devices. */
provider virtio {
	probe transport__features(const char *device, uint64_t features);
	probe transport__status(const char *device, uint8_t old_status,
	    uint8_t new_status);
	probe transport__queue__enable(const char *device, uint16_t queue,
	    uint64_t desc, uint64_t used, uint16_t size);
	probe transport__queue__notify(const char *device, uint16_t queue);
	probe transport__descriptor__chain(const char *device, uint16_t queue,
	    uint8_t packed, uint8_t indirect, uint16_t descriptors);
	probe transport__event__idx(const char *device, uint16_t queue,
	    uint16_t event_idx, uint16_t produced_idx, uint8_t interrupt);
	probe transport__packed__event__idx(const char *device, uint16_t queue,
	    uint16_t event_off_wrap, uint16_t produced_off_wrap,
	    uint8_t interrupt);
	probe transport__queue__reset__begin(const char *device,
	    uint16_t queue, uint64_t generation);
	probe transport__queue__reset__end(const char *device, uint16_t queue,
	    uint64_t generation);
	probe transport__queue__reset__fail(const char *device, uint16_t queue,
	    uint64_t generation, int error);
	probe transport__cfg__window(const char *device, uint8_t bar,
	    uint32_t offset, uint32_t length, uint8_t is_write);
	probe transport__shared__memory(const char *device, uint8_t id,
	    const char *event, uint64_t length, uint8_t writable);
	probe transport__config__changed(const char *device,
	    uint8_t generation);
	probe transport__reset(const char *device);
	probe transport__lifecycle(const char *device, const char *operation,
	    const char *phase, int error);
	probe transport__error(const char *device, const char *reason);
	probe net__rx__hash(const char *device, uint16_t queue,
	    uint32_t hash, uint16_t report, uint32_t length);
	probe balloon__request(const char *device, uint16_t queue,
	    uint32_t seen, uint32_t rejected, int error);
	probe balloon__discard(const char *device, uint64_t gpa,
	    uint64_t length, int error);
	probe balloon__undiscard(const char *device, uint64_t gpa,
	    uint64_t length, int error);
	probe balloon__config(const char *device, uint32_t target,
	    uint32_t actual);
	probe balloon__poison(const char *device, uint32_t value);
	probe balloon__stats(const char *device, const char *event,
	    uint16_t present, uint32_t entries, uint32_t ignored);
	probe balloon__hint(const char *device, const char *event,
	    uint32_t command, uint64_t gpa, int64_t result);
	probe rtc__request(const char *device, uint16_t type,
	    uint64_t input_length, uint64_t output_length, uint8_t status);
	probe rtc__alarm(const char *device, uint16_t clock_id,
	    uint8_t event, int result);
	probe gpu__command(const char *device, uint16_t queue,
	    uint32_t command, uint32_t used_length, int error);
	probe iommu__request(const char *device, uint16_t queue,
	    uint8_t type, uint32_t used_length, int error);
	probe iommu__fault(const char *device, uint32_t endpoint,
	    uint8_t reason, uint64_t address, uint8_t direction);
	probe iommu__translate(const char *device, uint32_t endpoint,
	    uint64_t address, uint64_t length, uint8_t success);
	probe iommu__config(const char *device, uint32_t offset,
	    uint32_t size, uint32_t value, int error);
	probe iommu__topology(const char *device, uint16_t iommu_bdf,
	    uint32_t endpoints);
	probe mem__request(const char *device, uint16_t type,
	    uint64_t address, uint16_t blocks, int result);
	probe admin__command(uint16_t group, uint16_t opcode,
	    uint64_t member, uint16_t status, uint16_t qualifier);
	probe admin__sriov__lifecycle(uint8_t capable, uint8_t vf_enable,
	    uint8_t vf_migration_capable, uint16_t num_vfs,
	    uint64_t generation);
	probe fs__request(const char *device, uint16_t queue,
	    uint16_t readable, uint16_t writable, int error);
	probe fs__complete(const char *device, uint16_t queue,
	    uint32_t used, uint8_t discarded);
	probe fs__latency(const char *device, uint16_t queue,
	    uint64_t nanoseconds, uint32_t used, int result);
	probe fs__backend(const char *device, const char *operation,
	    uint32_t pending, int error);
	probe fs__queue__reset(const char *device, uint16_t queue,
	    uint64_t generation, int error);
	probe fs__pressure(const char *device, uint16_t queue,
	    uint32_t pending, uint32_t outgoing, int error);
	probe sound__io(const char *device, uint16_t queue, uint64_t bytes,
	    uint64_t playback_total, uint64_t capture_total);
	probe console__emergency__write(const char *device, uint8_t value,
	    uint8_t delivered);
	probe scsi__event(const char *device, const char *stage,
	    uint32_t event, uint64_t sequence, int result);
	probe pmem__flush(const char *device, const char *stage,
	    uint32_t request, uint64_t epoch, int result);
};

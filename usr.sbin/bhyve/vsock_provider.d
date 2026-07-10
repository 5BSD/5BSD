/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT provider for the bhyve virtio-vsock host device
 * (pci_virtio_vsock.c).  Probes fire alongside the WPRINTF/DPRINTF logs so an
 * operator can observe and aggregate connection lifecycle, flow control,
 * backpressure, and hostile-guest-input events live -- without enabling debug
 * logging or restarting bhyve.  The provider name matches the SDT provider in
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

	/* Security: malformed / spoofed guest input rejected */
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

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probe wrappers for the bhyve virtio-vsock host device.
 * Provider: vsock (see vsock_provider.d).  Every macro is a no-op unless the
 * binary was built WITH_DTRACE.  Each probe is fired next to the existing
 * WPRINTF/DPRINTF log at the same site in pci_virtio_vsock.c, so logs remain
 * the forensic record and probes add live, queryable, aggregatable telemetry.
 *
 * Example D scripts (bhyve pid = $target):
 *   dtrace -n 'vsock$target:::'                            all host-device probes
 *   dtrace -n 'vsock*:::desc-drop{ @[copyinstr(arg0)] = count(); }'   attack signal
 *   dtrace -n 'vsock*:::conn-reset{ @[arg0, arg1] = count(); }'       resets by cid:port
 *   dtrace -n 'vsock*:::tx-overflow{ @ = quantize(arg2); }'          backlog histogram
 */
#ifndef _PCI_VIRTIO_VSOCK_PROBES_H_
#define	_PCI_VIRTIO_VSOCK_PROBES_H_

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled (MK_DTRACE=no). */
#define	DTRACE_PROBE(...)
#define	DTRACE_PROBE1(...)
#define	DTRACE_PROBE2(...)
#define	DTRACE_PROBE3(...)
#endif

/* Connection lifecycle */
#define	VSOCK_PROBE_CONN_REQUEST(cid, port)		\
	DTRACE_PROBE2(vsock, conn__request, cid, port)
#define	VSOCK_PROBE_CONN_ESTABLISHED(cid, port)		\
	DTRACE_PROBE2(vsock, conn__established, cid, port)
#define	VSOCK_PROBE_CONN_RESET(cid, port, state)	\
	DTRACE_PROBE3(vsock, conn__reset, cid, port, state)
#define	VSOCK_PROBE_CONN_SHUTDOWN(cid, port, flags)	\
	DTRACE_PROBE3(vsock, conn__shutdown, cid, port, flags)

/* Flow control */
#define	VSOCK_PROBE_CREDIT_STALL(cid, port)		\
	DTRACE_PROBE2(vsock, credit__stall, cid, port)
#define	VSOCK_PROBE_CREDIT_UPDATE(cid, port, fwd_cnt)	\
	DTRACE_PROBE3(vsock, credit__update, cid, port, fwd_cnt)

/* Backpressure / resource ceilings */
#define	VSOCK_PROBE_TX_OVERFLOW(cid, port, bytes)	\
	DTRACE_PROBE3(vsock, tx__overflow, cid, port, bytes)
#define	VSOCK_PROBE_REASM_OVERFLOW(cid, port, bytes)	\
	DTRACE_PROBE3(vsock, reasm__overflow, cid, port, bytes)
#define	VSOCK_PROBE_PEND_DROP(pend_count)		\
	DTRACE_PROBE1(vsock, pend__drop, pend_count)
#define	VSOCK_PROBE_RX_RINGFULL(cid, port)		\
	DTRACE_PROBE2(vsock, rx__ringfull, cid, port)

/* Security: malformed / spoofed guest input rejected */
#define	VSOCK_PROBE_DESC_DROP(why)			\
	DTRACE_PROBE1(vsock, desc__drop, why)
/* Resource watermark */
#define	VSOCK_PROBE_CONN_COUNT(nconns)			\
	DTRACE_PROBE1(vsock, conn__count, nconns)

/* Relay socket buffer sizing (host<->app Unix socket) */
#define	VSOCK_PROBE_RELAY_BUFSIZE(port, want, got)	\
	DTRACE_PROBE3(vsock, relay__bufsize, port, want, got)

#endif /* _PCI_VIRTIO_VSOCK_PROBES_H_ */

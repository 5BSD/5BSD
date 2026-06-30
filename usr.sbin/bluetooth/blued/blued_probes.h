/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for blued.
 *
 * Provider: blued
 *
 * Usage:
 *   dtrace -n 'blued*:::'              -- trace all probes
 *   dtrace -n 'blued*:::conn-*'        -- trace connection lifecycle
 *   dtrace -n 'blued*:::att-*'         -- trace ATT PDUs
 *   dtrace -n 'blued*:::smp-*'         -- trace SMP pairing
 *   dtrace -n 'blued*:::ctl-*'         -- trace control commands
 *   dtrace -n 'blued*:::hid-*'         -- trace HID reports
 */

#ifndef BLUED_PROBES_H
#define BLUED_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE(...)
#define	DTRACE_PROBE1(...)
#define	DTRACE_PROBE2(...)
#define	DTRACE_PROBE3(...)
#define	DTRACE_PROBE4(...)
#endif

/* Connection lifecycle */
#define	BLUED_PROBE_CONN_OPEN(addr, role)	\
	DTRACE_PROBE2(blued, conn__open, addr, role)
#define	BLUED_PROBE_CONN_CLOSE(addr, reason)	\
	DTRACE_PROBE2(blued, conn__close, addr, reason)

/* ATT PDU tracing */
#define	BLUED_PROBE_ATT_RECV(opcode, len)	\
	DTRACE_PROBE2(blued, att__recv, opcode, len)
#define	BLUED_PROBE_ATT_SEND(opcode, len)	\
	DTRACE_PROBE2(blued, att__send, opcode, len)

/* SMP pairing */
#define	BLUED_PROBE_SMP_PAIR_START(addr, method)	\
	DTRACE_PROBE2(blued, smp__pair__start, addr, method)
#define	BLUED_PROBE_SMP_PAIR_DONE(addr, status)	\
	DTRACE_PROBE2(blued, smp__pair__done, addr, status)

/* Control socket */
#define	BLUED_PROBE_CTL_CMD(cmd)	\
	DTRACE_PROBE1(blued, ctl__cmd, cmd)

/* HID report injection */
#define	BLUED_PROBE_HID_REPORT(report_id, len)	\
	DTRACE_PROBE2(blued, hid__report, report_id, len)

/* Bond database operations */
#define	BLUED_PROBE_BOND_ADD(addr, sc)	\
	DTRACE_PROBE2(blued, bond__add, addr, sc)
#define	BLUED_PROBE_BOND_REMOVE(addr)	\
	DTRACE_PROBE1(blued, bond__remove, addr)
#define	BLUED_PROBE_BOND_LOAD(count)	\
	DTRACE_PROBE1(blued, bond__load, count)
#define	BLUED_PROBE_BOND_SAVE(count)	\
	DTRACE_PROBE1(blued, bond__save, count)

/* GATT database changes */
#define	BLUED_PROBE_GATT_SVC_ADD(handle, uuid)	\
	DTRACE_PROBE2(blued, gatt__svc__add, handle, uuid)
#define	BLUED_PROBE_GATT_SVC_REMOVE(handle)	\
	DTRACE_PROBE1(blued, gatt__svc__remove, handle)

/* Scan operations */
#define	BLUED_PROBE_SCAN_START(adapter)	\
	DTRACE_PROBE1(blued, scan__start, adapter)
#define	BLUED_PROBE_SCAN_RESULT(addr, rssi)	\
	DTRACE_PROBE2(blued, scan__result, addr, rssi)

/* Security events */
#define	BLUED_PROBE_ENCRYPT_START(addr)	\
	DTRACE_PROBE1(blued, encrypt__start, addr)
#define	BLUED_PROBE_AUTH_FAIL(addr, reason)	\
	DTRACE_PROBE2(blued, auth__fail, addr, reason)

/* Capsicum sandbox */
#define	BLUED_PROBE_SANDBOX_ENTER()	\
	DTRACE_PROBE(blued, sandbox__enter)

#endif /* BLUED_PROBES_H */

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
 *
 * Three interchangeable backends are selected at compile time:
 *
 *   (default)          BLUED_PROBE_x(...) expands to nothing.
 *   -DWITH_DTRACE      BLUED_PROBE_x(...) fires a DTrace USDT probe.
 *   -DWITH_PROBE_TAP   BLUED_PROBE_x(...) appends a record to an
 *                      in-process ring buffer (blued_probe_tap.[ch]) so
 *                      ATF unit tests can observe/assert protocol steps.
 *
 * The three branches are mutually exclusive; every BLUED_PROBE_* macro is
 * defined in exactly one of them so the daemon builds clean under -Werror
 * in all three modes.
 */

#ifndef BLUED_PROBES_H
#define BLUED_PROBES_H

#if defined(WITH_PROBE_TAP)

/* ================================================================
 * Backend 3: in-process probe tap (test observability).
 * Each macro records the probe name, its integer args (widened to
 * uint64_t), and -- for probes that carry a string -- a copy of the
 * most useful string argument.
 * ================================================================ */
#include "blued_probe_tap.h"

/* Connection lifecycle */
#define	BLUED_PROBE_CONN_OPEN(addr, role)	\
	probe_tap_rec1("conn:open", (addr), (uint64_t)(role))
#define	BLUED_PROBE_CONN_CLOSE(addr, reason)	\
	probe_tap_rec1("conn:close", (addr), (uint64_t)(reason))

/* ATT PDU tracing */
#define	BLUED_PROBE_ATT_RECV(opcode, len)	\
	probe_tap_rec2("att:recv", NULL, (uint64_t)(opcode), (uint64_t)(len))
#define	BLUED_PROBE_ATT_SEND(opcode, len)	\
	probe_tap_rec2("att:send", NULL, (uint64_t)(opcode), (uint64_t)(len))
#define	BLUED_PROBE_ATT_ERROR(req_op, handle, code)	\
	probe_tap_rec3("att:error", NULL, (uint64_t)(req_op),	\
	    (uint64_t)(handle), (uint64_t)(code))
#define	BLUED_PROBE_ATT_ROBUST_TRANSITION(from, to, trigger)	\
	probe_tap_rec3("att:robust:transition", NULL, (uint64_t)(from),	\
	    (uint64_t)(to), (uint64_t)(trigger))

/* GATT discovery / database changes */
#define	BLUED_PROBE_GATT_DISC_STEP(proc, start, end, found)	\
	probe_tap_rec4("gatt:disc:step", NULL, (uint64_t)(proc),	\
	    (uint64_t)(start), (uint64_t)(end), (uint64_t)(found))
#define	BLUED_PROBE_GATT_SVC_ADD(handle, uuid)	\
	probe_tap_rec2("gatt:svc:add", NULL, (uint64_t)(handle), (uint64_t)(uuid))
#define	BLUED_PROBE_GATT_SVC_REMOVE(handle)	\
	probe_tap_rec1("gatt:svc:remove", NULL, (uint64_t)(handle))

/* SMP pairing */
#define	BLUED_PROBE_SMP_PAIR_START(addr, method)	\
	probe_tap_rec1("smp:pair:start", (addr), (uint64_t)(method))
#define	BLUED_PROBE_SMP_PAIR_DONE(addr, status)	\
	probe_tap_rec1("smp:pair:done", (addr), (uint64_t)(status))
#define	BLUED_PROBE_SMP_METHOD_SELECT(addr, init_io, resp_io, authreq, model) \
	probe_tap_rec4("smp:method:select", (addr), (uint64_t)(init_io),	\
	    (uint64_t)(resp_io), (uint64_t)(authreq), (uint64_t)(model))
/* smp:phase carries two strings (addr, phase); the tap stores the phase
 * name -- that is what a phase-sequence assertion keys on. */
#define	BLUED_PROBE_SMP_PHASE(addr, phase)	\
	probe_tap_rec0("smp:phase", (phase))
#define	BLUED_PROBE_SMP_TIMEOUT(addr)	\
	probe_tap_rec0("smp:timeout", (addr))

/* HID report injection */
#define	BLUED_PROBE_HID_REPORT(report_id, len)	\
	probe_tap_rec2("hid:report", NULL, (uint64_t)(report_id), (uint64_t)(len))

/* Bond database operations */
#define	BLUED_PROBE_BOND_ADD(addr, sc)	\
	probe_tap_rec1("bond:add", (addr), (uint64_t)(sc))
#define	BLUED_PROBE_BOND_REMOVE(addr)	\
	probe_tap_rec0("bond:remove", (addr))
#define	BLUED_PROBE_BOND_LOAD(count)	\
	probe_tap_rec1("bond:load", NULL, (uint64_t)(count))
#define	BLUED_PROBE_BOND_SAVE(count)	\
	probe_tap_rec1("bond:save", NULL, (uint64_t)(count))

/* Scan operations */
#define	BLUED_PROBE_SCAN_START(adapter)	\
	probe_tap_rec0("scan:start", (adapter))
#define	BLUED_PROBE_SCAN_RESULT(addr, rssi)	\
	probe_tap_rec1("scan:result", (addr), (uint64_t)(rssi))

/* Security events */
#define	BLUED_PROBE_ENCRYPT_START(addr)	\
	probe_tap_rec0("encrypt:start", (addr))
#define	BLUED_PROBE_AUTH_FAIL(addr, reason)	\
	probe_tap_rec1("auth:fail", (addr), (uint64_t)(reason))

/* Capsicum sandbox */
#define	BLUED_PROBE_SANDBOX_ENTER()	\
	probe_tap_rec0("sandbox:enter", NULL)

/* ----------------------------------------------------------------
 * Expanded observability set (tap backend).  Every macro below maps
 * 1:1 to a probe already declared in blued_provider.d.  The tap keeps
 * at most one string (the address / step / rpa) plus up to four int
 * args; no macro emits secret key material -- only opcodes, handles,
 * lengths, reason codes, verdicts and sequence-ish scalars.
 * ---------------------------------------------------------------- */

/* SMP: per-PDU flow, crypto step boundaries, key distribution, timer */
#define	BLUED_PROBE_SMP_PDU_TX(addr, opcode, len)	\
	probe_tap_rec2("smp:pdu:tx", (addr), (uint64_t)(opcode), (uint64_t)(len))
#define	BLUED_PROBE_SMP_PDU_RX(addr, opcode, len)	\
	probe_tap_rec2("smp:pdu:rx", (addr), (uint64_t)(opcode), (uint64_t)(len))
#define	BLUED_PROBE_SMP_FAIL_RX(addr, reason)	\
	probe_tap_rec1("smp:fail:rx", (addr), (uint64_t)(reason))
#define	BLUED_PROBE_SMP_CRYPTO(step, handle)	\
	probe_tap_rec1("smp:crypto", (step), (uint64_t)(handle))
#define	BLUED_PROBE_SMP_DHKEY(addr)	\
	probe_tap_rec0("smp:dhkey", (addr))
#define	BLUED_PROBE_SMP_KEY_DIST(addr, keytype)	\
	probe_tap_rec1("smp:key:dist", (addr), (uint64_t)(keytype))
#define	BLUED_PROBE_SMP_KEY_RECV(addr, keytype)	\
	probe_tap_rec1("smp:key:recv", (addr), (uint64_t)(keytype))
#define	BLUED_PROBE_SMP_TIMER_ARM(addr, seconds)	\
	probe_tap_rec1("smp:timer:arm", (addr), (uint64_t)(seconds))

/* ATT: MTU, notify/indicate/confirm, client error, robust caching */
#define	BLUED_PROBE_ATT_MTU(role, client_mtu, server_mtu, mtu)	\
	probe_tap_rec4("att:mtu", NULL, (uint64_t)(role),	\
	    (uint64_t)(client_mtu), (uint64_t)(server_mtu), (uint64_t)(mtu))
#define	BLUED_PROBE_ATT_NOTIFY(handle, len)	\
	probe_tap_rec2("att:notify", NULL, (uint64_t)(handle), (uint64_t)(len))
#define	BLUED_PROBE_ATT_INDICATE(handle, len)	\
	probe_tap_rec2("att:indicate", NULL, (uint64_t)(handle), (uint64_t)(len))
#define	BLUED_PROBE_ATT_NOTIFY_MULTI(count, len)	\
	probe_tap_rec2("att:notify:multi", NULL, (uint64_t)(count), (uint64_t)(len))
#define	BLUED_PROBE_ATT_CONFIRM(handle)	\
	probe_tap_rec1("att:confirm", NULL, (uint64_t)(handle))
#define	BLUED_PROBE_ATT_CLIENT_ERROR(req_op, handle, code)	\
	probe_tap_rec3("att:client:error", NULL, (uint64_t)(req_op),	\
	    (uint64_t)(handle), (uint64_t)(code))
#define	BLUED_PROBE_ATT_CACHE_OOS(handle)	\
	probe_tap_rec1("att:cache:oos", NULL, (uint64_t)(handle))
#define	BLUED_PROBE_ATT_CACHE_AWARE(trigger)	\
	probe_tap_rec1("att:cache:aware", NULL, (uint64_t)(trigger))
#define	BLUED_PROBE_ATT_CACHE_HASH(len)	\
	probe_tap_rec1("att:cache:hash", NULL, (uint64_t)(len))
#define	BLUED_PROBE_ATT_CACHE_INVALIDATE(nconn)	\
	probe_tap_rec1("att:cache:invalidate", NULL, (uint64_t)(nconn))

/* GATT: characteristic add, CCCD write, subscription */
#define	BLUED_PROBE_GATT_CHAR_ADD(handle, uuid, props)	\
	probe_tap_rec3("gatt:char:add", NULL, (uint64_t)(handle),	\
	    (uint64_t)(uuid), (uint64_t)(props))
#define	BLUED_PROBE_GATT_CCCD_WRITE(handle, value)	\
	probe_tap_rec2("gatt:cccd:write", NULL, (uint64_t)(handle), (uint64_t)(value))
#define	BLUED_PROBE_GATT_SUBSCRIBE(addr, handle)	\
	probe_tap_rec1("gatt:subscribe", (addr), (uint64_t)(handle))
#define	BLUED_PROBE_GATT_UNSUBSCRIBE(addr, handle)	\
	probe_tap_rec1("gatt:unsubscribe", (addr), (uint64_t)(handle))

/* HCI: command chokepoint, disconnect, LE connection/encryption/LTK */
#define	BLUED_PROBE_HCI_CMD_REQ(opcode, status, clen)	\
	probe_tap_rec3("hci:cmd:req", NULL, (uint64_t)(opcode),	\
	    (uint64_t)(status), (uint64_t)(clen))
#define	BLUED_PROBE_HCI_CMD_RAW(opcode, plen)	\
	probe_tap_rec2("hci:cmd:raw", NULL, (uint64_t)(opcode), (uint64_t)(plen))
#define	BLUED_PROBE_HCI_DISCONNECT_REQ(handle, reason)	\
	probe_tap_rec2("hci:disconnect:req", NULL, (uint64_t)(handle),	\
	    (uint64_t)(reason))
#define	BLUED_PROBE_HCI_LE_CONN_COMPLETE(status, handle, role, interval)	\
	probe_tap_rec4("hci:le:conn:complete", NULL, (uint64_t)(status),	\
	    (uint64_t)(handle), (uint64_t)(role), (uint64_t)(interval))
#define	BLUED_PROBE_HCI_LE_ENH_CONN_COMPLETE(status, handle, role, interval) \
	probe_tap_rec4("hci:le:enh:conn:complete", NULL, (uint64_t)(status), \
	    (uint64_t)(handle), (uint64_t)(role), (uint64_t)(interval))
#define	BLUED_PROBE_HCI_ENC_CHANGE(status, handle, enabled, key_size)	\
	probe_tap_rec4("hci:enc:change", NULL, (uint64_t)(status),	\
	    (uint64_t)(handle), (uint64_t)(enabled), (uint64_t)(key_size))
#define	BLUED_PROBE_HCI_LE_LTK_REQUEST(handle, ediv, rand)	\
	probe_tap_rec3("hci:le:ltk:request", NULL, (uint64_t)(handle),	\
	    (uint64_t)(ediv), (uint64_t)(rand))
#define	BLUED_PROBE_HCI_LE_ADV_REPORT(addr, addr_type, event_type, rssi) \
	probe_tap_rec3("hci:le:adv:report", (addr), (uint64_t)(addr_type), \
	    (uint64_t)(event_type), (uint64_t)(rssi))
#define	BLUED_PROBE_HCI_LE_EXT_ADV_REPORT(addr, addr_type, event_type, rssi) \
	probe_tap_rec3("hci:le:ext:adv:report", (addr), (uint64_t)(addr_type), \
	    (uint64_t)(event_type), (uint64_t)(rssi))

/* GAP: connection state, advertising / scan lifecycle */
#define	BLUED_PROBE_CONN_STATE(handle, old_state, new_state)	\
	probe_tap_rec3("conn:state", NULL, (uint64_t)(handle),	\
	    (uint64_t)(old_state), (uint64_t)(new_state))
#define	BLUED_PROBE_GAP_ADV_PARAMS(interval_min, interval_max)	\
	probe_tap_rec2("gap:adv:params", NULL, (uint64_t)(interval_min),	\
	    (uint64_t)(interval_max))
#define	BLUED_PROBE_GAP_ADV_ENABLE(enable, handle)	\
	probe_tap_rec2("gap:adv:enable", NULL, (uint64_t)(enable), (uint64_t)(handle))
#define	BLUED_PROBE_GAP_ADV_DATA(len)	\
	probe_tap_rec1("gap:adv:data", NULL, (uint64_t)(len))
#define	BLUED_PROBE_GAP_SCAN_PARAMS(interval, window)	\
	probe_tap_rec2("gap:scan:params", NULL, (uint64_t)(interval),	\
	    (uint64_t)(window))
#define	BLUED_PROBE_GAP_SCAN_ENABLE(enable, filter_dup)	\
	probe_tap_rec2("gap:scan:enable", NULL, (uint64_t)(enable),	\
	    (uint64_t)(filter_dup))

#define	BLUED_PROBE_PER_ADV_PARAMS(min, max)	\
	probe_tap_rec2("per:adv:params", NULL, (uint64_t)(min), (uint64_t)(max))
#define	BLUED_PROBE_PER_ADV_SYNC(handle, status)	\
	probe_tap_rec2("per:adv:sync", NULL, (uint64_t)(handle), (uint64_t)(status))
#define	BLUED_PROBE_PER_ADV_REPORT(handle, len)	\
	probe_tap_rec2("per:adv:report", NULL, (uint64_t)(handle), (uint64_t)(len))
#define	BLUED_PROBE_PAST_RECEIVE_ENABLE(handle, enable)	\
	probe_tap_rec2("past:receive:enable", NULL, (uint64_t)(handle), (uint64_t)(enable))
#define	BLUED_PROBE_PAST_TRANSFER(handle, service_data)	\
	probe_tap_rec2("past:transfer", NULL, (uint64_t)(handle), (uint64_t)(service_data))
#define	BLUED_PROBE_PATH_LOSS(handle, loss, zone)	\
	probe_tap_rec3("power:path-loss", NULL, (uint64_t)(handle), (uint64_t)(loss), (uint64_t)(zone))

/* Privacy / RPA (rpa string already log-safe: it is a resolvable random addr) */
#define	BLUED_PROBE_PRIVACY_RPA_GENERATE(rpa)	\
	probe_tap_rec0("privacy:rpa:generate", (rpa))
#define	BLUED_PROBE_PRIVACY_RPA_ROTATE(rpa)	\
	probe_tap_rec0("privacy:rpa:rotate", (rpa))
#define	BLUED_PROBE_PRIVACY_RESOLVE(addr, matched)	\
	probe_tap_rec1("privacy:resolve", (addr), (uint64_t)(matched))
#define	BLUED_PROBE_PRIVACY_IRK_LOAD(generated)	\
	probe_tap_rec1("privacy:irk:load", NULL, (uint64_t)(generated))
#define	BLUED_PROBE_PRIVACY_RESLIST_LOAD(count)	\
	probe_tap_rec1("privacy:reslist:load", NULL, (uint64_t)(count))

#else /* !WITH_PROBE_TAP */

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE(...)
#define	DTRACE_PROBE1(...)
#define	DTRACE_PROBE2(...)
#define	DTRACE_PROBE3(...)
#define	DTRACE_PROBE4(...)
#define	DTRACE_PROBE5(...)
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
#define	BLUED_PROBE_ATT_ERROR(req_op, handle, code)	\
	DTRACE_PROBE3(blued, att__error, req_op, handle, code)
#define	BLUED_PROBE_ATT_ROBUST_TRANSITION(from, to, trigger)	\
	DTRACE_PROBE3(blued, att__robust__transition, from, to, trigger)

/* GATT discovery / database changes */
#define	BLUED_PROBE_GATT_DISC_STEP(proc, start, end, found)	\
	DTRACE_PROBE4(blued, gatt__disc__step, proc, start, end, found)
#define	BLUED_PROBE_GATT_SVC_ADD(handle, uuid)	\
	DTRACE_PROBE2(blued, gatt__svc__add, handle, uuid)
#define	BLUED_PROBE_GATT_SVC_REMOVE(handle)	\
	DTRACE_PROBE1(blued, gatt__svc__remove, handle)

/* SMP pairing */
#define	BLUED_PROBE_SMP_PAIR_START(addr, method)	\
	DTRACE_PROBE2(blued, smp__pair__start, addr, method)
#define	BLUED_PROBE_SMP_PAIR_DONE(addr, status)	\
	DTRACE_PROBE2(blued, smp__pair__done, addr, status)
#define	BLUED_PROBE_SMP_METHOD_SELECT(addr, init_io, resp_io, authreq, model) \
	DTRACE_PROBE5(blued, smp__method__select, addr, init_io, resp_io, \
	    authreq, model)
#define	BLUED_PROBE_SMP_PHASE(addr, phase)	\
	DTRACE_PROBE2(blued, smp__phase, addr, phase)
#define	BLUED_PROBE_SMP_TIMEOUT(addr)	\
	DTRACE_PROBE1(blued, smp__timeout, addr)

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

/* ----------------------------------------------------------------
 * Expanded observability set (USDT / no-op backend).  Each macro maps
 * 1:1 to a probe declared in blued_provider.d.
 * ---------------------------------------------------------------- */

/* SMP: per-PDU flow, crypto step boundaries, key distribution, timer */
#define	BLUED_PROBE_SMP_PDU_TX(addr, opcode, len)	\
	DTRACE_PROBE3(blued, smp__pdu__tx, addr, opcode, len)
#define	BLUED_PROBE_SMP_PDU_RX(addr, opcode, len)	\
	DTRACE_PROBE3(blued, smp__pdu__rx, addr, opcode, len)
#define	BLUED_PROBE_SMP_FAIL_RX(addr, reason)	\
	DTRACE_PROBE2(blued, smp__fail__rx, addr, reason)
#define	BLUED_PROBE_SMP_CRYPTO(step, handle)	\
	DTRACE_PROBE2(blued, smp__crypto, step, handle)
#define	BLUED_PROBE_SMP_DHKEY(addr)	\
	DTRACE_PROBE1(blued, smp__dhkey, addr)
#define	BLUED_PROBE_SMP_KEY_DIST(addr, keytype)	\
	DTRACE_PROBE2(blued, smp__key__dist, addr, keytype)
#define	BLUED_PROBE_SMP_KEY_RECV(addr, keytype)	\
	DTRACE_PROBE2(blued, smp__key__recv, addr, keytype)
#define	BLUED_PROBE_SMP_TIMER_ARM(addr, seconds)	\
	DTRACE_PROBE2(blued, smp__timer__arm, addr, seconds)

/* ATT: MTU, notify/indicate/confirm, client error, robust caching */
#define	BLUED_PROBE_ATT_MTU(role, client_mtu, server_mtu, mtu)	\
	DTRACE_PROBE4(blued, att__mtu, role, client_mtu, server_mtu, mtu)
#define	BLUED_PROBE_ATT_NOTIFY(handle, len)	\
	DTRACE_PROBE2(blued, att__notify, handle, len)
#define	BLUED_PROBE_ATT_INDICATE(handle, len)	\
	DTRACE_PROBE2(blued, att__indicate, handle, len)
#define	BLUED_PROBE_ATT_NOTIFY_MULTI(count, len)	\
	DTRACE_PROBE2(blued, att__notify__multi, count, len)
#define	BLUED_PROBE_ATT_CONFIRM(handle)	\
	DTRACE_PROBE1(blued, att__confirm, handle)
#define	BLUED_PROBE_ATT_CLIENT_ERROR(req_op, handle, code)	\
	DTRACE_PROBE3(blued, att__client__error, req_op, handle, code)
#define	BLUED_PROBE_ATT_CACHE_OOS(handle)	\
	DTRACE_PROBE1(blued, att__cache__oos, handle)
#define	BLUED_PROBE_ATT_CACHE_AWARE(trigger)	\
	DTRACE_PROBE1(blued, att__cache__aware, trigger)
#define	BLUED_PROBE_ATT_CACHE_HASH(len)	\
	DTRACE_PROBE1(blued, att__cache__hash, len)
#define	BLUED_PROBE_ATT_CACHE_INVALIDATE(nconn)	\
	DTRACE_PROBE1(blued, att__cache__invalidate, nconn)

/* GATT: characteristic add, CCCD write, subscription */
#define	BLUED_PROBE_GATT_CHAR_ADD(handle, uuid, props)	\
	DTRACE_PROBE3(blued, gatt__char__add, handle, uuid, props)
#define	BLUED_PROBE_GATT_CCCD_WRITE(handle, value)	\
	DTRACE_PROBE2(blued, gatt__cccd__write, handle, value)
#define	BLUED_PROBE_GATT_SUBSCRIBE(addr, handle)	\
	DTRACE_PROBE2(blued, gatt__subscribe, addr, handle)
#define	BLUED_PROBE_GATT_UNSUBSCRIBE(addr, handle)	\
	DTRACE_PROBE2(blued, gatt__unsubscribe, addr, handle)

/* HCI: command chokepoint, disconnect, LE connection/encryption/LTK */
#define	BLUED_PROBE_HCI_CMD_REQ(opcode, status, clen)	\
	DTRACE_PROBE3(blued, hci__cmd__req, opcode, status, clen)
#define	BLUED_PROBE_HCI_CMD_RAW(opcode, plen)	\
	DTRACE_PROBE2(blued, hci__cmd__raw, opcode, plen)
#define	BLUED_PROBE_HCI_DISCONNECT_REQ(handle, reason)	\
	DTRACE_PROBE2(blued, hci__disconnect__req, handle, reason)
#define	BLUED_PROBE_HCI_LE_CONN_COMPLETE(status, handle, role, interval)	\
	DTRACE_PROBE4(blued, hci__le__conn__complete, status, handle, role, \
	    interval)
#define	BLUED_PROBE_HCI_LE_ENH_CONN_COMPLETE(status, handle, role, interval) \
	DTRACE_PROBE4(blued, hci__le__enh__conn__complete, status, handle, \
	    role, interval)
#define	BLUED_PROBE_HCI_ENC_CHANGE(status, handle, enabled, key_size)	\
	DTRACE_PROBE4(blued, hci__enc__change, status, handle, enabled, key_size)
#define	BLUED_PROBE_HCI_LE_LTK_REQUEST(handle, ediv, rand)	\
	DTRACE_PROBE3(blued, hci__le__ltk__request, handle, ediv, rand)
#define	BLUED_PROBE_HCI_LE_ADV_REPORT(addr, addr_type, event_type, rssi) \
	DTRACE_PROBE4(blued, hci__le__adv__report, addr, addr_type, \
	    event_type, rssi)
#define	BLUED_PROBE_HCI_LE_EXT_ADV_REPORT(addr, addr_type, event_type, rssi) \
	DTRACE_PROBE4(blued, hci__le__ext__adv__report, addr, addr_type, \
	    event_type, rssi)

/* GAP: connection state, advertising / scan lifecycle */
#define	BLUED_PROBE_CONN_STATE(handle, old_state, new_state)	\
	DTRACE_PROBE3(blued, conn__state, handle, old_state, new_state)
#define	BLUED_PROBE_GAP_ADV_PARAMS(interval_min, interval_max)	\
	DTRACE_PROBE2(blued, gap__adv__params, interval_min, interval_max)
#define	BLUED_PROBE_GAP_ADV_ENABLE(enable, handle)	\
	DTRACE_PROBE2(blued, gap__adv__enable, enable, handle)
#define	BLUED_PROBE_GAP_ADV_DATA(len)	\
	DTRACE_PROBE1(blued, gap__adv__data, len)
#define	BLUED_PROBE_GAP_SCAN_PARAMS(interval, window)	\
	DTRACE_PROBE2(blued, gap__scan__params, interval, window)
#define	BLUED_PROBE_GAP_SCAN_ENABLE(enable, filter_dup)	\
	DTRACE_PROBE2(blued, gap__scan__enable, enable, filter_dup)

#define	BLUED_PROBE_PER_ADV_PARAMS(min, max)	\
	DTRACE_PROBE2(blued, per__adv__params, min, max)
#define	BLUED_PROBE_PER_ADV_SYNC(handle, status)	\
	DTRACE_PROBE2(blued, per__adv__sync, handle, status)
#define	BLUED_PROBE_PER_ADV_REPORT(handle, len)	\
	DTRACE_PROBE2(blued, per__adv__report, handle, len)
#define	BLUED_PROBE_PAST_RECEIVE_ENABLE(handle, enable)	\
	DTRACE_PROBE2(blued, past__receive__enable, handle, enable)
#define	BLUED_PROBE_PAST_TRANSFER(handle, service_data)	\
	DTRACE_PROBE2(blued, past__transfer, handle, service_data)
#define	BLUED_PROBE_PATH_LOSS(handle, loss, zone)	\
	DTRACE_PROBE3(blued, power__path__loss, handle, loss, zone)

/* Privacy / RPA */
#define	BLUED_PROBE_PRIVACY_RPA_GENERATE(rpa)	\
	DTRACE_PROBE1(blued, privacy__rpa__generate, rpa)
#define	BLUED_PROBE_PRIVACY_RPA_ROTATE(rpa)	\
	DTRACE_PROBE1(blued, privacy__rpa__rotate, rpa)
#define	BLUED_PROBE_PRIVACY_RESOLVE(addr, matched)	\
	DTRACE_PROBE2(blued, privacy__resolve, addr, matched)
#define	BLUED_PROBE_PRIVACY_IRK_LOAD(generated)	\
	DTRACE_PROBE1(blued, privacy__irk__load, generated)
#define	BLUED_PROBE_PRIVACY_RESLIST_LOAD(count)	\
	DTRACE_PROBE1(blued, privacy__reslist__load, count)

#endif /* WITH_PROBE_TAP */

#endif /* BLUED_PROBES_H */

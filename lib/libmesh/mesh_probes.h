/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for libmesh (BLE Mesh).
 *
 * Provider: mesh (see mesh_provider.d).  A leaf name's "__" renders as "-"
 * in the DTrace probe name, e.g. mesh__net__decrypt -> mesh$target:::mesh-net-decrypt.
 *
 * Three interchangeable backends are selected at compile time, mirroring
 * blued_probes.h:
 *
 *   (default)              MESH_PROBE_x(...) expands to nothing (zero cost).
 *   -DMESH_DTRACE_PROBES   MESH_PROBE_x(...) fires a `mesh` USDT probe,
 *                          is-enabled-gated so it is free when not traced.
 *                          The libmesh Makefile also adds mesh_provider.d to
 *                          SRCS in this mode so the provider object links.
 *   -DMESH_WITH_PROBE_TAP  MESH_PROBE_x(...) appends a record to the shared
 *                          in-process probe tap (blued_probe_tap.[ch]) so ATF
 *                          tests can assert the exact probe sequence.
 *
 * Firm rule: probes NEVER emit secret key material (NetKey/AppKey/DevKey/
 * private keys).  They carry observable protocol facts only -- addresses,
 * sequence numbers, IV index, opcodes, lengths, verdicts and reason codes.
 */

#ifndef MESH_PROBES_H
#define MESH_PROBES_H

#if defined(MESH_WITH_PROBE_TAP)

/* ================================================================
 * Backend 3: in-process probe tap (shared with blued's tap).
 * ================================================================ */
#include "blued_probe_tap.h"

/* Network layer */
#define	MESH_PROBE_NET_ENCRYPT(src, dst, seq, ttl)	\
	probe_tap_rec4("mesh:net:encrypt", NULL, (uint64_t)(src),	\
	    (uint64_t)(dst), (uint64_t)(seq), (uint64_t)(ttl))
#define	MESH_PROBE_NET_DECRYPT(nid, src, result)	\
	probe_tap_rec3("mesh:net:decrypt", NULL, (uint64_t)(nid),	\
	    (uint64_t)(src), (uint64_t)(result))
#define	MESH_PROBE_NET_NID_MATCH(local_nid, pdu_nid, matched)	\
	probe_tap_rec3("mesh:net:nid:match", NULL, (uint64_t)(local_nid),	\
	    (uint64_t)(pdu_nid), (uint64_t)(matched))
#define	MESH_PROBE_NET_RELAY(src, ttl, new_ttl, decision)	\
	probe_tap_rec4("mesh:net:relay", NULL, (uint64_t)(src),	\
	    (uint64_t)(ttl), (uint64_t)(new_ttl), (uint64_t)(decision))

/* Transport layer */
#define	MESH_PROBE_TRANSPORT_ENC(akf, szmic, len)	\
	probe_tap_rec3("mesh:transport:enc", NULL, (uint64_t)(akf),	\
	    (uint64_t)(szmic), (uint64_t)(len))
#define	MESH_PROBE_TRANSPORT_DEC(akf, result)	\
	probe_tap_rec2("mesh:transport:dec", NULL, (uint64_t)(akf),	\
	    (uint64_t)(result))
#define	MESH_PROBE_TRANSPORT_SEG(seqzero, sego, segn)	\
	probe_tap_rec3("mesh:transport:seg", NULL, (uint64_t)(seqzero),	\
	    (uint64_t)(sego), (uint64_t)(segn))
#define	MESH_PROBE_TRANSPORT_REASM(src, seg, complete)	\
	probe_tap_rec3("mesh:transport:reasm", NULL, (uint64_t)(src),	\
	    (uint64_t)(seg), (uint64_t)(complete))
#define	MESH_PROBE_SEG_ACK(seqzero, blockack)	\
	probe_tap_rec2("mesh:seg:ack", NULL, (uint64_t)(seqzero),	\
	    (uint64_t)(blockack))

/* Access / model dispatch */
#define	MESH_PROBE_ACCESS_DISPATCH(opcode, src, dst)	\
	probe_tap_rec3("mesh:access:dispatch", NULL, (uint64_t)(opcode),	\
	    (uint64_t)(src), (uint64_t)(dst))
#define	MESH_PROBE_ACCESS_PARSE(opcode, len)	\
	probe_tap_rec2("mesh:access:parse", NULL, (uint64_t)(opcode),	\
	    (uint64_t)(len))

/* Replay protection */
#define	MESH_PROBE_RPL_CHECK(src, seq, accepted)	\
	probe_tap_rec3("mesh:rpl:check", NULL, (uint64_t)(src),	\
	    (uint64_t)(seq), (uint64_t)(accepted))
#define	MESH_PROBE_RPL_NET_RECV(src, accepted)	\
	probe_tap_rec2("mesh:rpl:net:recv", NULL, (uint64_t)(src),	\
	    (uint64_t)(accepted))

/* IV update */
#define	MESH_PROBE_IV_UPDATE_BEGIN(old_iv, new_iv)	\
	probe_tap_rec2("mesh:iv:update:begin", NULL, (uint64_t)(old_iv),	\
	    (uint64_t)(new_iv))
#define	MESH_PROBE_IV_UPDATE_DONE(iv_index)	\
	probe_tap_rec1("mesh:iv:update:done", NULL, (uint64_t)(iv_index))
#define	MESH_PROBE_IV_RX_ACCEPT(pdu_iv, accepted)	\
	probe_tap_rec2("mesh:iv:rx:accept", NULL, (uint64_t)(pdu_iv),	\
	    (uint64_t)(accepted))
#define	MESH_PROBE_IV_BEACON(recv_iv, accepted)	\
	probe_tap_rec2("mesh:iv:beacon", NULL, (uint64_t)(recv_iv),	\
	    (uint64_t)(accepted))

/* Secure Network Beacon */
#define	MESH_PROBE_BEACON_AUTH(key_refresh, result)	\
	probe_tap_rec2("mesh:beacon:auth", NULL, (uint64_t)(key_refresh),	\
	    (uint64_t)(result))

/* Provisioning */
#define	MESH_PROBE_PROV_STEP(type, role)	\
	probe_tap_rec2("mesh:prov:step", NULL, (uint64_t)(type), (uint64_t)(role))
#define	MESH_PROBE_PROV_CONFIRM(role)	\
	probe_tap_rec1("mesh:prov:confirm", NULL, (uint64_t)(role))
#define	MESH_PROBE_PROV_FAILED(error_code)	\
	probe_tap_rec1("mesh:prov:failed", NULL, (uint64_t)(error_code))

#elif defined(MESH_DTRACE_PROBES)

/* ================================================================
 * Backend 2: `mesh` USDT provider via raw DTRACE_PROBE (same idiom as
 * blued_probes.h).  The provider is `mesh`; each probe's leaf name is
 * declared in mesh_provider.d (added to SRCS in this mode so dtrace -G
 * links the provider object).  No generated header is needed.
 * ================================================================ */
#include <sys/sdt.h>

#define	MESH_PROBE_NET_ENCRYPT(src, dst, seq, ttl)	\
	DTRACE_PROBE4(mesh, mesh__net__encrypt, src, dst, seq, ttl)
#define	MESH_PROBE_NET_DECRYPT(nid, src, result)	\
	DTRACE_PROBE3(mesh, mesh__net__decrypt, nid, src, result)
#define	MESH_PROBE_NET_NID_MATCH(local_nid, pdu_nid, matched)	\
	DTRACE_PROBE3(mesh, mesh__net__nid__match, local_nid, pdu_nid, matched)
#define	MESH_PROBE_NET_RELAY(src, ttl, new_ttl, decision)	\
	DTRACE_PROBE4(mesh, mesh__net__relay, src, ttl, new_ttl, decision)

#define	MESH_PROBE_TRANSPORT_ENC(akf, szmic, len)	\
	DTRACE_PROBE3(mesh, mesh__transport__enc, akf, szmic, len)
#define	MESH_PROBE_TRANSPORT_DEC(akf, result)	\
	DTRACE_PROBE2(mesh, mesh__transport__dec, akf, result)
#define	MESH_PROBE_TRANSPORT_SEG(seqzero, sego, segn)	\
	DTRACE_PROBE3(mesh, mesh__transport__seg, seqzero, sego, segn)
#define	MESH_PROBE_TRANSPORT_REASM(src, seg, complete)	\
	DTRACE_PROBE3(mesh, mesh__transport__reasm, src, seg, complete)
#define	MESH_PROBE_SEG_ACK(seqzero, blockack)	\
	DTRACE_PROBE2(mesh, mesh__seg__ack, seqzero, blockack)

#define	MESH_PROBE_ACCESS_DISPATCH(opcode, src, dst)	\
	DTRACE_PROBE3(mesh, mesh__access__dispatch, opcode, src, dst)
#define	MESH_PROBE_ACCESS_PARSE(opcode, len)	\
	DTRACE_PROBE2(mesh, mesh__access__parse, opcode, len)

#define	MESH_PROBE_RPL_CHECK(src, seq, accepted)	\
	DTRACE_PROBE3(mesh, mesh__rpl__check, src, seq, accepted)
#define	MESH_PROBE_RPL_NET_RECV(src, accepted)	\
	DTRACE_PROBE2(mesh, mesh__rpl__net__recv, src, accepted)

#define	MESH_PROBE_IV_UPDATE_BEGIN(old_iv, new_iv)	\
	DTRACE_PROBE2(mesh, mesh__iv__update__begin, old_iv, new_iv)
#define	MESH_PROBE_IV_UPDATE_DONE(iv_index)	\
	DTRACE_PROBE1(mesh, mesh__iv__update__done, iv_index)
#define	MESH_PROBE_IV_RX_ACCEPT(pdu_iv, accepted)	\
	DTRACE_PROBE2(mesh, mesh__iv__rx__accept, pdu_iv, accepted)
#define	MESH_PROBE_IV_BEACON(recv_iv, accepted)	\
	DTRACE_PROBE2(mesh, mesh__iv__beacon, recv_iv, accepted)

#define	MESH_PROBE_BEACON_AUTH(key_refresh, result)	\
	DTRACE_PROBE2(mesh, mesh__beacon__auth, key_refresh, result)

#define	MESH_PROBE_PROV_STEP(type, role)	\
	DTRACE_PROBE2(mesh, mesh__prov__step, type, role)
#define	MESH_PROBE_PROV_CONFIRM(role)	\
	DTRACE_PROBE1(mesh, mesh__prov__confirm, role)
#define	MESH_PROBE_PROV_FAILED(error_code)	\
	DTRACE_PROBE1(mesh, mesh__prov__failed, error_code)

#else /* neither tap nor DTrace: zero-cost no-ops */

#define	MESH_PROBE_NET_ENCRYPT(src, dst, seq, ttl)		((void)0)
#define	MESH_PROBE_NET_DECRYPT(nid, src, result)		((void)0)
#define	MESH_PROBE_NET_NID_MATCH(local_nid, pdu_nid, matched)	((void)0)
#define	MESH_PROBE_NET_RELAY(src, ttl, new_ttl, decision)	((void)0)
#define	MESH_PROBE_TRANSPORT_ENC(akf, szmic, len)		((void)0)
#define	MESH_PROBE_TRANSPORT_DEC(akf, result)			((void)0)
#define	MESH_PROBE_TRANSPORT_SEG(seqzero, sego, segn)		((void)0)
#define	MESH_PROBE_TRANSPORT_REASM(src, seg, complete)		((void)0)
#define	MESH_PROBE_SEG_ACK(seqzero, blockack)			((void)0)
#define	MESH_PROBE_ACCESS_DISPATCH(opcode, src, dst)		((void)0)
#define	MESH_PROBE_ACCESS_PARSE(opcode, len)			((void)0)
#define	MESH_PROBE_RPL_CHECK(src, seq, accepted)		((void)0)
#define	MESH_PROBE_RPL_NET_RECV(src, accepted)			((void)0)
#define	MESH_PROBE_IV_UPDATE_BEGIN(old_iv, new_iv)		((void)0)
#define	MESH_PROBE_IV_UPDATE_DONE(iv_index)			((void)0)
#define	MESH_PROBE_IV_RX_ACCEPT(pdu_iv, accepted)		((void)0)
#define	MESH_PROBE_IV_BEACON(recv_iv, accepted)			((void)0)
#define	MESH_PROBE_BEACON_AUTH(key_refresh, result)		((void)0)
#define	MESH_PROBE_PROV_STEP(type, role)			((void)0)
#define	MESH_PROBE_PROV_CONFIRM(role)				((void)0)
#define	MESH_PROBE_PROV_FAILED(error_code)			((void)0)

#endif

#endif /* MESH_PROBES_H */

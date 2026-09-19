/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh foundation-model status codes --
 * the complete Table 4.308 "Summary of status codes", plus the corresponding
 * enumerations in two independent reference implementations.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/lib/libmesh or /usr/src/usr.sbin/bluetooth, and no value was
 * produced by running 5BSD code.
 *
 * A NOTE ON WHICH DOCUMENT IS AUTHORITATIVE
 * =========================================
 * Earlier mesh oracles in this directory (spec_extref_mesh_vectors.h,
 * spec_extref_mesh_iv_recovery.h) open with the statement that
 * /usr/src/bluetooth-specs contains no mesh specification, and fall back to
 * quoting reference-implementation comments.  That is no longer true.  The
 * tree now carries MshPRT_v1.1.1.txt and MshMDL_v1.1.1.txt and this header
 * quotes the specification directly.
 *
 * It also matters WHICH of the two.  In Mesh 1.1 the foundation models were
 * moved out of the Model specification and into the Protocol specification.
 * The Configuration Server model is MshPRT v1.1.1 Section 4.4.1; the
 * configuration messages are Section 4.3.2; the status code table is
 * Section 4.3.14.  MshMDL v1.1.1 contains only the generic, sensor,
 * time/scene and lighting models and defines none of this.  Looking for the
 * Config Server in MshMDL, as the pre-1.1 layout would suggest, finds nothing.
 *
 * SOURCES
 * =======
 * SPEC: /usr/src/bluetooth-specs/MshPRT_v1.1.1.txt
 *   Section 4.3.14 "Summary of status codes", Table 4.308, .txt lines
 *   23227-23292.  Line numbers below are lines of that .txt file.
 *
 *   The governing sentence, .txt lines 23229-23233, verbatim:
 *     "Table 4.308 defines status codes for configuration messages (see
 *      Section 4.3.2), health messages (see Section 4.3.3), directed
 *      forwarding configuration messages (see Section 4.3.5), bridge messages
 *      (see Section 4.3.11), and mesh private beacon messages (see Section
 *      4.3.12) that contain a Status parameter. Status messages are sent only
 *      in response to properly formatted messages (see Section 3.7.3.4)."
 *
 *   Two things in that sentence are load-bearing and are easy to miss:
 *
 *   (a) ONE table covers five message families.  The directed forwarding,
 *       bridge and private beacon models do NOT have private status
 *       enumerations; they draw from the same 0x00-0x15 space.  An
 *       implementation that gives Directed Forwarding its own status codes
 *       starting again at 0x01 is not conformant.
 *
 *   (b) "Status messages are sent only in response to properly formatted
 *       messages."  There is no status code for "malformed message".  A
 *       message that fails length or field validation is DROPPED, not
 *       answered.  There is deliberately no 0x16 meaning "bad request".
 *
 * REFERENCE IMPLEMENTATIONS
 * =========================
 * BLUEZ 5.87, git.kernel.org/pub/scm/bluetooth/bluez.git, snapshot commit
 *   92305dc06ab8a6d89af2dae1d725cc4d51462ad1.
 *   File mesh/mesh-defs.h lines 57-74 define the MESH_STATUS_* enumeration
 *   BlueZ puts on the wire.  (Note: mesh/error.h is NOT it -- that file holds
 *   BlueZ's D-Bus error enum, which is a different and unrelated numbering.)
 *   BlueZ predates Mesh 1.1: it has no directed forwarding and no subnet
 *   bridge (verified: no file under mesh/ matches "bridge"), so its table
 *   stops at MESH_STATUS_INVALID_BINDING = 0x11 and it defines nothing for
 *   0x12-0x15.
 *
 * ZEPHYR, github.com/zephyrproject-rtos/zephyr, snapshot commit
 *   2665fcca3cced3aefb7202d6289991d8cc1dfcac.
 *   File subsys/bluetooth/mesh/foundation.h lines 138-155.  That table also
 *   stops at STATUS_INVALID_BINDING = 0x11.  Zephyr implements Mesh 1.1
 *   subnet bridging (brg_cfg_srv.c) and SAR configuration (sar_cfg_srv.c) but
 *   NOT directed forwarding, so it defines the bridge-related codes and not
 *   the path-related ones.
 *
 * APACHE NIMBLE: its mesh stack (nimble/host/mesh/src/) is Mesh 1.0-era --
 *   no sar_cfg, no brg_cfg, no va.c, no remote provisioning -- and therefore
 *   defines only 0x00-0x11.
 *
 * The consequence, stated plainly because it changes how a divergence should
 * be read: for status codes 0x12 "Invalid Path Entry", 0x13 "Cannot Get",
 * 0x14 "Obsolete Information" and 0x15 "Invalid Bearer" there is NO reference
 * implementation to compare against.  Those four are adjudicated from the
 * specification text alone.
 */

#ifndef SPEC_EXTREF_MESH_CFG_STATUS_CODES_H
#define SPEC_EXTREF_MESH_CFG_STATUS_CODES_H

#include <stdint.h>

/*
 * MshPRT v1.1.1 Table 4.308, transcribed in full and in order.
 * The trailing comment on each line is the specification's own Status Code
 * Name column, verbatim.
 */
#define	SPEC_EXTREF_MESH_STATUS_SUCCESS			0x00u	/* Success */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_ADDRESS		0x01u	/* Invalid Address */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_MODEL		0x02u	/* Invalid Model */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_APPKEY_INDEX	0x03u	/* Invalid AppKey Index */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_NETKEY_INDEX	0x04u	/* Invalid NetKey Index */
#define	SPEC_EXTREF_MESH_STATUS_INSUFFICIENT_RESOURCES	0x05u	/* Insufficient Resources */
#define	SPEC_EXTREF_MESH_STATUS_KEY_INDEX_ALREADY_STORED 0x06u	/* Key Index Already Stored */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_PUBLISH_PARAMS	0x07u	/* Invalid Publish Parameters */
#define	SPEC_EXTREF_MESH_STATUS_NOT_A_SUBSCRIBE_MODEL	0x08u	/* Not a Subscribe Model */
#define	SPEC_EXTREF_MESH_STATUS_STORAGE_FAILURE		0x09u	/* Storage Failure */
#define	SPEC_EXTREF_MESH_STATUS_FEATURE_NOT_SUPPORTED	0x0Au	/* Feature Not Supported */
#define	SPEC_EXTREF_MESH_STATUS_CANNOT_UPDATE		0x0Bu	/* Cannot Update */
#define	SPEC_EXTREF_MESH_STATUS_CANNOT_REMOVE		0x0Cu	/* Cannot Remove */
#define	SPEC_EXTREF_MESH_STATUS_CANNOT_BIND		0x0Du	/* Cannot Bind */
#define	SPEC_EXTREF_MESH_STATUS_TEMP_UNABLE_TO_CHANGE	0x0Eu	/* Temporarily Unable to Change State */
#define	SPEC_EXTREF_MESH_STATUS_CANNOT_SET		0x0Fu	/* Cannot Set */
#define	SPEC_EXTREF_MESH_STATUS_UNSPECIFIED_ERROR	0x10u	/* Unspecified Error */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_BINDING		0x11u	/* Invalid Binding */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_PATH_ENTRY	0x12u	/* Invalid Path Entry */
#define	SPEC_EXTREF_MESH_STATUS_CANNOT_GET		0x13u	/* Cannot Get */
#define	SPEC_EXTREF_MESH_STATUS_OBSOLETE_INFORMATION	0x14u	/* Obsolete Information */
#define	SPEC_EXTREF_MESH_STATUS_INVALID_BEARER		0x15u	/* Invalid Bearer */

/* 0x16-0xFF are RFU.  There are exactly 22 defined codes. */
#define	SPEC_EXTREF_MESH_STATUS_RFU_FIRST		0x16u
#define	SPEC_EXTREF_MESH_STATUS_DEFINED_COUNT		22u

/*
 * Which codes were present in Mesh Profile 1.0 and which are Mesh 1.1
 * additions.  This is the boundary that decides whether a divergence is a
 * conformance defect or an unimplemented 1.1 feature, so it is pinned rather
 * than left to be inferred.
 *
 * 0x00-0x11 are the 1.0 set (all three reference implementations define them).
 * 0x12-0x15 arrived with the 1.1 directed-forwarding, bridging and private
 * beacon models.
 */
#define	SPEC_EXTREF_MESH_STATUS_IS_MESH_1_1_ADDITION(s)			\
	((s) >= SPEC_EXTREF_MESH_STATUS_INVALID_PATH_ENTRY &&		\
	 (s) <= SPEC_EXTREF_MESH_STATUS_INVALID_BEARER)

#define	SPEC_EXTREF_MESH_STATUS_IS_DEFINED(s)				\
	((s) <= SPEC_EXTREF_MESH_STATUS_INVALID_BEARER)

/*
 * BlueZ 5.87 mesh/mesh-defs.h:57-74 and Zephyr foundation.h:138-155.  Both
 * enumerations are value-for-value identical to Table 4.308 over 0x00-0x11
 * and both stop there; the four Mesh 1.1 codes are absent from each.
 */
#define	SPEC_EXTREF_MESH_BLUEZ_HIGHEST_STATUS		0x11u
#define	SPEC_EXTREF_MESH_BLUEZ_HAS_SUBNET_BRIDGE	0
#define	SPEC_EXTREF_MESH_BLUEZ_HAS_DIRECTED_FORWARDING	0

/*
 * Zephyr subsys/bluetooth/mesh/foundation.h.  Zephyr implements subnet
 * bridging and SAR configuration but not directed forwarding.
 */
#define	SPEC_EXTREF_MESH_ZEPHYR_HAS_SUBNET_BRIDGE	1
#define	SPEC_EXTREF_MESH_ZEPHYR_HAS_SAR_CONFIG		1
#define	SPEC_EXTREF_MESH_ZEPHYR_HAS_DIRECTED_FORWARDING	0

/* NimBLE's mesh is Mesh 1.0-era throughout. */
#define	SPEC_EXTREF_MESH_NIMBLE_HAS_SUBNET_BRIDGE	0
#define	SPEC_EXTREF_MESH_NIMBLE_HAS_SAR_CONFIG		0
#define	SPEC_EXTREF_MESH_NIMBLE_HAS_DIRECTED_FORWARDING	0

/*
 * MshPRT v1.1.1 Table 4.309, .txt lines 23296-23316 -- the SEPARATE and much
 * smaller status enumeration used by Opcodes Aggregator messages.  It is a
 * distinct namespace: 0x01 means Invalid Address in both tables, but 0x02
 * means "Invalid Model" in Table 4.308 and "WrongAccessKey" here.  Zephyr
 * keeps them apart as ACCESS_STATUS_* (foundation.h:157-162); a stack that
 * reuses the configuration codes for an Opcodes Aggregator Status is wrong on
 * the wire.  BlueZ and NimBLE have no Opcodes Aggregator at all.
 */
#define	SPEC_EXTREF_MESH_AGG_STATUS_SUCCESS		0x00u	/* Success */
#define	SPEC_EXTREF_MESH_AGG_STATUS_INVALID_ADDRESS	0x01u	/* Invalid Address */
#define	SPEC_EXTREF_MESH_AGG_STATUS_WRONG_ACCESS_KEY	0x02u	/* WrongAccessKey */
#define	SPEC_EXTREF_MESH_AGG_STATUS_WRONG_OPCODE	0x03u	/* WrongOpCode */
#define	SPEC_EXTREF_MESH_AGG_STATUS_MSG_NOT_UNDERSTOOD	0x04u	/* MessageNotUnderstood */
#define	SPEC_EXTREF_MESH_AGG_STATUS_RESPONSE_OVERFLOW	0x05u	/* ResponseOverflow */
#define	SPEC_EXTREF_MESH_AGG_STATUS_RFU_FIRST		0x06u

/*
 * MshPRT Section 4.3.14, .txt lines 23232-23233: "Status messages are sent
 * only in response to properly formatted messages."  Pinned as a flag so a
 * test can assert the drop-not-answer behaviour explicitly rather than
 * assuming some catch-all error reply is acceptable.
 */
#define	SPEC_EXTREF_MESH_MALFORMED_IS_DROPPED_NOT_ANSWERED	1

#endif /* SPEC_EXTREF_MESH_CFG_STATUS_CODES_H */

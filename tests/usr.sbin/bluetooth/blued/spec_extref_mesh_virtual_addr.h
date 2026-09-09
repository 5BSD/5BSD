/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh addressing -- virtual addresses
 * and Label UUIDs, the fixed group addresses, and the address-validity
 * matrices (Table 3.9 and Table 3.10).
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/lib/libmesh or /usr/src/usr.sbin/bluetooth, and no value was
 * produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ======================
 * A virtual address is a 14-bit HASH of a 128-bit Label UUID.  Two facts
 * follow, and an implementation has to honour both:
 *
 *   1. The hash is lossy by design -- "each hash represents many Label UUIDs"
 *      -- so the 16-bit address on the wire does NOT identify a subscription.
 *      Only the Label UUID does.
 *   2. The Label UUID is never transmitted.  It is recovered by TRYING each
 *      candidate label as the CCM additional data until the MIC verifies.
 *
 * The trap is to do step 2 correctly, prove which label authenticated the
 * message, and then throw that answer away and dispatch on the 16-bit address
 * -- which cannot distinguish two colliding labels.  Both reference
 * implementations carry the winning label through to model dispatch, and this
 * header pins the specification text that requires it.
 *
 * SOURCES
 * =======
 * SPEC: /usr/src/bluetooth-specs/MshPRT_v1.1.1.txt.  Line numbers below are
 *   lines of that .txt file.
 *     Section 3.4.2.3 Virtual address ................ lines 3335-3364
 *     Section 3.4.2.4 Group address, Table 3.8 ....... lines 3379-3420
 *     Section 3.4.3   Address validity, Tables 3.9/3.10 lines 3424-3477
 *
 *   .txt lines 3335-3339, verbatim:
 *     "A virtual address represents a set of destination addresses. Each
 *      virtual address logically represents a Label UUID, which is a 128-bit
 *      value that does not have to be managed centrally. One or more elements
 *      may be programmed to publish or subscribe to a Label UUID. The Label
 *      UUID is not transmitted and shall be used as the Additional Data field
 *      of the message integrity check value in the upper transport layer (see
 *      Section 3.9.7.1)."
 *
 *   .txt lines 3341-3343, verbatim -- the address construction:
 *     "The virtual address is a 16-bit value that has bit 15 set to 1, bit 14
 *      set to 0, and bits 13 to 0 set to the value of a hash. This hash is a
 *      derivation of the Label UUID such that each hash represents many Label
 *      UUIDs."
 *
 *   .txt lines 3345-3347, verbatim -- the derivation itself:
 *     "SALT=s1(\"vtad\")"
 *     "hash=AES-CMAC_SALT (Label UUID) mod 2^14"
 *
 *   .txt lines 3349-3351, verbatim -- THE DISPATCH RULE:
 *     "When an Access message is received to a virtual address that has a
 *      matching hash, each corresponding Label UUID is used by the upper
 *      transport layer as additional data as part of the authentication of the
 *      message until a match is found."
 *
 *   .txt line 3353, verbatim:
 *     "Transport Control messages cannot use virtual addresses."
 *
 *   And the specification's own note on collision probability, .txt lines
 *   3374-3376, verbatim:
 *     "When factoring in a 32-bit MIC and the size of the hash, there is only
 *      a 1/2^46=1.42x10^-14 likelihood that two matching virtual addresses
 *      using the same application key but different Label UUIDs will collide."
 *
 *   Read that note precisely, because it is easy to misread as licence to
 *   ignore collisions.  It bounds the chance that two DIFFERENT labels both
 *   produce a matching hash AND a passing 32-bit MIC.  It says nothing about
 *   the chance of a hash collision alone, which is 2^-14 per pair -- roughly
 *   one in sixteen thousand, and reachable by an adversary who simply searches
 *   for a Label UUID hashing to an address already in use.  The MIC is what
 *   makes the collision harmless, and the MIC only helps if the label that
 *   passed it is the label used to route.
 *
 * REFERENCE IMPLEMENTATIONS
 * =========================
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac) keeps a dedicated virtual
 *   address module, subsys/bluetooth/mesh/va.c + va.h, and threads the
 *   authenticating UUID from the upper transport into access-layer dispatch:
 *   transport.c records the winning UUID on the receive context, and
 *   access.c's model_has_dst() resolves a virtual destination by looking the
 *   model up BY UUID, not by the 16-bit address.
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1) does the same in
 *   mesh/model.c: virt_packet_decrypt() returns the matching
 *   "struct mesh_virtual *", and forward_model() matches a subscription
 *   against that object rather than against the address.
 * APACHE NIMBLE's mesh is Mesh 1.0-era and has no va.c; its virtual-address
 *   support is correspondingly thinner and it is not a strong reference here.
 */

#ifndef SPEC_EXTREF_MESH_VIRTUAL_ADDR_H
#define SPEC_EXTREF_MESH_VIRTUAL_ADDR_H

#include <stdint.h>

/*
 * Address type ranges, Section 3.4.2.  A virtual address is 0x8000-0xBFFF
 * (bit 15 = 1, bit 14 = 0); a group address is 0xC000-0xFFFF (bits 15 and 14
 * both 1); a unicast address is 0x0001-0x7FFF; 0x0000 is unassigned.
 */
#define	SPEC_EXTREF_MESH_ADDR_UNASSIGNED		0x0000u
#define	SPEC_EXTREF_MESH_ADDR_UNICAST_MIN		0x0001u
#define	SPEC_EXTREF_MESH_ADDR_UNICAST_MAX		0x7FFFu
#define	SPEC_EXTREF_MESH_ADDR_VIRTUAL_MIN		0x8000u
#define	SPEC_EXTREF_MESH_ADDR_VIRTUAL_MAX		0xBFFFu
#define	SPEC_EXTREF_MESH_ADDR_GROUP_MIN			0xC000u
#define	SPEC_EXTREF_MESH_ADDR_GROUP_MAX			0xFFFFu

#define	SPEC_EXTREF_MESH_ADDR_IS_UNICAST(a)				\
	((a) >= 0x0001u && (a) <= 0x7FFFu)
#define	SPEC_EXTREF_MESH_ADDR_IS_VIRTUAL(a)				\
	(((a) & 0xC000u) == 0x8000u)
#define	SPEC_EXTREF_MESH_ADDR_IS_GROUP(a)				\
	(((a) & 0xC000u) == 0xC000u)

/*
 * The virtual-address hash, Section 3.4.2.3.
 * SALT = s1("vtad"); hash = AES-CMAC_SALT(Label UUID) mod 2^14; the address is
 * 0x8000 | hash.  The CMAC output is 16 octets and the hash is its LAST two
 * octets read big-endian, masked to 14 bits -- mesh crypto is big-endian
 * throughout (see spec_extref_mesh_vectors.h for the evidence).
 */
#define	SPEC_EXTREF_MESH_VTAD_SALT_STRING		"vtad"
#define	SPEC_EXTREF_MESH_VTAD_SALT_LEN			4u
#define	SPEC_EXTREF_MESH_LABEL_UUID_OCTETS		16u
#define	SPEC_EXTREF_MESH_VIRT_HASH_BITS			14
#define	SPEC_EXTREF_MESH_VIRT_HASH_MASK			0x3FFFu
#define	SPEC_EXTREF_MESH_VIRT_ADDR_FROM_HASH(h)				\
	((uint16_t)(0x8000u | ((h) & SPEC_EXTREF_MESH_VIRT_HASH_MASK)))
/* Offset within the 16-octet CMAC output at which the hash is read. */
#define	SPEC_EXTREF_MESH_VIRT_HASH_CMAC_OFFSET		14u

/*
 * THE DISPATCH RULE, .txt lines 3349-3351.  Pinned as three separate flags
 * because they are three separate obligations and an implementation can
 * satisfy the first two while failing the third -- which is the failure mode
 * this header exists to catch.
 */
/* Every candidate label whose hash matches must be tried, not just one. */
#define	SPEC_EXTREF_MESH_VIRT_TRY_EVERY_MATCHING_LABEL	1
/* The label is the CCM additional data, i.e. it authenticates the message. */
#define	SPEC_EXTREF_MESH_VIRT_LABEL_IS_CCM_AAD		1
/* The label that authenticated must be what selects the destination model;
 * the 16-bit address is not sufficient, by construction. */
#define	SPEC_EXTREF_MESH_VIRT_DISPATCH_BY_LABEL_NOT_ADDR	1

/* Hash collisions between distinct labels: 2^-14 per pair, i.e. reachable. */
#define	SPEC_EXTREF_MESH_VIRT_HASH_SPACE		16384u

/* .txt line 3353: "Transport Control messages cannot use virtual addresses." */
#define	SPEC_EXTREF_MESH_VIRT_NOT_FOR_CONTROL_MSG	1

/*
 * Table 3.8 Fixed group addresses, .txt lines 3398-3417, transcribed in full.
 * The names are the specification's own.
 */
#define	SPEC_EXTREF_MESH_ADDR_FIXED_GROUP_MIN		0xFF00u
#define	SPEC_EXTREF_MESH_ADDR_ALL_IPT_BORDER_ROUTERS	0xFFF9u
#define	SPEC_EXTREF_MESH_ADDR_ALL_IPT_NODES		0xFFFAu
#define	SPEC_EXTREF_MESH_ADDR_ALL_DIRECTED_FWD_NODES	0xFFFBu
#define	SPEC_EXTREF_MESH_ADDR_ALL_PROXIES		0xFFFCu
#define	SPEC_EXTREF_MESH_ADDR_ALL_FRIENDS		0xFFFDu
#define	SPEC_EXTREF_MESH_ADDR_ALL_RELAYS		0xFFFEu
#define	SPEC_EXTREF_MESH_ADDR_ALL_NODES			0xFFFFu

/* .txt lines 3390-3392: "Group addresses in the range 0xFF00 through 0xFFFF
 * are reserved for Fixed Group addresses ... and addresses in the range
 * 0xC000 through 0xFEFF are generally available for other usage." */
#define	SPEC_EXTREF_MESH_ADDR_DYNAMIC_GROUP_MIN		0xC000u
#define	SPEC_EXTREF_MESH_ADDR_DYNAMIC_GROUP_MAX		0xFEFFu
#define	SPEC_EXTREF_MESH_ADDR_IS_FIXED_GROUP(a)		((a) >= 0xFF00u)

/*
 * Table 3.9 "Address type and message field validity", .txt lines 3428-3452.
 * Transcribed cell by cell.  The three columns are: valid in SRC; valid in DST
 * of a Control message (segmented or unsegmented); valid in DST of an Access
 * message (segmented or unsegmented).
 *
 *   Unassigned Address ...... No  / No  / No
 *   Unicast Address ......... Yes / Yes / Yes
 *   Virtual Address ......... No  / No  / Yes
 *   Group Address ........... No  / Yes / Yes
 *
 * Two cells are the ones implementations miss: a virtual address is NEVER
 * valid in SRC (so a node's own address can never be virtual), and a virtual
 * address is NEVER valid as the destination of a Control message -- which is
 * the same statement as line 3353, arrived at from the other direction.
 *
 * .txt line 3454 adds: "A fixed group address defined as Reserved for Future
 * Use in Section 3.4.2.4 is a valid group address for the purposes of
 * Table 3.9." -- an RFU fixed group address must not be rejected as malformed.
 */
#define	SPEC_EXTREF_MESH_SRC_VALID_UNASSIGNED		0
#define	SPEC_EXTREF_MESH_SRC_VALID_UNICAST		1
#define	SPEC_EXTREF_MESH_SRC_VALID_VIRTUAL		0
#define	SPEC_EXTREF_MESH_SRC_VALID_GROUP		0

#define	SPEC_EXTREF_MESH_CTL_DST_VALID_UNASSIGNED	0
#define	SPEC_EXTREF_MESH_CTL_DST_VALID_UNICAST		1
#define	SPEC_EXTREF_MESH_CTL_DST_VALID_VIRTUAL		0
#define	SPEC_EXTREF_MESH_CTL_DST_VALID_GROUP		1

#define	SPEC_EXTREF_MESH_ACC_DST_VALID_UNASSIGNED	0
#define	SPEC_EXTREF_MESH_ACC_DST_VALID_UNICAST		1
#define	SPEC_EXTREF_MESH_ACC_DST_VALID_VIRTUAL		1
#define	SPEC_EXTREF_MESH_ACC_DST_VALID_GROUP		1

#define	SPEC_EXTREF_MESH_RFU_FIXED_GROUP_IS_VALID	1

/*
 * Table 3.10 "Address type and access layer key type validity", .txt lines
 * 3458-3472.  Transcribed cell by cell.
 *
 *   Unassigned Address ... device key No  / application key No
 *   Unicast Address ...... device key Yes / application key Yes
 *   Virtual Address ...... device key No  / application key Yes
 *   Group Address ........ device key No  / application key Yes
 *
 * The device-key row is the security-relevant one: a message secured with a
 * device key is only ever valid to a UNICAST destination.  A stack that
 * accepts a device-key-secured message addressed to a group or virtual
 * address lets a configuration message be broadcast.
 */
#define	SPEC_EXTREF_MESH_DEVKEY_VALID_UNASSIGNED	0
#define	SPEC_EXTREF_MESH_DEVKEY_VALID_UNICAST		1
#define	SPEC_EXTREF_MESH_DEVKEY_VALID_VIRTUAL		0
#define	SPEC_EXTREF_MESH_DEVKEY_VALID_GROUP		0

#define	SPEC_EXTREF_MESH_APPKEY_VALID_UNASSIGNED	0
#define	SPEC_EXTREF_MESH_APPKEY_VALID_UNICAST		1
#define	SPEC_EXTREF_MESH_APPKEY_VALID_VIRTUAL		1
#define	SPEC_EXTREF_MESH_APPKEY_VALID_GROUP		1

/*
 * Section 3.4.2.4, .txt line 3396, verbatim:
 *   "A Network PDU sent to a group address shall be delivered to all the
 *    instances of models that subscribe to this group address."
 * "that subscribe" is per-MODEL, not per-element.  Delivering to every model
 * on an element because one model on that element subscribes is a different
 * behaviour and is not what this sentence describes.
 */
#define	SPEC_EXTREF_MESH_GROUP_DELIVERY_IS_PER_MODEL	1

#endif /* SPEC_EXTREF_MESH_VIRTUAL_ADDR_H */

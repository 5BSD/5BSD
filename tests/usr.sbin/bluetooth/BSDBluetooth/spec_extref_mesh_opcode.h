/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh access-layer opcode encoding --
 * the one-, two- and three-octet forms, the reserved value, the vendor
 * company-identifier byte order, and the specification's own worked example.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/lib/libmesh or /usr/src/usr.sbin/bluetooth, and no value was
 * produced by running 5BSD code.
 *
 * SOURCES
 * =======
 * SPEC: /usr/src/bluetooth-specs/MshPRT_v1.1.1.txt, Section 3.7.2.1 "Opcode
 *   field", Table 3.63 "Opcode formats", .txt lines 8828-8878.  Line numbers
 *   below are lines of that .txt file.
 *
 *   .txt lines 8833-8838, verbatim:
 *     "The Opcode field contains an operation code (opcode). The opcode is an
 *      array of octets comprising 1, 2, or 3 octets. The first octet of the
 *      opcode determines the number of octets of the opcode thus defining the
 *      size of the Opcode field.
 *      If the most significant bit of the first octet of the opcode is zero,
 *      then the opcode contains a single octet. If the two most significant
 *      bits of the first octet are 0b10, then the opcode contains two octets.
 *      If the two most significant bits of the first octet are 0b11, then the
 *      opcode contains three octets."
 *
 *   Table 3.63 itself, .txt lines 8843-8859, verbatim:
 *     "0xxxxxxx (excluding 01111111)   1-octet Opcodes"
 *     "01111111                        Reserved for Future Use"
 *     "10xxxxxx xxxxxxxx               2-octet Opcodes"
 *     "11xxxxxx zzzzzzzz zzzzzzzz      3-octet Opcodes"
 *
 *   .txt lines 8861-8871, verbatim -- the counts and the company identifier:
 *     "There are 127 1-octet opcodes that can be defined and allocated by the
 *      Bluetooth SIG. Opcode 0x7F is reserved for future possible extension."
 *     "There are 16384 2-octet opcodes ..."
 *     "There are 64 3-octet opcodes available per company identifier. ... The
 *      company identifiers are 16-bit values defined by the Bluetooth SIG and
 *      are coded into the second and third octets of the 3-octet opcodes,
 *      identified using 'z' in Table 3.63, using endianness as defined in
 *      Section 3.7.1."
 *
 *   And the worked example that settles the byte order beyond argument,
 *   .txt lines 8873-8874, verbatim:
 *     "For example, when the manufacturer-specific opcode is equal to 0x23 and
 *      the company identifier is equal to 0x0136 [4], then the 3-octet opcode
 *      is equal to 0xE3 0x36 0x01."
 *
 *   Read that example carefully.  The company identifier 0x0136 goes on the
 *   wire as 0x36 then 0x01 -- LITTLE-endian -- while every other multi-octet
 *   field in a mesh Network PDU (SRC, DST, SEQ, IV Index) is big-endian.  The
 *   access layer is the one layer where the mesh specification switches
 *   endianness, and Section 3.7.1 is where it says so.  This single example is
 *   the highest-value vector in this header: an implementation that reuses its
 *   network-layer big-endian helper for the vendor CID produces 0xE3 0x01 0x36
 *   and its vendor opcodes match nothing in the field.
 *
 * REFERENCE IMPLEMENTATIONS -- all three read, none assumed
 * ========================================================
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac),
 *   subsys/bluetooth/mesh/access.c:1424-1459, get_opcode():
 *     switches on buf->data[0] >> 6; rejects 0x7f explicitly with "Ignoring
 *     RFU OpCode"; length-checks 2 and 3 octet forms before pulling; and for
 *     the 3-octet form does
 *       *opcode = pull_u8() << 16;  *opcode |= pull_le16();
 *     carrying the comment "Using LE for the CID since the model layer is
 *     defined as little-endian in the mesh spec".
 *
 * NIMBLE (mesh is Mesh 1.0-era), nimble/host/mesh/src/access.c:631-666,
 *   get_opcode(): character-for-character the same function as Zephyr's,
 *   including the same comment.  It is a common ancestor, not an independent
 *   reading, and should be weighted as one reference rather than two.
 *
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1),
 *   mesh/model.c:1800-1838 mesh_model_opcode_get() and
 *   mesh/model.c:1778-1798 mesh_model_opcode_set():
 *     switches on buf[0] & 0xc0; rejects 0x7f; length-checks both multi-octet
 *     forms.  For the 3-octet form it uses l_get_be16(buf + 1) on decode and
 *     l_put_be16(opcode, buf + 1) on encode.
 *
 *   THE BYTE ORDER IS AN INTERNAL-REPRESENTATION SPLIT, NOT A WIRE SPLIT, and
 *   it is worth being precise about because it looks like a BlueZ bug and is
 *   not one.  BlueZ's 32-bit opcode key holds the CID octets in WIRE order
 *   (for the example above, 0xE33601); Zephyr's and NimBLE's key holds the CID
 *   as a NUMBER (0xE30136).  Both round-trip their own encode/decode pair and
 *   both put the same three octets on the wire.  What differs is the constant
 *   a model table must be written with.  A stack borrowing model-table
 *   constants from one project while decoding like the other silently fails to
 *   dispatch every vendor opcode.  The wire, and only the wire, is normative:
 *   0xE3 0x36 0x01.
 */

#ifndef SPEC_EXTREF_MESH_OPCODE_H
#define SPEC_EXTREF_MESH_OPCODE_H

#include <stdint.h>

/* Table 3.63 form selection, from the first octet. */
#define	SPEC_EXTREF_MESH_OP_IS_1_OCTET(b0)	(((b0) & 0x80u) == 0x00u)
#define	SPEC_EXTREF_MESH_OP_IS_2_OCTET(b0)	(((b0) & 0xC0u) == 0x80u)
#define	SPEC_EXTREF_MESH_OP_IS_3_OCTET(b0)	(((b0) & 0xC0u) == 0xC0u)

/*
 * "Opcode 0x7F is reserved for future possible extension."  It is not a
 * 1-octet opcode, it is not an unknown opcode to be silently ignored at the
 * model layer, and it must be rejected at parse time -- otherwise 0x7F is
 * accepted as an opcode and the parameters are misaligned by one octet.  All
 * three references reject it by value before anything else.
 */
#define	SPEC_EXTREF_MESH_OP_RESERVED_1_OCTET	0x7Fu
#define	SPEC_EXTREF_MESH_OP_IS_RESERVED(b0)	((b0) == 0x7Fu)

/* Opcode space sizes, .txt lines 8861-8869. */
#define	SPEC_EXTREF_MESH_OP_1_OCTET_COUNT	127u	/* 0x00-0x7E */
#define	SPEC_EXTREF_MESH_OP_2_OCTET_COUNT	16384u	/* 0x8000-0xBFFF */
#define	SPEC_EXTREF_MESH_OP_3_OCTET_PER_CID	64u	/* 0xC0-0xFF first octet */

/* Valid first-octet ranges per form. */
#define	SPEC_EXTREF_MESH_OP_1_OCTET_MIN		0x00u
#define	SPEC_EXTREF_MESH_OP_1_OCTET_MAX		0x7Eu
#define	SPEC_EXTREF_MESH_OP_2_OCTET_FIRST_MIN	0x80u
#define	SPEC_EXTREF_MESH_OP_2_OCTET_FIRST_MAX	0xBFu
#define	SPEC_EXTREF_MESH_OP_3_OCTET_FIRST_MIN	0xC0u
#define	SPEC_EXTREF_MESH_OP_3_OCTET_FIRST_MAX	0xFFu

/* Encoded length in octets, given the first octet.  0 means "reserved". */
#define	SPEC_EXTREF_MESH_OP_LEN(b0)					\
	(SPEC_EXTREF_MESH_OP_IS_RESERVED(b0) ? 0u :			\
	 SPEC_EXTREF_MESH_OP_IS_1_OCTET(b0) ? 1u :			\
	 SPEC_EXTREF_MESH_OP_IS_2_OCTET(b0) ? 2u : 3u)

/*
 * THE WORKED EXAMPLE, .txt lines 8873-8874.  These four constants are the
 * whole point of this header: they are the specification's own numbers, not a
 * derivation, and they pin the vendor CID byte order on the wire.
 */
#define	SPEC_EXTREF_MESH_OP3_EXAMPLE_VENDOR_OP	0x23u	/* 6-bit vendor opcode */
#define	SPEC_EXTREF_MESH_OP3_EXAMPLE_CID	0x0136u	/* company identifier */
#define	SPEC_EXTREF_MESH_OP3_EXAMPLE_OCTET0	0xE3u	/* 0b11 | 0x23 */
#define	SPEC_EXTREF_MESH_OP3_EXAMPLE_OCTET1	0x36u	/* CID low octet FIRST */
#define	SPEC_EXTREF_MESH_OP3_EXAMPLE_OCTET2	0x01u	/* CID high octet */

/* The same three octets as an array, for a memcmp-style assertion. */
static const uint8_t spec_extref_mesh_op3_example_wire[3] = { 0xE3, 0x36, 0x01 };

/*
 * Construction and destructuring of the 3-octet form, expressed only in terms
 * of the wire octets so that neither project's internal 32-bit convention is
 * baked in.
 *
 *   octet0 = 0xC0 | (vendor_opcode & 0x3F)
 *   octet1 = cid & 0xFF          (LOW octet first -- little-endian)
 *   octet2 = (cid >> 8) & 0xFF
 */
#define	SPEC_EXTREF_MESH_OP3_OCTET0(vop)	(0xC0u | ((vop) & 0x3Fu))
#define	SPEC_EXTREF_MESH_OP3_OCTET1(cid)	((cid) & 0xFFu)
#define	SPEC_EXTREF_MESH_OP3_OCTET2(cid)	(((cid) >> 8) & 0xFFu)
#define	SPEC_EXTREF_MESH_OP3_CID_FROM_WIRE(o1, o2)			\
	((uint16_t)((o1) | ((uint16_t)(o2) << 8)))
#define	SPEC_EXTREF_MESH_OP3_VENDOR_OP_FROM_WIRE(o0)	((o0) & 0x3Fu)

/*
 * The 2-octet form has no such subtlety: "10xxxxxx xxxxxxxx" is a single
 * 14-bit number transmitted most-significant octet first, and all three
 * references read it with a big-endian 16-bit pull.  Pinned so nobody
 * "corrects" it to match the 3-octet CID's little-endianness.
 */
#define	SPEC_EXTREF_MESH_OP2_IS_BIG_ENDIAN	1
#define	SPEC_EXTREF_MESH_OP3_CID_IS_LITTLE_ENDIAN	1

/*
 * Parse-time length checks.  All three references refuse a first octet that
 * announces a longer opcode than the buffer holds, BEFORE consuming anything.
 * Pinned separately because a truncated 3-octet opcode is the natural way for
 * a fuzzer or a lossy bearer to walk a parser off the end of a PDU.
 */
#define	SPEC_EXTREF_MESH_OP_NEEDS_OCTETS(b0)	SPEC_EXTREF_MESH_OP_LEN(b0)
#define	SPEC_EXTREF_MESH_OP_TRUNCATED_IS_REJECTED	1

/*
 * Zephyr access.c:1416-1418 records a dispatch rule worth pinning, with the
 * comment "Return early if LEN == 3, since SIG models cannot contain 3-byte
 * opcodes."  A 3-octet opcode is a vendor opcode by construction and must
 * never be offered to a SIG model's handler table; conversely a 1- or 2-octet
 * opcode is a SIG opcode.  This follows from .txt lines 8861-8869 ("The
 * 1-octet opcodes are used for Bluetooth SIG defined models ... The 3-octet
 * opcodes are used for manufacturer-specific opcodes").
 */
#define	SPEC_EXTREF_MESH_OP3_IS_VENDOR_ONLY		1
#define	SPEC_EXTREF_MESH_OP12_IS_SIG_ONLY		1

/*
 * Maximum Parameters field length per opcode form, .txt lines 8800-8803,
 * verbatim: "With a 32-bit TransMIC field, the maximum size of the Access
 * message is 380 octets, and therefore with a single-octet opcode, the
 * parameters field can be up to 379 octets. With a 2-octet opcode, the
 * parameters field can be up to 378 octets. With a 3-octet opcode, the
 * parameters field can be up to 377 octets."
 */
#define	SPEC_EXTREF_MESH_ACCESS_MSG_MAX			380u
#define	SPEC_EXTREF_MESH_PARAMS_MAX_1_OCTET_OP		379u
#define	SPEC_EXTREF_MESH_PARAMS_MAX_2_OCTET_OP		378u
#define	SPEC_EXTREF_MESH_PARAMS_MAX_3_OCTET_OP		377u

#endif /* SPEC_EXTREF_MESH_OPCODE_H */

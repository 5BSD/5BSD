/*
 * EXTERNAL REFERENCE ORACLE: ATT_READ_BLOB_REQ response selection, and the
 * status of Attribute Not Long (0x0B) in the ecosystem.
 *
 * Hand-written.  Every claim is traceable to a named external source; nothing
 * here was derived from blued and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * A long read that terminates exactly on an attribute boundary is the single
 * most common real-world long-read shape, because it is what a client does
 * when the value length is an exact multiple of (ATT_MTU - 1).  The spec
 * mandates a zero-length response there.  Returning an error instead makes the
 * peer discard data it has already successfully collected -- a silent
 * data-loss failure rather than a visible protocol error.
 *
 * SPEC
 * ----
 * /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *
 *   Vol 3, Part F, Section 3.4.4.5 (text lines 70444-70451), the two rules in
 *   the order the specification states them, verbatim:
 *     "If the value offset of the Read Blob Request is greater than the length
 *      of the attribute value, an ATT_ERROR_RSP PDU shall be sent with the
 *      Error Code parameter set to Invalid Offset (0x07)."
 *     "If the attribute value has a fixed length that is less than or equal to
 *      (ATT_MTU - 1) octets in length, then an ATT_ERROR_RSP PDU may be sent
 *      with the Error Code parameter set to Attribute Not Long (0x0B)."
 *     "If the value offset of the ATT_READ_BLOB_REQ PDU is equal to the length
 *      of the attribute value, then the length of the part attribute value in
 *      the response shall be zero."
 *
 *   Two things to note in that text, because both are load-bearing:
 *     1. 0x0B is a "may", and it is conditioned on the attribute having a
 *        FIXED length.  It is not a general "the value is short" error.
 *     2. The zero-length rule is a "shall" and it is stated for offset EQUAL
 *        to the length -- which is precisely the case a naive "value is
 *        shorter than the MTU" test also matches.  A "may" cannot override a
 *        "shall"; when both descriptions fit, the zero-length response wins.
 *
 *   Vol 3, Part F, Table 3.4 (text line 69837) defines 0x0B as: "The attribute
 *   cannot be read using the ATT_READ_BLOB_REQ PDU."
 *
 * REFERENCE IMPLEMENTATIONS: NONE OF THE THREE EVER SENDS 0x0B
 * -----------------------------------------------------------
 *   BlueZ, snapshot commit 92305dc06ab8a6d89af2dae1d725cc4d51462ad1:
 *     the server delegates offset handling to the gatt-db layer and produces
 *     only Invalid Offset (0x07).
 *     Client side, src/shared/gatt-client.c:3008-3060 read_long_cb(): the loop
 *     continues issuing ATT_READ_BLOB_REQ while the received length is
 *     >= (MTU - 1).  For a value whose length is an exact multiple of
 *     (MTU - 1) this necessarily issues one final request at
 *     offset == value length.  An error response on that request takes the
 *     failure branch and sets success = false, discarding the octets already
 *     accumulated.
 *   Zephyr, snapshot commit 2665fcca3cced3aefb7202d6289991d8cc1dfcac:
 *     subsys/bluetooth/host/gatt.c:1769-1784 bt_gatt_attr_read() returns
 *     Invalid Offset (0x07) for offset > value_len, and returns a zero-length
 *     read for offset == value_len.
 *   Apache NimBLE, snapshot commit
 *   1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845:
 *     the error code has no occurrence in the host source at all.
 *
 * The practical reading: 0x0B is a legacy permission of the specification that
 * the ecosystem has collectively declined to exercise.  A server that emits it
 * is interoperating with no one.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_ATT_READ_BLOB_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_ATT_READ_BLOB_H

#include <stdint.h>

#define BT_EXTREF_ATT_ERR_INVALID_OFFSET		0x07
#define BT_EXTREF_ATT_ERR_ATTRIBUTE_NOT_LONG		0x0b

/*
 * The three outcomes of an ATT_READ_BLOB_REQ against an attribute of length
 * L at offset O, per Section 3.4.4.5.  "Zero-length response" means an
 * ATT_READ_BLOB_RSP whose Part Attribute Value field is empty -- a RESPONSE,
 * not an error.
 */
enum bt_extref_att_read_blob_outcome {
	BT_EXTREF_READ_BLOB_DATA		= 0,	/* O <  L */
	BT_EXTREF_READ_BLOB_ZERO_LENGTH_RSP	= 1,	/* O == L */
	BT_EXTREF_READ_BLOB_ERR_INVALID_OFFSET	= 2	/* O >  L */
};

/*
 * Core 6.3, Vol 3, Part F, Section 3.4.4.5.  The decision depends only on the
 * relation between offset and length -- NOT on how the length compares to the
 * ATT MTU.
 */
static inline enum bt_extref_att_read_blob_outcome
bt_extref_att_read_blob_expected(uint16_t offset, uint16_t value_len)
{
	if (offset > value_len)
		return BT_EXTREF_READ_BLOB_ERR_INVALID_OFFSET;
	if (offset == value_len)
		return BT_EXTREF_READ_BLOB_ZERO_LENGTH_RSP;
	return BT_EXTREF_READ_BLOB_DATA;
}

/*
 * Does the named reference implementation ever transmit Attribute Not Long?
 * All three: no.  Recorded as a set so a test can assert the ecosystem
 * position rather than restating it in prose.
 */
#define BT_EXTREF_READ_BLOB_BLUEZ_EMITS_0X0B		0
#define BT_EXTREF_READ_BLOB_ZEPHYR_EMITS_0X0B		0
#define BT_EXTREF_READ_BLOB_NIMBLE_EMITS_0X0B		0

/*
 * The BlueZ client-side long-read termination condition, from
 * src/shared/gatt-client.c:3008-3060.  The loop continues while the received
 * part length is >= (MTU - 1); therefore a value length that is an exact
 * multiple of (MTU - 1) provokes a final request at offset == length.
 *
 * Worked example at the default ATT_MTU of 23, i.e. a 22-octet part size: a
 * 22-octet characteristic value.  The client reads offset 0 (22 octets, which
 * is >= 22, so it continues) and then issues offset 22 == length.  Per the
 * table above the correct answer is a zero-length response.
 */
#define BT_EXTREF_READ_BLOB_DEFAULT_ATT_MTU		23
#define BT_EXTREF_READ_BLOB_DEFAULT_PART_LEN		22
#define BT_EXTREF_READ_BLOB_BLUEZ_TRIGGER_VALUE_LEN	22
#define BT_EXTREF_READ_BLOB_BLUEZ_TRIGGER_FINAL_OFFSET	22

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_ATT_READ_BLOB_H */

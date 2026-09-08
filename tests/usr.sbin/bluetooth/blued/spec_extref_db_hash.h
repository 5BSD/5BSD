/*
 * Generated from the Bluetooth Core 6.3 text by
 * spec_extref_db_hash_gen.awk; do not edit.
 *
 * EXTERNAL REFERENCE ORACLE.  Every value below comes from outside this
 * source tree.  Nothing here was produced by running blued.
 *
 * Spec provenance:
 *   Core 6.3, Vol 3, Part G, Section 7.3   -- Database Hash characteristic,
 *     Table 7.8 types the characteristic value as uint128.
 *   Core 6.3, Vol 3, Part G, Section 7.3.1 -- "Database Hash =",
 *     "AES-CMACk(m)" with k = 0, m built in ascending handle order with
 *     each field little-endian, padded per RFC-4493 Section 2.4.
 *   Core 6.3, Vol 3, Part G, Appendix B    -- worked example; the source
 *     text states "The bytes in M0 to M6 and the Database Hash are ordered
 *     from the most significant on the left to the least significant on
 *     the right."
 *
 * BlueZ provenance for the ON-THE-WIRE byte order (snapshot
 * git.kernel.org/pub/scm/bluetooth/bluez.git, commit
 * 92305dc06ab8a6d89af2dae1d725cc4d51462ad1):
 *   src/shared/crypto.c:724  bt_crypto_gatt_hash() -- feeds the iovec
 *     straight into the kernel cmac(aes) socket and read()s the result
 *     straight out.  Note what it does NOT do: unlike aes_cmac() at
 *     src/shared/crypto.c:619, which swap_buf()s key, message AND result
 *     for the SMP functions, bt_crypto_gatt_hash() performs NO swap on
 *     either side.  res[0] is therefore the most significant CMAC octet.
 *   src/shared/gatt-db.c:377  gen_hash_m() -- builds each iovec element as
 *     put_le16(handle) || bt_uuid_to_le(type) || value, i.e. exactly the
 *     little-endian wire concatenation of Section 7.3.1.
 *   src/shared/gatt-db.c:429  db_hash_update() -> db->hash.
 *   src/shared/gatt-db.c:711  gatt_db_get_hash() returns db->hash verbatim.
 *   src/gatt-database.c:1212  db_hash_read_cb() ->
 *     gatt_db_attribute_read_result(attrib, id, 0, hash, 16) at line 1227,
 *     i.e. the 16 octets of the raw CMAC output are placed in the ATT Read
 *     Response value field in that order, unreversed.
 *   src/shared/gatt-client.c:1448 db_hash_read_cb() (client side) memcmp()s
 *     the received value against the locally computed hash with no
 *     reversal, so read and write are symmetric.
 *   src/settings.c:400 persists hash[0]..hash[15] in that same order.
 *
 * WHAT BLUEZ PUTS ON THE WIRE (unambiguous): the raw AES-CMAC output,
 * most significant octet first, i.e.
 *   F1 CA 2D 48 EC F5 8B AC 8A 88 30 BB B9 FB A9 90
 * for the Appendix B database.  BlueZ does not reverse it anywhere on
 * either the server or the client side.  This is
 * bt_extref_db_hash_wire_bluez[] below.
 *
 * BUT THIS IS A GENUINE ECOSYSTEM SPLIT -- READ BEFORE ASSERTING.
 * ---------------------------------------------------------------
 * Zephyr transmits the OPPOSITE order, and did so deliberately to pass
 * the Bluetooth SIG's own qualification test suite.
 *   zephyr/subsys/bluetooth/host/gatt.c, db_hash_gen(), current main:
 *     /-**
 *      * Core 5.1 does not state the endianness of the hash.
 *      * However Vol 3, Part F, 3.3.1 says that multi-octet Characteristic
 *      * Values shall be LE unless otherwise defined. PTS expects hash to be
 *      * in little endianness as well. bt_smp_aes_cmac calculates the hash in
 *      * big endianness so we have to swap.
 *      *-/
 *     sys_mem_swap(db_hash.hash, sizeof(db_hash.hash));
 *   and db_hash_read() returns db_hash.hash verbatim, so the reversed
 *   value is what reaches the wire.
 *   Zephyr's gen_hash_m() builds m identically to BlueZ's (little-endian
 *   handle, little-endian UUID, then value), so the two swaps do NOT
 *   cancel: the two stacks really do emit opposite octet orders.
 *   Provenance: zephyrproject-rtos/zephyr issue #17857 and PR #17859,
 *   "Bluetooth: GATT: Fix byte order for database hash", filed against
 *   PTS qualification test case GATT/SR/GAS/BV-02-C.
 *
 * THE SPEC DOES NOT CLEANLY SETTLE IT.  The two defensible readings:
 *   (a) BlueZ's: Section 7.3.1 and Appendix B define the hash as an octet
 *       string produced by AES-CMAC and print it MSB-first, so transmit it
 *       in that order.  Appendix B's closing note -- "The bytes in M0 to
 *       M6 and the Database Hash are ordered from the most significant on
 *       the left to the least significant on the right" -- is read as
 *       fixing the wire order.
 *   (b) Zephyr's / PTS's: Table 7.8 types the value as uint128, i.e. a
 *       multi-octet integer field, and Vol 3, Part G, Section 2.4 (text
 *       line 71983) says "The Characteristic Value and any fields within
 *       it shall be little-endian unless otherwise defined in the
 *       specification which defines the characteristic."  Appendix B's
 *       note describes the printed significance ordering of the VALUE, not
 *       a transmission order, so nothing "otherwise defines" it and the
 *       default little-endian rule applies: least significant octet first.
 *
 * The qualification authority sides with (b).  BlueZ is therefore the
 * outlier here, and "matches BlueZ" is NOT the same as "passes PTS".
 * Both candidate encodings are provided below so that a test can assert
 * whichever this project decides to ship, deliberately and in writing,
 * rather than by accident.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_DB_HASH_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_DB_HASH_H

#include <stdint.h>

/* Core 6.3, Vol 3, Part G, Section 7.3.1: k is all zero. */
#define BT_EXTREF_DB_HASH_KEY_LEN 16
static const uint8_t bt_extref_db_hash_key[BT_EXTREF_DB_HASH_KEY_LEN] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Core 6.3, Vol 3, Part G, Appendix B, blocks M0..M6 concatenated.
 * This is the AES-CMAC message m for the Appendix B example database,
 * in the order the octets are fed to the MAC.
 */
#define BT_EXTREF_DB_HASH_M_LEN 111
static const uint8_t bt_extref_db_hash_m[BT_EXTREF_DB_HASH_M_LEN] = {
	0x01, 0x00, 0x00, 0x28, 0x00, 0x18, 0x02, 0x00,
	0x03, 0x28, 0x0a, 0x03, 0x00, 0x00, 0x2a, 0x04,
	0x00, 0x03, 0x28, 0x02, 0x05, 0x00, 0x01, 0x2a,
	0x06, 0x00, 0x00, 0x28, 0x01, 0x18, 0x07, 0x00,
	0x03, 0x28, 0x20, 0x08, 0x00, 0x05, 0x2a, 0x09,
	0x00, 0x02, 0x29, 0x0a, 0x00, 0x03, 0x28, 0x0a,
	0x0b, 0x00, 0x29, 0x2b, 0x0c, 0x00, 0x03, 0x28,
	0x02, 0x0d, 0x00, 0x2a, 0x2b, 0x0e, 0x00, 0x00,
	0x28, 0x08, 0x18, 0x0f, 0x00, 0x02, 0x28, 0x14,
	0x00, 0x16, 0x00, 0x0f, 0x18, 0x10, 0x00, 0x03,
	0x28, 0xa2, 0x11, 0x00, 0x18, 0x2a, 0x12, 0x00,
	0x02, 0x29, 0x13, 0x00, 0x00, 0x29, 0x00, 0x00,
	0x14, 0x00, 0x01, 0x28, 0x0f, 0x18, 0x15, 0x00,
	0x03, 0x28, 0x02, 0x16, 0x00, 0x19, 0x2a
};

/*
 * Core 6.3, Vol 3, Part G, Appendix B: the AES-CMAC output, most
 * significant octet first (bt_extref_db_hash_cmac[0] == 0xf1).
 */
#define BT_EXTREF_DB_HASH_LEN 16
static const uint8_t bt_extref_db_hash_cmac[BT_EXTREF_DB_HASH_LEN] = {
	0xf1, 0xca, 0x2d, 0x48, 0xec, 0xf5, 0x8b, 0xac,
	0x8a, 0x88, 0x30, 0xbb, 0xb9, 0xfb, 0xa9, 0x90
};

/*
 * CANDIDATE (a): the octets BlueZ places in the ATT Read Response value
 * field for the Database Hash characteristic (UUID 0x2B2A), and the
 * octets BlueZ's client compares against its stored copy.
 *
 * Identical to bt_extref_db_hash_cmac: NOT byte-reversed.  Sourced from
 * BlueZ src/gatt-database.c:1227 (server) and
 * src/shared/gatt-client.c:1448 (client); see the file header.
 */
static const uint8_t bt_extref_db_hash_wire_bluez[BT_EXTREF_DB_HASH_LEN] = {
	0xf1, 0xca, 0x2d, 0x48, 0xec, 0xf5, 0x8b, 0xac,
	0x8a, 0x88, 0x30, 0xbb, 0xb9, 0xfb, 0xa9, 0x90
};

/*
 * CANDIDATE (b): the octets Zephyr places on the wire, and the octets the
 * SIG qualification suite expects per PTS test GATT/SR/GAS/BV-02-C: the
 * same 128-bit value transmitted least significant octet first.
 *
 * This is bt_extref_db_hash_cmac[] reversed.  The reversal is a pure
 * reordering of the externally published Appendix B constant -- no key
 * material or algorithm is involved and nothing was computed by blued --
 * and it is performed here by the generator, not typed by hand.
 * Sourced from zephyr/subsys/bluetooth/host/gatt.c db_hash_gen()
 * (sys_mem_swap) and db_hash_read(); see the file header.
 */
static const uint8_t bt_extref_db_hash_wire_zephyr_pts[BT_EXTREF_DB_HASH_LEN] = {
	0x90, 0xa9, 0xfb, 0xb9, 0xbb, 0x30, 0x88, 0x8a,
	0xac, 0x8b, 0xf5, 0xec, 0x48, 0x2d, 0xca, 0xf1
};

/* Core 6.3, Vol 3, Part G, Table 7.7/7.8 and Assigned Numbers. */
#define BT_EXTREF_DB_HASH_UUID16 0x2b2a

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_DB_HASH_H */

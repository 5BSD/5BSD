# Generate the external GATT Database Hash reference oracle directly from the
# Bluetooth Core 6.3 text.  Nothing here is derived from blued: the message
# blocks M0..M6 and the resulting hash are parsed out of Vol 3, Part G,
# Appendix B ("Example Database Hash"), and the on-the-wire byte order is
# asserted from BlueZ (see the citations emitted into the header).
#
# Usage:
#	awk -f spec_extref_db_hash_gen.awk Core_Specification_6_3.txt
#
# Style follows generate_core63_oracles.awk: values are parsed from the
# normative text and validated before output; the script fails loudly rather
# than emitting a value it could not confirm.

function emit_bytes(hex, indent,    i, n, out) {
	n = length(hex) / 2
	out = ""
	for (i = 0; i < n; i++) {
		if (i > 0) {
			out = out ","
			if (i % 8 == 0)
				out = out "\n" indent
			else
				out = out " "
		}
		out = out "0x" tolower(substr(hex, i * 2 + 1, 2))
	}
	return out
}

BEGIN {
	in_appendix = 0
	m = ""
	hash = ""
	in_hash = 0
	nblocks = 0
}

# Appendix B body.  Guard on the section heading rather than a page number so
# that repagination of the source cannot silently move the window.
/^Appendix B[ \t]+Example Database Hash[ \t]*$/ {
	in_appendix = 1
	next
}

in_appendix == 0 { next }

# "     M0: 01000028 00180200 03280A03 00002A04"
/^[ \t]*M[0-9]+:[ \t]*[0-9A-Fa-f ]+$/ {
	line = $0
	sub(/^[ \t]*M[0-9]+:[ \t]*/, "", line)
	gsub(/[ \t]/, "", line)
	if (line !~ /^[0-9A-Fa-f]+$/) {
		print "malformed Database Hash message block: " $0 > "/dev/stderr"
		exit 1
	}
	m = m toupper(line)
	nblocks++
	next
}

# "The resulting Database Hash is (MSB to LSB):"
/^The resulting Database Hash is \(MSB to LSB\):[ \t]*$/ {
	in_hash = 1
	next
}

in_hash == 1 {
	line = $0
	sub(/^[ \t]*Database Hash = AES-CMACk\(m\) =[ \t]*/, "", line)
	if (line ~ /^[ \t]*$/)
		next
	gsub(/[ \t]/, "", line)
	if (line !~ /^[0-9A-Fa-f]+$/) {
		print "malformed Database Hash value: " $0 > "/dev/stderr"
		exit 1
	}
	hash = hash toupper(line)
	if (length(hash) >= 32) {
		in_hash = 0
		in_appendix = 0
	}
	next
}

END {
	if (nblocks == 0) {
		print "no Database Hash message blocks found" > "/dev/stderr"
		exit 1
	}
	if (length(hash) != 32) {
		print "Database Hash is not 128 bits: " hash > "/dev/stderr"
		exit 1
	}
	if (length(m) % 2 != 0) {
		print "Database Hash message is not a whole number of octets" > "/dev/stderr"
		exit 1
	}
	mlen = length(m) / 2
	# Appendix B's example database yields 111 octets of m (blocks M0..M6,
	# the last one short).  Assert it so that a mis-parse cannot pass.
	if (mlen != 111) {
		print "unexpected Database Hash message length " mlen > "/dev/stderr"
		exit 1
	}

	print "/*"
	print " * Generated from the Bluetooth Core 6.3 text by"
	print " * spec_extref_db_hash_gen.awk; do not edit."
	print " *"
	print " * EXTERNAL REFERENCE ORACLE.  Every value below comes from outside this"
	print " * source tree.  Nothing here was produced by running blued."
	print " *"
	print " * Spec provenance:"
	print " *   Core 6.3, Vol 3, Part G, Section 7.3   -- Database Hash characteristic,"
	print " *     Table 7.8 types the characteristic value as uint128."
	print " *   Core 6.3, Vol 3, Part G, Section 7.3.1 -- \"Database Hash =\","
	print " *     \"AES-CMACk(m)\" with k = 0, m built in ascending handle order with"
	print " *     each field little-endian, padded per RFC-4493 Section 2.4."
	print " *   Core 6.3, Vol 3, Part G, Appendix B    -- worked example; the source"
	print " *     text states \"The bytes in M0 to M6 and the Database Hash are ordered"
	print " *     from the most significant on the left to the least significant on"
	print " *     the right.\""
	print " *"
	print " * BlueZ provenance for the ON-THE-WIRE byte order (snapshot"
	print " * git.kernel.org/pub/scm/bluetooth/bluez.git, commit"
	print " * 92305dc06ab8a6d89af2dae1d725cc4d51462ad1):"
	print " *   src/shared/crypto.c:724  bt_crypto_gatt_hash() -- feeds the iovec"
	print " *     straight into the kernel cmac(aes) socket and read()s the result"
	print " *     straight out.  Note what it does NOT do: unlike aes_cmac() at"
	print " *     src/shared/crypto.c:619, which swap_buf()s key, message AND result"
	print " *     for the SMP functions, bt_crypto_gatt_hash() performs NO swap on"
	print " *     either side.  res[0] is therefore the most significant CMAC octet."
	print " *   src/shared/gatt-db.c:377  gen_hash_m() -- builds each iovec element as"
	print " *     put_le16(handle) || bt_uuid_to_le(type) || value, i.e. exactly the"
	print " *     little-endian wire concatenation of Section 7.3.1."
	print " *   src/shared/gatt-db.c:429  db_hash_update() -> db->hash."
	print " *   src/shared/gatt-db.c:711  gatt_db_get_hash() returns db->hash verbatim."
	print " *   src/gatt-database.c:1212  db_hash_read_cb() ->"
	print " *     gatt_db_attribute_read_result(attrib, id, 0, hash, 16) at line 1227,"
	print " *     i.e. the 16 octets of the raw CMAC output are placed in the ATT Read"
	print " *     Response value field in that order, unreversed."
	print " *   src/shared/gatt-client.c:1448 db_hash_read_cb() (client side) memcmp()s"
	print " *     the received value against the locally computed hash with no"
	print " *     reversal, so read and write are symmetric."
	print " *   src/settings.c:400 persists hash[0]..hash[15] in that same order."
	print " *"
	print " * WHAT BLUEZ PUTS ON THE WIRE (unambiguous): the raw AES-CMAC output,"
	print " * most significant octet first, i.e."
	print " *   F1 CA 2D 48 EC F5 8B AC 8A 88 30 BB B9 FB A9 90"
	print " * for the Appendix B database.  BlueZ does not reverse it anywhere on"
	print " * either the server or the client side.  This is"
	print " * bt_extref_db_hash_wire_bluez[] below."
	print " *"
	print " * BUT THIS IS A GENUINE ECOSYSTEM SPLIT -- READ BEFORE ASSERTING."
	print " * ---------------------------------------------------------------"
	print " * Zephyr transmits the OPPOSITE order, and did so deliberately to pass"
	print " * the Bluetooth SIG's own qualification test suite."
	print " *   zephyr/subsys/bluetooth/host/gatt.c, db_hash_gen(), current main:"
	print " *     /-**"
	print " *      * Core 5.1 does not state the endianness of the hash."
	print " *      * However Vol 3, Part F, 3.3.1 says that multi-octet Characteristic"
	print " *      * Values shall be LE unless otherwise defined. PTS expects hash to be"
	print " *      * in little endianness as well. bt_smp_aes_cmac calculates the hash in"
	print " *      * big endianness so we have to swap."
	print " *      *-/"
	print " *     sys_mem_swap(db_hash.hash, sizeof(db_hash.hash));"
	print " *   and db_hash_read() returns db_hash.hash verbatim, so the reversed"
	print " *   value is what reaches the wire."
	print " *   Zephyr's gen_hash_m() builds m identically to BlueZ's (little-endian"
	print " *   handle, little-endian UUID, then value), so the two swaps do NOT"
	print " *   cancel: the two stacks really do emit opposite octet orders."
	print " *   Provenance: zephyrproject-rtos/zephyr issue #17857 and PR #17859,"
	print " *   \"Bluetooth: GATT: Fix byte order for database hash\", filed against"
	print " *   PTS qualification test case GATT/SR/GAS/BV-02-C."
	print " *"
	print " * THE SPEC DOES NOT CLEANLY SETTLE IT.  The two defensible readings:"
	print " *   (a) BlueZ's: Section 7.3.1 and Appendix B define the hash as an octet"
	print " *       string produced by AES-CMAC and print it MSB-first, so transmit it"
	print " *       in that order.  Appendix B's closing note -- \"The bytes in M0 to"
	print " *       M6 and the Database Hash are ordered from the most significant on"
	print " *       the left to the least significant on the right\" -- is read as"
	print " *       fixing the wire order."
	print " *   (b) Zephyr's / PTS's: Table 7.8 types the value as uint128, i.e. a"
	print " *       multi-octet integer field, and Vol 3, Part G, Section 2.4 (text"
	print " *       line 71983) says \"The Characteristic Value and any fields within"
	print " *       it shall be little-endian unless otherwise defined in the"
	print " *       specification which defines the characteristic.\"  Appendix B's"
	print " *       note describes the printed significance ordering of the VALUE, not"
	print " *       a transmission order, so nothing \"otherwise defines\" it and the"
	print " *       default little-endian rule applies: least significant octet first."
	print " *"
	print " * The qualification authority sides with (b).  BlueZ is therefore the"
	print " * outlier here, and \"matches BlueZ\" is NOT the same as \"passes PTS\"."
	print " * Both candidate encodings are provided below so that a test can assert"
	print " * whichever this project decides to ship, deliberately and in writing,"
	print " * rather than by accident."
	print " */"
	print "#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_DB_HASH_H"
	print "#define TESTS_BLUETOOTH_SPEC_EXTREF_DB_HASH_H"
	print ""
	print "#include <stdint.h>"
	print ""
	print "/* Core 6.3, Vol 3, Part G, Section 7.3.1: k is all zero. */"
	print "#define BT_EXTREF_DB_HASH_KEY_LEN 16"
	print "static const uint8_t bt_extref_db_hash_key[BT_EXTREF_DB_HASH_KEY_LEN] = {"
	print "\t0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,"
	print "\t0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00"
	print "};"
	print ""
	print "/*"
	print " * Core 6.3, Vol 3, Part G, Appendix B, blocks M0..M6 concatenated."
	print " * This is the AES-CMAC message m for the Appendix B example database,"
	print " * in the order the octets are fed to the MAC."
	print " */"
	printf "#define BT_EXTREF_DB_HASH_M_LEN %d\n", mlen
	print "static const uint8_t bt_extref_db_hash_m[BT_EXTREF_DB_HASH_M_LEN] = {"
	printf "\t%s\n", emit_bytes(m, "\t")
	print "};"
	print ""
	print "/*"
	print " * Core 6.3, Vol 3, Part G, Appendix B: the AES-CMAC output, most"
	print " * significant octet first (bt_extref_db_hash_cmac[0] == 0xf1)."
	print " */"
	print "#define BT_EXTREF_DB_HASH_LEN 16"
	print "static const uint8_t bt_extref_db_hash_cmac[BT_EXTREF_DB_HASH_LEN] = {"
	printf "\t%s\n", emit_bytes(hash, "\t")
	print "};"
	print ""
	print "/*"
	print " * CANDIDATE (a): the octets BlueZ places in the ATT Read Response value"
	print " * field for the Database Hash characteristic (UUID 0x2B2A), and the"
	print " * octets BlueZ's client compares against its stored copy."
	print " *"
	print " * Identical to bt_extref_db_hash_cmac: NOT byte-reversed.  Sourced from"
	print " * BlueZ src/gatt-database.c:1227 (server) and"
	print " * src/shared/gatt-client.c:1448 (client); see the file header."
	print " */"
	print "static const uint8_t bt_extref_db_hash_wire_bluez[BT_EXTREF_DB_HASH_LEN] = {"
	printf "\t%s\n", emit_bytes(hash, "\t")
	print "};"
	print ""
	print "/*"
	print " * CANDIDATE (b): the octets Zephyr places on the wire, and the octets the"
	print " * SIG qualification suite expects per PTS test GATT/SR/GAS/BV-02-C: the"
	print " * same 128-bit value transmitted least significant octet first."
	print " *"
	print " * This is bt_extref_db_hash_cmac[] reversed.  The reversal is a pure"
	print " * reordering of the externally published Appendix B constant -- no key"
	print " * material or algorithm is involved and nothing was computed by blued --"
	print " * and it is performed here by the generator, not typed by hand."
	print " * Sourced from zephyr/subsys/bluetooth/host/gatt.c db_hash_gen()"
	print " * (sys_mem_swap) and db_hash_read(); see the file header."
	print " */"
	print "static const uint8_t bt_extref_db_hash_wire_zephyr_pts[BT_EXTREF_DB_HASH_LEN] = {"
	rev = ""
	for (i = 15; i >= 0; i--)
		rev = rev substr(hash, i * 2 + 1, 2)
	printf "\t%s\n", emit_bytes(rev, "\t")
	print "};"
	print ""
	print "/* Core 6.3, Vol 3, Part G, Table 7.7/7.8 and Assigned Numbers. */"
	print "#define BT_EXTREF_DB_HASH_UUID16 0x2b2a"
	print ""
	print "#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_DB_HASH_H */"
}

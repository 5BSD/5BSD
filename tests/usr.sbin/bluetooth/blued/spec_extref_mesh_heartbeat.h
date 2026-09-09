/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh Heartbeat -- the two DIFFERENT
 * logarithmic field transforms, Table 4.1, Table 4.323, and the field-zeroing
 * and remaining-versus-configured reporting rules of the four Config
 * Heartbeat messages.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/lib/libmesh or /usr/src/usr.sbin/bluetooth, and no value was
 * produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ======================
 * Heartbeat compresses 16-bit counters into 8-bit "Log" fields, and it does so
 * with TWO transforms that are not inverses of each other and are not the same
 * function:
 *
 *   - The general transform, Table 4.1, is a FLOOR: "the largest integer n,
 *     where 2^(n-1) is less than or equal to the two-octet value".  It is used
 *     for Heartbeat Subscription Count and Heartbeat Subscription Period.
 *   - Heartbeat Publication Count Log uses a CEILING: "the smallest integer n
 *     where 2^(n-1) is greater than or equal to the Heartbeat Publication
 *     Count value".
 *
 * They differ on every value that is not an exact power of two, and they have
 * different ranges (Table 4.1 tops out at 0x11 meaning 0x10000; publication
 * CountLog's 0x11 means 0xFFFE, and 0xFF means 0xFFFF).  Getting the decode
 * direction of publication CountLog wrong -- in particular collapsing 0x11
 * into "indefinitely" -- turns a bounded 65534-message heartbeat burst into an
 * unbounded one, and is visible on the wire in the very next Status message.
 *
 * SOURCES
 * =======
 * SPEC: /usr/src/bluetooth-specs/MshPRT_v1.1.1.txt.  Line numbers below are
 *   lines of that .txt file.
 *     Section 4.1.3   Log field transform, Table 4.1 .... lines 12155-12197
 *     Section 4.2.18  Heartbeat Publication ............. lines 13290-13420
 *     Section 4.2.19  Heartbeat Subscription ............ lines 13440-13530
 *     Section 4.4.1.2.15 Heartbeat Publication state .... lines ~24340-24410
 *     Table 4.323 CountLog -> Count mapping ............. lines 24401-24413
 *     Section 4.4.1.2.16 Heartbeat Subscription state ... lines 24415-24460
 *
 * REFERENCE IMPLEMENTATIONS
 * =========================
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac): subsys/bluetooth/mesh/
 *   heartbeat.c and cfg_srv.c.  Zephyr implements both directions of Table
 *   4.323 explicitly, including the 0x11 <-> 0xFFFE special case, and carries
 *   in-code comments naming the PTS test cases its behaviour was tuned to.
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1): mesh/cfgmod-server.c
 *   and mesh/net.c.  BlueZ implements heartbeat publication and subscription
 *   but reports some fields differently from Zephyr on the disable path (see
 *   MIN/MAX HOPS below), which is a genuine split.
 * APACHE NIMBLE: nimble/host/mesh/src/heartbeat.c, Mesh 1.0-era but the
 *   heartbeat encodings did not change in 1.1, so it is a usable third
 *   reading.
 */

#ifndef SPEC_EXTREF_MESH_HEARTBEAT_H
#define SPEC_EXTREF_MESH_HEARTBEAT_H

#include <stdint.h>

/*
 * ---------------------------------------------------------------------------
 * Transform 1: Table 4.1 "Log field values", the FLOOR transform.
 * Section 4.1.3, .txt lines 12155-12197.
 *
 * .txt lines 12155-12157, verbatim:
 *   "In order to compress two-octet values into one-octet fields, the
 *    following logarithmic transformation is used: any two-octet value is
 *    mapped onto a one-octet field value representing the largest integer n,
 *    where 2^(n-1) is less than or equal to the two-octet value."
 *
 * Transcribed in full, as ranges, because the boundaries are what a decoder
 * gets wrong:
 *   0x01 -> 0x0001            0x0A -> 0x0200-0x03FF
 *   0x02 -> 0x0002-0x0003     0x0B -> 0x0400-0x07FF
 *   0x03 -> 0x0004-0x0007     0x0C -> 0x0800-0x0FFF
 *   0x04 -> 0x0008-0x000F     0x0D -> 0x1000-0x1FFF
 *   0x05 -> 0x0010-0x001F     0x0E -> 0x2000-0x3FFF
 *   0x06 -> 0x0020-0x003F     0x0F -> 0x4000-0x7FFF
 *   0x07 -> 0x0040-0x007F     0x10 -> 0x8000-0xFFFF
 *   0x08 -> 0x0080-0x00FF     0x11 -> 0x10000
 *   0x09 -> 0x0100-0x01FF
 *
 * Note the last row: log value 0x11 corresponds to 0x10000, a value that does
 * not fit in sixteen bits.  It is reachable only for Period, whose underlying
 * quantity is a duration in seconds, not a counter.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_LOG_TABLE41_MIN		0x01u
#define	SPEC_EXTREF_MESH_LOG_TABLE41_MAX		0x11u
#define	SPEC_EXTREF_MESH_LOG_TABLE41_TOP_VALUE		0x10000UL

/* Lower bound of the 2-octet range that maps to log value n (n >= 1):
 * 2^(n-1).  The range's upper bound is 2^n - 1, except for n = 0x11. */
#define	SPEC_EXTREF_MESH_LOG_TABLE41_LOW(n)	(1UL << ((n) - 1u))
#define	SPEC_EXTREF_MESH_LOG_TABLE41_HIGH(n)					\
	((n) == 0x11u ? 0x10000UL : ((1UL << (n)) - 1UL))

/*
 * ---------------------------------------------------------------------------
 * Transform 2: Heartbeat Publication Count Log, the CEILING transform.
 * Section 4.2.18.2, .txt lines 13312-13318.
 *
 * .txt lines 13312-13318, verbatim:
 *   "The Heartbeat Publication Count Log is a representation of the Heartbeat
 *    Publication Count state value. The Heartbeat Publication Count Log and
 *    Heartbeat Publication Count with the value 0x00 and 0x0000 are
 *    equivalent. The Heartbeat Publication Count Log value of 0xFF is
 *    equivalent to the Heartbeat Publication count value of 0xFFFF. The
 *    Heartbeat Publication Count Log value between 0x01 and 0x11 shall
 *    represent that smallest integer n where 2^(n-1) is greater than or equal
 *    to the Heartbeat Publication Count value. For example, if the Heartbeat
 *    Publication Count value is 0x0579, then the Heartbeat Publication Count
 *    Log value would be 0x0C."
 *
 * The worked example is the vector to test against: 0x0579 -> 0x0C.  Under the
 * FLOOR transform of Table 4.1 the same input gives 0x0B.  One value, two
 * transforms, two different answers -- which is precisely why they must not be
 * shared.
 *
 * Table 4.36 "Heartbeat Publication Count Log values", .txt lines 13322-13330,
 * verbatim:
 *   "0x00       Periodic Heartbeat messages are not published"
 *   "0x01-0x11  Number of Heartbeat messages, 2^(n-1), that remain to be sent"
 *   "0x12-0xFE  Prohibited"
 *   "0xFF       Periodic Heartbeat messages are published indefinitely"
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_NONE		0x00u
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_MIN		0x01u
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_MAX		0x11u
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_PROHIB_MIN	0x12u
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_PROHIB_MAX	0xFEu
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_INDEFINITE	0xFFu

/* The specification's own worked example, ceiling transform. */
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_EX_COUNT	0x0579u
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_EX_LOG		0x0Cu
/* The same input under the Table 4.1 floor transform, for contrast. */
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_EX_FLOOR_LOG	0x0Bu

/*
 * TABLE 4.323 "CountLog Field Value to Heartbeat Publication Count State
 * mappings", .txt lines 24401-24413, transcribed in full.  This is the DECODE
 * direction -- what a Config Heartbeat Publication Set's CountLog field means
 * as a stored count:
 *
 *   0x00        -> 0x0000
 *   0x01-0x10   -> 2^(CountLog-1)
 *   0x11        -> 0xFFFE
 *   0x12-0xFE   -> Prohibited
 *   0xFF        -> 0xFFFF
 *
 * Note carefully: the 0x01-0x10 row stops at 0x10, and 0x11 is a SPECIAL CASE
 * mapping to 0xFFFE -- not to 2^16 = 0x10000, which does not fit, and NOT to
 * 0xFFFF, which is the distinct "publish indefinitely" value carried by 0xFF.
 * Collapsing 0x11 into 0xFFFF is the single easiest mistake to make here, and
 * it is directly observable: a Set carrying CountLog 0x11 must produce a
 * Status carrying CountLog 0x11, not 0xFF.
 */
#define	SPEC_EXTREF_MESH_HB_PUB_COUNT_STOPPED		0x0000u
#define	SPEC_EXTREF_MESH_HB_PUB_COUNT_MAX_FINITE	0xFFFEu	/* CountLog 0x11 */
#define	SPEC_EXTREF_MESH_HB_PUB_COUNT_INDEFINITE	0xFFFFu	/* CountLog 0xFF */
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_POW2_MAX	0x10u

#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_DECODE(cl)			\
	((cl) == 0x00u ? 0x0000u :					\
	 (cl) == 0xFFu ? 0xFFFFu :					\
	 (cl) == 0x11u ? 0xFFFEu :					\
	 (cl) <= 0x10u ? (uint16_t)(1u << ((cl) - 1u)) : 0u /* prohibited */)

/*
 * The 0x11 <-> 0xFFFE round trip, stated as an assertion a test can make
 * directly.  Encoding 0xFFFE with the ceiling transform must give 0x11, since
 * 2^(0x11-1) = 65536 >= 65534 while 2^(0x10-1) = 32768 < 65534.
 */
#define	SPEC_EXTREF_MESH_HB_PUB_COUNTLOG_ROUNDTRIP_0X11	1

/*
 * .txt lines 13305-13310, verbatim -- the decrement semantics, which decide
 * what the Status must report:
 *   "When set to 0xFFFF, it is not decremented after publication of a periodic
 *    Heartbeat message. When set to 0x0000, periodic Heartbeat messages are
 *    not published. When set to a value greater than or equal to 0x0001 or
 *    less than or equal to 0xFFFE, it is decremented after publishing a
 *    periodic Heartbeat message. Publication of a triggered Heartbeat message
 *    does not affect the Heartbeat Publication Count state."
 *
 * A triggered heartbeat (a feature-change heartbeat) does NOT consume the
 * count.  Only periodic publication does.
 */
#define	SPEC_EXTREF_MESH_HB_TRIGGERED_DOES_NOT_DECREMENT	1

/*
 * ---------------------------------------------------------------------------
 * Heartbeat Publication Period Log, Section 4.2.18.3.
 * .txt lines 13383-13387: "The value is represented as 2^(n-1) seconds. For
 * example, the value 0x04 would have a publication period of 8 seconds, and
 * the value 0x07 would have a publication period of 64 seconds."
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_HB_PERIODLOG_SECONDS(n)			\
	((n) == 0u ? 0UL : (1UL << ((n) - 1u)))
#define	SPEC_EXTREF_MESH_HB_PERIODLOG_EX1_LOG		0x04u
#define	SPEC_EXTREF_MESH_HB_PERIODLOG_EX1_SECONDS	8UL
#define	SPEC_EXTREF_MESH_HB_PERIODLOG_EX2_LOG		0x07u
#define	SPEC_EXTREF_MESH_HB_PERIODLOG_EX2_SECONDS	64UL

/*
 * ---------------------------------------------------------------------------
 * Features bitmask, Table 4.39 (.txt lines 13380-13392) and Table 4.40.
 * Bit set = "The feature change indicated by the bit triggers a Heartbeat
 * message".  Bits 4-15 are RFU.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_HB_FEATURE_RELAY		0x0001u	/* bit 0 */
#define	SPEC_EXTREF_MESH_HB_FEATURE_PROXY		0x0002u	/* bit 1 */
#define	SPEC_EXTREF_MESH_HB_FEATURE_FRIEND		0x0004u	/* bit 2 */
#define	SPEC_EXTREF_MESH_HB_FEATURE_LOW_POWER		0x0008u	/* bit 3 */
#define	SPEC_EXTREF_MESH_HB_FEATURE_RFU_MASK		0xFFF0u
#define	SPEC_EXTREF_MESH_HB_FEATURE_DEFINED_MASK	0x000Fu

/*
 * ---------------------------------------------------------------------------
 * Heartbeat Subscription, Section 4.2.19.
 * ---------------------------------------------------------------------------
 *
 * .txt lines 13440-13443, verbatim -- the destination constraint:
 *   "The Heartbeat Subscription Destination shall be the unassigned address,
 *    the primary unicast address of the node, or a group address, all other
 *    values are Prohibited."
 * Note what is excluded: a VIRTUAL address, and any unicast address other than
 * this node's own primary.
 */
#define	SPEC_EXTREF_MESH_HB_SUB_DST_ALLOWS_UNASSIGNED	1
#define	SPEC_EXTREF_MESH_HB_SUB_DST_ALLOWS_OWN_PRIMARY	1
#define	SPEC_EXTREF_MESH_HB_SUB_DST_ALLOWS_GROUP	1
#define	SPEC_EXTREF_MESH_HB_SUB_DST_ALLOWS_VIRTUAL	0
#define	SPEC_EXTREF_MESH_HB_SUB_DST_ALLOWS_OTHER_UNICAST	0

/* Table 4.41, .txt lines 13466-13472: the Count state saturates, it does not
 * wrap.  "0xFFFF: More than 0xFFFE messages have been received". */
#define	SPEC_EXTREF_MESH_HB_SUB_COUNT_SATURATES_AT	0xFFFFu

/* Table 4.42, .txt lines 13492-13500: Subscription Period Log.
 *   0x00       Heartbeat messages are not processed
 *   0x01-0x11  Remaining period in seconds, per Table 4.1
 *   0x12-0xFF  Prohibited
 * Subscription Count Log and Period Log both use the Table 4.1 FLOOR
 * transform; Subscription Count Log caps at 0x10, Period Log at 0x11. */
#define	SPEC_EXTREF_MESH_HB_SUB_COUNTLOG_MAX		0x10u
#define	SPEC_EXTREF_MESH_HB_SUB_PERIODLOG_MAX		0x11u
#define	SPEC_EXTREF_MESH_HB_SUB_PERIODLOG_PROHIB_MIN	0x12u
#define	SPEC_EXTREF_MESH_HB_SUB_USES_FLOOR_TRANSFORM	1
#define	SPEC_EXTREF_MESH_HB_PUB_COUNT_USES_CEIL_TRANSFORM	1

/* Tables 4.43/4.44: MinHops and MaxHops are 0x00-0x7F; 0x80-0xFF Prohibited. */
#define	SPEC_EXTREF_MESH_HB_HOPS_MAX			0x7Fu
#define	SPEC_EXTREF_MESH_HB_HOPS_PROHIBITED_MIN		0x80u

/*
 * ---------------------------------------------------------------------------
 * Reporting rules.  These are the ones that differ BETWEEN the two heartbeat
 * message families, which is why they are pinned separately rather than left
 * as "the Status echoes the message".
 * ---------------------------------------------------------------------------
 *
 * Heartbeat PUBLICATION Get / Status, .txt lines 24351-24357, verbatim:
 *   "...setting the CountLog field to the Heartbeat Publication Count Log
 *    representation of the Heartbeat Publication Count state, the PeriodLog
 *    field to the value of the Heartbeat Publication Period ... When the
 *    Destination field is set to the unassigned address, the values of the
 *    CountLog, PeriodLog, TTL, and Features fields shall be set to 0x00 and
 *    NetKeyIndex field shall be set to 0x0000."
 *
 * So: CountLog reports the REMAINING count (the live state, decremented),
 * while PeriodLog reports the CONFIGURED period.  And an unassigned
 * Destination zeroes everything else.
 */
#define	SPEC_EXTREF_MESH_HB_PUB_STATUS_COUNT_IS_REMAINING	1
#define	SPEC_EXTREF_MESH_HB_PUB_STATUS_PERIOD_IS_CONFIGURED	1
#define	SPEC_EXTREF_MESH_HB_PUB_UNASSIGNED_DST_ZEROES_ALL	1

/*
 * Heartbeat PUBLICATION Set failure, .txt lines 24369-24373, verbatim:
 *   "it shall respond with a Config Heartbeat Publication Status message,
 *    setting the Destination, CountLog, PeriodLog, and TTL fields to the
 *    values of corresponding fields of the incoming message and setting the
 *    Status field to a status code."
 *
 * ECHO THE REQUEST.  Note this is the OPPOSITE of the Model Publication rule,
 * where a failing Status zeroes every field but ElementAddress and
 * ModelIdentifier (.txt lines 23830-23833).  The two are easy to swap.
 */
#define	SPEC_EXTREF_MESH_HB_PUB_STATUS_ON_ERROR_ECHOES_REQUEST	1
#define	SPEC_EXTREF_MESH_MODEL_PUB_STATUS_ON_ERROR_ZEROES	1

/*
 * Heartbeat SUBSCRIPTION Get / Status, .txt lines 24425-24433, verbatim:
 *   "When the Heartbeat Subscription Source state or the Heartbeat
 *    Subscription Destination state is set to the unassigned address, the
 *    value of the Source and Destination fields ... shall be set to the
 *    unassigned address and the values of the CountLog, PeriodLog, MinHops,
 *    and MaxHops fields shall be set to 0x00."
 *
 * That sentence governs the GET response.  The disable action list for a SET
 * (.txt lines 24437-24452) is deliberately different: it resets Source,
 * Destination and Period, and then says the Status carries "the Source,
 * Destination, MinHops, and MaxHops fields set to the NEW VALUES of the
 * corresponding fields of the Heartbeat Subscription state" -- it does not
 * order MinHops/MaxHops to be reset.  Applying the Get rule to the Set
 * response is a real divergence, not a cosmetic one: Zephyr reports MinHops
 * 0x7F after a disabling Set and 0x00 on a subsequent Get, and carries an
 * in-code note naming the PTS case that requires it.  BlueZ reports the
 * hops it actually collected.  This is the one genuinely contested cell in
 * the heartbeat surface.
 */
#define	SPEC_EXTREF_MESH_HB_SUB_GET_ZEROES_ON_UNASSIGNED	1
#define	SPEC_EXTREF_MESH_HB_SUB_SET_DISABLE_RESETS_SRC_DST_PERIOD	1
#define	SPEC_EXTREF_MESH_HB_SUB_SET_DISABLE_RESETS_HOPS_UNSTATED	1
/* Zephyr's PTS-tuned answer for MinHops in the disabling Set response. */
#define	SPEC_EXTREF_MESH_HB_SUB_SET_DISABLE_MINHOPS_ZEPHYR	0x7Fu

/*
 * The three conditions any one of which disables subscription, .txt lines
 * 24437-24443, verbatim: "The Source field is set to the unassigned address."
 * / "The Destination field is set to the unassigned address." / "The PeriodLog
 * field is set to 0x00."
 */
#define	SPEC_EXTREF_MESH_HB_SUB_DISABLE_ON_SRC_UNASSIGNED	1
#define	SPEC_EXTREF_MESH_HB_SUB_DISABLE_ON_DST_UNASSIGNED	1
#define	SPEC_EXTREF_MESH_HB_SUB_DISABLE_ON_PERIODLOG_ZERO	1

/* Config Heartbeat opcodes, for completeness. */
#define	SPEC_EXTREF_MESH_OP_HB_PUB_STATUS		0x06u	/* 1-octet */
#define	SPEC_EXTREF_MESH_OP_HB_PUB_GET			0x8038u
#define	SPEC_EXTREF_MESH_OP_HB_PUB_SET			0x8039u
#define	SPEC_EXTREF_MESH_OP_HB_SUB_GET			0x803Au
#define	SPEC_EXTREF_MESH_OP_HB_SUB_SET			0x803Bu
#define	SPEC_EXTREF_MESH_OP_HB_SUB_STATUS		0x803Cu

#endif /* SPEC_EXTREF_MESH_HEARTBEAT_H */

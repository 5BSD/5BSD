/*
 * EXTERNAL REFERENCE ORACLE: isochronous parameter ranges for the HCI LE
 * isochronous commands, and specifically the Retransmission Number (RTN)
 * bound, which differs between the connected (CIG) and broadcast (BIG)
 * commands.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from blued, iso.c, ctl_iso.c or
 * hci_misc.c.
 *
 * WHY THIS EXISTS
 * ---------------
 * ctl_iso.c carried a comment stating that the upper bound on RTN_C_To_P /
 * RTN_P_To_C for HCI_LE_Set_CIG_Parameters "could NOT be settled from in-tree
 * sources", and kept 0x1E as "the tightest bound we can defend".  The bound
 * IS settled, in three independent places, and it is not 0x1E.  0x1E is the
 * bound on a DIFFERENT command -- HCI_LE_Create_BIG.  This header pins both
 * so the two are never conflated again.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   (line numbers are lines of that .txt file)
 *
 *   Vol 4, Part E, Section 7.8.97 -- HCI_LE_Set_CIG_Parameters
 *   (section begins at text line 120922).
 *
 *   Command parameter table, RTN_C_To_P[i] (text lines 121221-121225),
 *   verbatim:
 *     "RTN_C_To_P[i]:                        Size: CIS_Count x 1 octet
 *       Value     Parameter Description
 *       0xXX      Number of times every CIS Data PDU should be retransmitted
 *                 from the Central to the Peripheral"
 *
 *   Command parameter table, RTN_P_To_C[i] (text lines 121228-121232),
 *   verbatim:
 *     "RTN_P_To_C[i]:                        Size: CIS_Count x 1 octet
 *       Value     Parameter Description
 *       0xXX      Number of times every CIS Data PDU should be retransmitted
 *                 from the Peripheral to the Central"
 *
 *   Note what is ABSENT from both tables: there is no "0x00 to 0xNN" row and
 *   no "All other values / Reserved for future use" row.  Every bounded
 *   parameter in this same command carries one -- CIG_ID (121141: "0x00 to
 *   0xEF" + "All other values Reserved for future use"), SDU_Interval
 *   (0x0000FF to 0x0FFFFF + RFU), Worst_Case_SCA (0x00 to 0x07 + RFU),
 *   Packing (0x00/0x01 + RFU), Framing (0x00/0x01/0x02 + RFU),
 *   Max_Transport_Latency (0x0005 to 0x0FA0 + RFU), CIS_Count (text line
 *   121174: "0x00 to 0x1F" + RFU), CIS_ID (0x00 to 0xEF + RFU), Max_SDU
 *   (0x0000 to 0x0FFF).  The RTN tables read "0xXX", the notation this
 *   specification uses for a field with no reserved values.  RTN for a CIS
 *   is therefore a full unsigned octet: 0x00 to 0xFF.
 *
 *   The descriptive text confirms that RTN is advisory rather than a
 *   constrained encoding.  Section 7.8.97, verbatim:
 *     "The RTN_C_To_P[i] (Retransmission Number) parameter contains the
 *      number of times that a CIS Data PDU should be retransmitted from the
 *      Central to Peripheral before being acknowledged or flushed
 *      (irrespective of which CIS events the retransmission opportunities
 *      occur in). If the CIS is unidirectional from Peripheral to Central,
 *      this parameter shall be ignored. Otherwise, this parameter is a
 *      recommendation to the Controller which the Controller may ignore."
 *
 *   Vol 4, Part E, Section 7.8.103 -- HCI_LE_Create_BIG (section begins at
 *   text line 122020).  Command parameter table, RTN (text lines
 *   122174-122179), verbatim:
 *     "RTN:                                                  Size: 1 octet
 *       Value                  Parameter Description
 *       0x00 to 0x1E           The number of times that every BIS Data PDU
 *                              should be retransmitted.
 *       All other values       Reserved for future use"
 *
 *   That is where 0x1E comes from.  It bounds the broadcast RTN only.
 *
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac) -- draws exactly this
 * distinction, in two separately named macros:
 *   include/zephyr/bluetooth/iso.h:135-142
 *     /-* Minimum connected ISO retransmission value (0) *-/
 *     #define BT_ISO_CONNECTED_RTN_MIN    0x00
 *     /-* Maximum connected ISO retransmission value (255) *-/
 *     #define BT_ISO_CONNECTED_RTN_MAX    0xFF
 *     /-* Minimum broadcast ISO retransmission value (0) *-/
 *     #define BT_ISO_BROADCAST_RTN_MIN    0x00
 *     /-* Maximum broadcast ISO retransmission value (30) *-/
 *     #define BT_ISO_BROADCAST_RTN_MAX    0x1E
 *
 *   subsys/bluetooth/host/iso.c:1047,1055-1059 -- valid_chan_io_qos() applies
 *   the RTN check ONLY when the channel is broadcast:
 *     if (IS_ENABLED(CONFIG_BT_ISO_BROADCASTER) && is_broadcast &&
 *         io_qos->rtn > BT_ISO_BROADCAST_RTN_MAX) {
 *             LOG_DBG("Invalid RTN %u", io_qos->phy);
 *             return false;
 *     }
 *   The unicast (CIG) path -- iso.c:1736,1741, reached from
 *   valid_cig_param() at iso.c:2061 -- performs no RTN range check at all.
 *
 *   subsys/bluetooth/audio/bap_broadcast_source.c:694 checks
 *   BT_ISO_BROADCAST_RTN_MAX; no BAP unicast path checks an RTN bound.
 *
 * NIMBLE (1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845) -- has no CIG support at
 * all; its only RTN validation is on HCI_LE_Create_BIG, in the controller:
 *   nimble/controller/src/ble_ll_iso_big.c:1281
 *     !IN_RANGE(cmd->rtn, 0x00, 0x1e) ||
 *   (this is ble_ll_iso_big_create_big(), validating the LE Create BIG
 *   command parameters -- again the broadcast command, not the CIG one.)
 *
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1) -- applies no RTN
 * range check anywhere.  It carries RTN as a plain uint8_t through the BAP
 * QoS structures and D-Bus dictionary (src/shared/bap.c:1063,1108,3374,
 * profiles/audio/bap.c:432,607, profiles/audio/media.c:884,1838) and hands it
 * to the kernel via the BT_ISO_QOS socket option.  Its own default unicast
 * values are small: src/shared/bap.c:384,391 use rtn = 2, and
 * src/shared/bap.c:1041-1042 defaults an unset rtn to 0x05.
 *
 * DETERMINATION
 * -------------
 * The two bounds are different and belong to different commands:
 *
 *   HCI_LE_Set_CIG_Parameters RTN_C_To_P / RTN_P_To_C : 0x00 - 0xFF
 *   HCI_LE_Create_BIG          RTN                    : 0x00 - 0x1E
 *
 * A host that rejects a CIG RTN above 0x1E rejects values the specification
 * permits and that Zephyr explicitly allows (BT_ISO_CONNECTED_RTN_MAX 0xFF).
 * Because RTN is advisory, an out-of-range value is not an interoperability
 * hazard on the air -- but rejecting a legal one locally is a host-side
 * failure with no spec basis.
 */

#ifndef SPEC_EXTREF_ISO_CIG_RTN_H
#define SPEC_EXTREF_ISO_CIG_RTN_H

#include <stdint.h>

/*
 * Core 6.3 Vol 4 Part E Sec 7.8.97, RTN_C_To_P[i]/RTN_P_To_C[i] tables
 * (.txt lines 121221, 121228): "0xXX", no reserved range.
 */
#define SPEC_EXTREF_ISO_CIG_RTN_MIN		0x00u
#define SPEC_EXTREF_ISO_CIG_RTN_MAX		0xFFu

/*
 * Core 6.3 Vol 4 Part E Sec 7.8.103, RTN table (.txt line 122174):
 * "0x00 to 0x1E ... All other values Reserved for future use".
 */
#define SPEC_EXTREF_ISO_BIG_RTN_MIN		0x00u
#define SPEC_EXTREF_ISO_BIG_RTN_MAX		0x1Eu

/* Zephyr's names for the same two bounds; see citation above. */
#define SPEC_EXTREF_ZEPHYR_CONNECTED_RTN_MAX	0xFFu
#define SPEC_EXTREF_ZEPHYR_BROADCAST_RTN_MAX	0x1Eu

/*
 * The rest of the Sec 7.8.97 command-parameter ranges, transcribed from the
 * same tables, so a validator can be checked field by field against one
 * external source rather than against itself.
 */
#define SPEC_EXTREF_ISO_CIG_ID_MAX		0xEFu	/* 0x00-0xEF   */
#define SPEC_EXTREF_ISO_SDU_INTERVAL_MIN	0x0000FFu
#define SPEC_EXTREF_ISO_SDU_INTERVAL_MAX	0x0FFFFFu
#define SPEC_EXTREF_ISO_WORST_CASE_SCA_MAX	0x07u
#define SPEC_EXTREF_ISO_PACKING_MAX		0x01u	/* 0 seq, 1 intlv */
#define SPEC_EXTREF_ISO_FRAMING_MAX		0x02u	/* 0,1,2          */
#define SPEC_EXTREF_ISO_MAX_TRANSPORT_LAT_MIN	0x0005u
#define SPEC_EXTREF_ISO_MAX_TRANSPORT_LAT_MAX	0x0FA0u
#define SPEC_EXTREF_ISO_CIS_COUNT_MAX		0x1Fu	/* .txt line 121174 */
#define SPEC_EXTREF_ISO_CIS_ID_MAX		0xEFu
#define SPEC_EXTREF_ISO_MAX_SDU_MAX		0x0FFFu
#define SPEC_EXTREF_ISO_PHY_MASK_VALID		0x07u	/* bits 0..2 only */

/* Sec 7.8.103 LE Create BIG, remaining ranges. */
#define SPEC_EXTREF_ISO_BIG_HANDLE_MAX		0xEFu
#define SPEC_EXTREF_ISO_ADV_HANDLE_MAX		0xEFu
#define SPEC_EXTREF_ISO_NUM_BIS_MIN		0x01u
#define SPEC_EXTREF_ISO_NUM_BIS_MAX		0x1Fu
#define SPEC_EXTREF_ISO_BIG_MAX_SDU_MIN		0x0001u
#define SPEC_EXTREF_ISO_BIG_MAX_SDU_MAX		0x0FFFu

/* Sec 7.8.106 LE BIG Create Sync. */
#define SPEC_EXTREF_ISO_MSE_ANY			0x00u
#define SPEC_EXTREF_ISO_MSE_MIN			0x01u
#define SPEC_EXTREF_ISO_MSE_MAX			0x1Fu
#define SPEC_EXTREF_ISO_BIG_SYNC_TIMEOUT_MIN	0x000Au
#define SPEC_EXTREF_ISO_BIG_SYNC_TIMEOUT_MAX	0x4000u
#define SPEC_EXTREF_ISO_BIS_INDEX_MIN		0x01u
#define SPEC_EXTREF_ISO_BIS_INDEX_MAX		0x1Fu

/*
 * Core 6.3 Vol 4 Part E Sec 7.8.106 (.txt lines 122627-122629), verbatim:
 *   "The BIS arrayed parameter is a list of BIS_Numbers corresponding to
 *    BIS(es) in the synchronized BIG. The list of BIS_Numbers shall be in
 *    ascending order and shall not contain any duplicates."
 * A host that enforces strictly ascending BIS indices is following a "shall",
 * not being gratuitously strict.
 */
#define SPEC_EXTREF_ISO_BIS_LIST_STRICTLY_ASCENDING	1

/* Sec 7.8.109 LE Setup ISO Data Path. */
#define SPEC_EXTREF_ISO_CONN_HANDLE_MAX		0x0EFFu
#define SPEC_EXTREF_ISO_DATA_PATH_DIR_INPUT	0x00u
#define SPEC_EXTREF_ISO_DATA_PATH_DIR_OUTPUT	0x01u
#define SPEC_EXTREF_ISO_DATA_PATH_ID_HCI	0x00u
#define SPEC_EXTREF_ISO_DATA_PATH_ID_RFU	0xFFu
#define SPEC_EXTREF_ISO_CONTROLLER_DELAY_MAX	0x3D0900u	/* 4 s */

/*
 * Core 6.3 Vol 4 Part E Sec 7.8.109 error table (.txt line 122970), verbatim:
 *   "Connection_Handle identifies a unidirectional CIS and Data_Path_Direction
 *    is the direction where BN is set to 0.   -> Command Disallowed (0x0C)"
 * i.e. blindly setting up both directions on a unidirectional CIS is expected
 * to fail one of the two commands; that is a controller-side rejection, not a
 * host error, but a host that does not track directionality cannot tell the
 * expected failure from a real one.
 */
#define SPEC_EXTREF_ISO_SETUP_PATH_UNIDIR_ERR	0x0Cu

/*
 * Core 6.3 Vol 4 Part E Sec 7.7.65.26 (LE CIS Request event, .txt line
 * 107811), verbatim:
 *   "When the Host receives this event it shall respond with either an
 *    HCI_LE_Accept_CIS_Request command or an HCI_LE_Reject_CIS_Request
 *    command before the timer Connection_Accept_Timeout expires. If it does
 *    not, the Controller shall reject the request and generate an
 *    HCI_LE_CIS_Established event with the status Connection Accept Timeout
 *    Exceeded (0x10)."
 * A host that tracks pending CIS requests must therefore accept an
 * LE_CIS_Established carrying 0x10 for a CIS it never accepted, and release
 * the pending state on it.
 */
#define SPEC_EXTREF_ISO_CONN_ACCEPT_TIMEOUT_ERR	0x10u

#endif /* SPEC_EXTREF_ISO_CIG_RTN_H */

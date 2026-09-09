/*
 * EXTERNAL REFERENCE ORACLE: Advertising_Event_Properties -- the legal
 * connectable / scannable / directed combinations, and the restrictions the
 * specification places on each.
 *
 * Hand-transcribed from the named external sources below.  Every constant and
 * every quoted sentence is traceable to one of them; nothing here was derived
 * from blued and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * Advertising_Event_Properties is a 16-bit field in which most bit patterns
 * are illegal, and the illegality is stated in three separate places: a table
 * of five permitted values for legacy PDUs, a prose sentence naming two
 * prohibited bit combinations for extended PDUs, and a scattering of "shall
 * be ignored" / "not allowed" clauses attached to individual parameters.  A
 * host that validates only the bit width, or only one of the three, emits
 * commands the controller rejects with an opaque status.
 *
 * The single most-missed rule is the one in the middle: an EXTENDED (non-
 * legacy) advertisement may not be both connectable and scannable.  It has no
 * legacy analogue -- ADV_IND is exactly that combination -- so code written
 * against the legacy model and then extended tends to carry the combination
 * forward.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   Vol 4 Part E Section 7.8.53 (LE Set Extended Advertising Parameters),
 *     including Table 7.3, at text lines 116205-116300
 *   Vol 4 Part E Section 7.8.5 (LE Set Advertising Parameters), text lines
 *     112126-112250
 *   Vol 4 Part E Section 7.8.54 (LE Set Extended Advertising Data),
 *     text lines 116650-116730
 *   Vol 4 Part E Section 7.8.56 (LE Set Extended Advertising Enable),
 *     text lines 116920-117110
 *   Vol 4 Part E Section 3.1.1 (legacy/extended command mixing), text line
 *     86407
 *   Vol 6 Part B Section 4.4.2.2.1 (advInterval range), text line 137329
 */

#ifndef SPEC_EXTREF_GAP_ADV_PROPS_H
#define SPEC_EXTREF_GAP_ADV_PROPS_H

#include <stdint.h>

/*
 * =========================================================================
 * Advertising_Event_Properties bit assignments, Section 7.8.53.
 * =========================================================================
 */
#define SPEC_ADV_PROP_CONNECTABLE		0x0001	/* bit 0 */
#define SPEC_ADV_PROP_SCANNABLE			0x0002	/* bit 1 */
#define SPEC_ADV_PROP_DIRECTED			0x0004	/* bit 2 */
#define SPEC_ADV_PROP_HIGH_DUTY_DIRECTED	0x0008	/* bit 3 */
#define SPEC_ADV_PROP_LEGACY			0x0010	/* bit 4 */
#define SPEC_ADV_PROP_ANONYMOUS			0x0020	/* bit 5 */
#define SPEC_ADV_PROP_INCLUDE_TX_POWER		0x0040	/* bit 6 */
/* Bits 7..15 are reserved for future use in the 5.2 target. */
#define SPEC_ADV_PROP_DEFINED_MASK		0x007F

/*
 * =========================================================================
 * Table 7.3: Advertising_Event_Properties values for legacy PDUs.
 *
 * Section 7.8.53, text lines 116211-116215, verbatim:
 *   "If legacy advertising PDU types are being used, then the parameter value
 *    shall be one of those specified in Table 7.3.  If the advertising set
 *    already contains data, the type shall be one that supports advertising
 *    data and the amount of data shall not exceed 31 octets."
 *
 * Table 7.3 itself, text lines 116217-116226.  Note the third column: two of
 * the five rows say advertising data is "Not allowed", not merely unused.
 * =========================================================================
 */

/* ADV_IND -- connectable and scannable undirected.  Advertising data: Supported. */
#define SPEC_ADV_LEGACY_ADV_IND			0x0013
/* ADV_DIRECT_IND low duty cycle.  Advertising data: NOT ALLOWED. */
#define SPEC_ADV_LEGACY_ADV_DIRECT_IND_LOW	0x0015
/* ADV_DIRECT_IND high duty cycle.  Advertising data: NOT ALLOWED. */
#define SPEC_ADV_LEGACY_ADV_DIRECT_IND_HIGH	0x001D
/* ADV_SCAN_IND -- scannable undirected.  Advertising data: Supported. */
#define SPEC_ADV_LEGACY_ADV_SCAN_IND		0x0012
/* ADV_NONCONN_IND -- non-connectable and non-scannable undirected.  Supported. */
#define SPEC_ADV_LEGACY_ADV_NONCONN_IND		0x0010

/*
 * The complete permitted set, in Table 7.3 order.  Any other value with bit 4
 * set is illegal; there are exactly five.
 */
static const uint16_t bt_extref_gap_adv_legacy_props[5] = {
	SPEC_ADV_LEGACY_ADV_IND,
	SPEC_ADV_LEGACY_ADV_DIRECT_IND_LOW,
	SPEC_ADV_LEGACY_ADV_DIRECT_IND_HIGH,
	SPEC_ADV_LEGACY_ADV_SCAN_IND,
	SPEC_ADV_LEGACY_ADV_NONCONN_IND,
};

/* Whether each of the five permits advertising data, in the same order. */
static const uint8_t bt_extref_gap_adv_legacy_data_allowed[5] = {
	1,	/* ADV_IND               Supported   */
	0,	/* ADV_DIRECT_IND low    Not allowed */
	0,	/* ADV_DIRECT_IND high   Not allowed */
	1,	/* ADV_SCAN_IND          Supported   */
	1,	/* ADV_NONCONN_IND       Supported   */
};

/*
 * The corresponding LEGACY (Section 7.8.5) Advertising_Type values, so the
 * two encodings can be checked against one another.  Section 7.8.5's
 * Advertising_Type parameter is a small enumeration, not a bit field.
 */
#define SPEC_ADV_TYPE_ADV_IND			0x00
#define SPEC_ADV_TYPE_ADV_DIRECT_IND_HIGH	0x01
#define SPEC_ADV_TYPE_ADV_SCAN_IND		0x02
#define SPEC_ADV_TYPE_ADV_NONCONN_IND		0x03
#define SPEC_ADV_TYPE_ADV_DIRECT_IND_LOW	0x04
#define SPEC_ADV_TYPE_MAX			0x04

/*
 * =========================================================================
 * Restrictions on EXTENDED (non-legacy) advertising PDUs.
 *
 * Section 7.8.53, text lines 116228-116231, verbatim:
 *   "If extended advertising PDU types are being used (bit 4 = 0), then the
 *    advertisement shall not be both connectable and scannable (bits 0 and 1
 *    must not both be set to 1) and high duty cycle directed connectable
 *    advertising (<= 3.75 ms advertising interval) shall not be used
 *    (bit 3 = 0)."
 *
 * TWO prohibitions in one sentence.  A validator that implements only the
 * bit-3 half -- the easier one to notice, because it is named last -- passes
 * 0x0003 straight to the controller.
 * =========================================================================
 */

/* Returns non-zero if props violates either extended-PDU prohibition. */
#define SPEC_ADV_EXT_PROPS_ILLEGAL(props)				\
	(!((props) & SPEC_ADV_PROP_LEGACY) &&				\
	 ((((props) & (SPEC_ADV_PROP_CONNECTABLE |			\
		       SPEC_ADV_PROP_SCANNABLE)) ==			\
	   (SPEC_ADV_PROP_CONNECTABLE | SPEC_ADV_PROP_SCANNABLE)) ||	\
	  (((props) & SPEC_ADV_PROP_HIGH_DUTY_DIRECTED) != 0)))

/*
 * Further per-parameter clauses from the same section, verbatim, each with
 * its text line:
 *
 *   116234: "The parameters beginning with 'Secondary' are only valid when
 *            extended advertising PDU types are being used (bit 4 = 0)."
 *   116237: "The Own_Address_Type parameter shall be ignored for undirected
 *            anonymous advertising (bit 2 = 0 and bit 5 = 1)."
 *   116240: "If Directed advertising is selected, the Peer_Address_Type and
 *            Peer_Address shall be valid and the Advertising_Filter_Policy
 *            parameter shall be ignored."
 *   116255: "For high duty cycle connectable directed advertising event type
 *            (ADV_DIRECT_IND), the Primary_Advertising_Interval_Min and
 *            Primary_Advertising_Interval_Max parameters are not used and
 *            shall be ignored."
 *   116268: "If legacy advertising PDUs are being used, the
 *            Primary_Advertising_PHY shall indicate the LE 1M PHY."
 *   116262: "At least one channel bit shall be set in the
 *            Primary_Advertising_Channel_Map parameter."
 *
 * And the rule that ties advertising to privacy, text lines 116265-116269:
 *   "If Own_Address_Type equals 0x02 or 0x03, the Peer_Address parameter
 *    contains the peer's Identity Address and the Peer_Address_Type parameter
 *    contains the peer's Identity Type (i.e., 0x00 or 0x01). These parameters
 *    are used to locate the corresponding local IRK in the resolving list;
 *    this IRK is used to generate their own address used in the
 *    advertisement."
 * -- note the consequence: under 0x02/0x03 the Peer_Address fields are load
 * bearing even for an UNDIRECTED advertisement, because they select which
 * resolving-list entry supplies the local IRK.
 * =========================================================================
 */

/*
 * =========================================================================
 * Intervals.
 *
 * Legacy, Section 7.8.5, Advertising_Interval_Min/Max tables at text lines
 * 112200-112217: "Range: 0x0020 to 0x4000", "Default: 0x0800",
 * Time = N * 0.625 ms, i.e. 20 ms to 10.24 s.
 *
 * Extended, Section 7.8.53, text lines 116394-116398:
 * Primary_Advertising_Interval_Min/Max are THREE octets,
 * "Range: 0x000020 to 0xFFFFFF", Time = N * 0.625 ms.
 *
 * Link layer, Vol 6 Part B Section 4.4.2.2.1, text line 137329, verbatim:
 *   "The advertising interval (advInterval) shall be an integer multiple of
 *    0.625 ms in the range 20 ms to 10,485.759375 s."
 *
 * There is NO advertising-type-dependent interval floor in the 5.2 target.
 * The Bluetooth 4.0-4.2 rule that a non-connectable or scannable undirected
 * advertisement must use at least 0x00A0 (100 ms) was removed in 5.0.  What
 * survives is a soft recommendation in GAP, Vol 3 Part C, text lines
 * 65888-65892, verbatim:
 *   "When advertising interval values of less than 100 ms are used for non-
 *    connectable or scannable undirected advertising in environments where
 *    the advertiser can interfere with other devices, steps should be taken
 *    to minimize the interference. For example, the advertising might be
 *    alternately enabled for only a few seconds and disabled for several
 *    minutes."
 *
 * Also a "should" rather than a "shall", Section 7.8.53 text lines
 * 116250-116252 and Section 7.8.5 text lines 112144-112146, verbatim:
 *   "The Primary_Advertising_Interval_Min and Primary_Advertising_Interval_-
 *    Max parameters should not be the same value so that the Controller can
 *    choose the best advertising interval given other activities."
 * =========================================================================
 */
#define SPEC_ADV_INTERVAL_LEGACY_MIN		0x0020		/* 20 ms */
#define SPEC_ADV_INTERVAL_LEGACY_MAX		0x4000		/* 10.24 s */
#define SPEC_ADV_INTERVAL_LEGACY_DEFAULT	0x0800
#define SPEC_ADV_INTERVAL_EXT_MIN		0x000020
#define SPEC_ADV_INTERVAL_EXT_MAX		0xFFFFFF
/* Advertising channel map: bits 0..2 = channels 37, 38, 39. */
#define SPEC_ADV_CHANNEL_MAP_DEFAULT		0x07
#define SPEC_ADV_CHANNEL_MAP_MASK		0x07

/* Advertising_Handle range, Section 7.8.53, text lines 116382-116385. */
#define SPEC_ADV_HANDLE_MIN			0x00
#define SPEC_ADV_HANDLE_MAX			0xEF

/*
 * =========================================================================
 * Advertising data length limits, Section 7.8.54.
 *
 * Advertising_Data_Length parameter table, text lines 116713-116714,
 * verbatim: "0 to 251 -- The number of octets in the Advertising Data
 * parameter".  251 is the SPEC maximum per HCI fragment, not a conservative
 * host choice; there is no larger value in this section.
 *
 * Operation values, text lines 116718-116724:
 *   0x00 Intermediate fragment    0x01 First fragment
 *   0x02 Last fragment            0x03 Complete data (unfragmented)
 *   0x04 Unchanged data (update DID only)
 *
 * Error condition, text lines 116659-116661, verbatim:
 *   "The advertising set uses legacy advertising PDUs that support
 *    advertising data and either Operation is not 0x03 or
 *    Advertising_Data_Length exceeds 31 octets."
 *    -> Invalid HCI Command Parameters (0x12)
 * -- so a LEGACY-props set may only ever be programmed with a single
 * unfragmented write of at most 31 octets, whichever command family is used.
 *
 * The legacy commands (7.8.7 / 7.8.8) take a fixed 31-octet buffer.
 * =========================================================================
 */
#define SPEC_ADV_DATA_LEGACY_MAX		31
#define SPEC_ADV_DATA_EXT_FRAGMENT_MAX		251
#define SPEC_ADV_DATA_OP_INTERMEDIATE_FRAGMENT	0x00
#define SPEC_ADV_DATA_OP_FIRST_FRAGMENT		0x01
#define SPEC_ADV_DATA_OP_LAST_FRAGMENT		0x02
#define SPEC_ADV_DATA_OP_COMPLETE		0x03
#define SPEC_ADV_DATA_OP_UNCHANGED		0x04

/*
 * =========================================================================
 * LE Set Extended Advertising Enable, Section 7.8.56.
 *
 * Duration[i] parameter, text lines 117040-117044:
 *   0x0000        = No advertising duration.  Advertise until the Host
 *                   disables advertising.
 *   0x0001-0xFFFF = Range 10 ms to 655.35 s, Time = N * 10 ms
 *
 * Max_Extended_Advertising_Events[i], text lines 117048-117050:
 *   0x00          = "No maximum number of advertising events"
 *   0x01-0xFF     = Maximum number of extended advertising events the
 *                   Controller shall attempt to send prior to terminating the
 *                   extended advertising
 *
 * -- 0x00 is the CORRECT and only value for indefinite advertising in BOTH
 * fields.  A host-side validator that rejects a zero Max_Extended_-
 * Advertising_Events rejects the normal case.
 *
 * Text line 116933, verbatim:
 *   "If the advertising is high duty cycle connectable directed advertising,
 *    then Duration[i] shall be less than or equal to 1.28 seconds and shall
 *    not be equal to 0."
 * -- 1.28 s in 10 ms units is 128.
 *
 * Error condition, text lines 116979-116980, verbatim:
 *   "The advertising set uses scannable extended advertising PDUs and there
 *    is no scan response data."  -> Command Disallowed (0x0C)
 * =========================================================================
 */
#define SPEC_ADV_ENABLE_DURATION_INDEFINITE		0x0000
#define SPEC_ADV_ENABLE_MAX_EVENTS_UNLIMITED		0x00
/* 1.28 s expressed in the Duration field's 10 ms units. */
#define SPEC_ADV_ENABLE_HIGH_DUTY_DIRECTED_DURATION_MAX	128

/*
 * =========================================================================
 * Legacy and extended advertising commands may not be mixed.
 *
 * Vol 4 Part E Section 3.1.1, text lines 86407-86410, verbatim:
 *   "If, since the last power-on or reset, the Host has ever issued a legacy
 *    advertising command and then issues an extended advertising command, or
 *    has ever issued an extended advertising command and then issues a legacy
 *    advertising command, the Controller shall return the error code Command
 *    Disallowed (0x0C)."
 *
 * And text line 86412, verbatim:
 *   "A Host should not issue legacy commands to a Controller that supports
 *    the LE Feature (Extended Advertising)."
 *
 * The practical consequence, which is what catches hosts out: a "try extended,
 * fall back to legacy" sequence is guaranteed to fail on any controller that
 * accepted the first extended command.  The choice of command family must be
 * made ONCE, from the LE feature bits, before the first advertising command
 * of any kind is issued.
 * =========================================================================
 */
/* LE Feature bit 12: LE Extended Advertising (Vol 6 Part B Section 4.6). */
#define SPEC_LE_FEAT_BIT_EXTENDED_ADVERTISING	12

#endif /* SPEC_EXTREF_GAP_ADV_PROPS_H */

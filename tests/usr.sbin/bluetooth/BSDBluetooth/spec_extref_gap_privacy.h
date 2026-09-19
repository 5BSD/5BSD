/*
 * EXTERNAL REFERENCE ORACLE: LE privacy and addressing -- address types, the
 * resolvable private address format, the resolving list, privacy modes, and
 * the conditions under which the governing HCI commands are disallowed.
 *
 * Hand-transcribed from the named external sources below.  Every constant and
 * every quoted sentence is traceable to one of them; nothing here was derived
 * from blued and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * This stack has already produced two defects from address-type confusion.
 * The trap is that four different one-octet enumerations, all called some
 * variant of "address type", carry four different value sets:
 *
 *   (a) Own_Address_Type          0x00..0x03  -- a REQUEST for a behaviour
 *   (b) Peer_Identity_Address_Type 0x00..0x01 -- only public / static random
 *   (c) Peer_Address_Type in events 0x00..0x03 -- a REPORT of what was used
 *   (d) Direct_Address_Type        0x00..0x03, 0xFE -- (c) plus "unresolved"
 *
 * A host that reuses one validator, or one mapping function, across these is
 * wrong somewhere.  Note in particular that 0x02/0x03 mean "controller
 * generates an RPA" in (a) but "this IS an identity address, resolved from an
 * RPA" in (c) and (d) -- opposite senses of the same two values.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   Vol 3 Part C Section 10.7 and 10.8 (GAP privacy feature)
 *   Vol 6 Part B Section 1.3.2 (link-layer private address formats)
 *   Vol 4 Part E Sections 7.8.4, 7.8.15-7.8.17, 7.8.38, 7.8.44, 7.8.45,
 *     7.8.53, 7.8.77, and 7.7.65.13 (LE Extended Advertising Report)
 * The line numbers cited are lines in that text file.
 */

#ifndef SPEC_EXTREF_GAP_PRIVACY_H
#define SPEC_EXTREF_GAP_PRIVACY_H

#include <stdint.h>

/*
 * =========================================================================
 * (a) Own_Address_Type -- a request, in a command, for a behaviour.
 *
 * Vol 4 Part E Section 7.8.53 (LE Set Extended Advertising Parameters),
 * Own_Address_Type table at text lines 116437-116455, verbatim:
 *   0x00  Public Device Address
 *   0x01  Random Device Address
 *   0x02  "Controller generates the Resolvable Private Address based on the
 *          local IRK from the resolving list. If the resolving list contains
 *          no matching entry, use the public address."
 *   0x03  "Controller generates the Resolvable Private Address based on the
 *          local IRK from the resolving list. If the resolving list contains
 *          no matching entry, use the random address from
 *          LE_Set_Advertising_Set_Random_Address."
 *
 * Two consequences worth stating explicitly, because they are easy to get
 * wrong and neither is stated as a separate rule anywhere:
 *
 *   1. Under 0x02 the fallback for a peer that is NOT in the resolving list
 *      is the PUBLIC identity address.  A privacy-enabled host that selects
 *      0x02 and then fails to program a peer's entry leaks its identity
 *      address to that peer.  0x03's fallback is a random address the host
 *      controls, so 0x03 fails closed and 0x02 fails open.
 *   2. Under 0x02/0x03 the address on air is chosen by the CONTROLLER, per
 *      resolving-list entry.  The host cannot know which address was used
 *      until the controller reports it (see Local_RPA below), and a zero
 *      Local_RPA under 0x03 does not identify the fallback address.
 * =========================================================================
 */
#define SPEC_OWN_ADDR_TYPE_PUBLIC			0x00
#define SPEC_OWN_ADDR_TYPE_RANDOM			0x01
#define SPEC_OWN_ADDR_TYPE_RPA_FALLBACK_PUBLIC		0x02
#define SPEC_OWN_ADDR_TYPE_RPA_FALLBACK_RANDOM		0x03
#define SPEC_OWN_ADDR_TYPE_MAX				0x03

/*
 * =========================================================================
 * (b) Peer_Identity_Address_Type -- resolving list and privacy mode only.
 *
 * Vol 4 Part E Section 7.8.77 (LE Set Privacy Mode), text lines 119272-119276,
 * and Section 7.8.38 (LE Add Device To Resolving List):
 *   0x00  Public Identity Address
 *   0x01  Random (static) Identity Address
 *   All other values: Reserved for future use.
 *
 * Section 7.8.38 additionally states this error condition, text line 115152:
 *   RC: "Peer_Identity_Address_Type is 0x01 and Peer_Identity_Address is a
 *        non-static address."  -> Invalid HCI Command Parameters (0x12)
 *
 * That is: the controller will REJECT an add whose random identity address is
 * not a static random address.  A host that stores an on-air RPA as a peer's
 * identity (which happens when pairing completed without identity
 * distribution) will get 0x12 back, not silence.  A static random address is
 * one whose two most significant bits are both 1 (Vol 6 Part B Section 1.3.2.1).
 * =========================================================================
 */
#define SPEC_PEER_IDENTITY_ADDR_TYPE_PUBLIC		0x00
#define SPEC_PEER_IDENTITY_ADDR_TYPE_RANDOM_STATIC	0x01
#define SPEC_PEER_IDENTITY_ADDR_TYPE_MAX		0x01

/* Error code returned for a non-static random identity address. */
#define SPEC_ERR_INVALID_HCI_COMMAND_PARAMETERS		0x12
/* Error code returned when the resolving list has no room (7.8.38). */
#define SPEC_ERR_MEMORY_CAPACITY_EXCEEDED		0x07
/* Error code for LE Set Privacy Mode on a peer not in the list (7.8.77). */
#define SPEC_ERR_UNKNOWN_CONNECTION_IDENTIFIER		0x02
/* Error code for a command issued in a disallowed state. */
#define SPEC_ERR_COMMAND_DISALLOWED			0x0C

/*
 * =========================================================================
 * (c) Peer_Address_Type in events -- a report of what was actually used.
 *
 * Vol 4 Part E, LE Enhanced Connection Complete and the advertising reports,
 * text lines 105156, 105755, 105912, 106179 (the same table appears at each):
 *   0x00  Public Device Address
 *   0x01  Random Device Address
 *   0x02  "Public Identity Address (Corresponds to a resolved RPA)"
 *   0x03  "Random (static) Identity Address (Corresponds to a resolved RPA)"
 *
 * So bit 0 alone distinguishes the underlying identity type, in both the
 * resolved and unresolved cases: (type & 0x01) selects random vs public and
 * is correct for all four values.  Testing (type == 0x01) alone is the bug.
 * =========================================================================
 */
#define SPEC_EVT_ADDR_TYPE_PUBLIC			0x00
#define SPEC_EVT_ADDR_TYPE_RANDOM			0x01
#define SPEC_EVT_ADDR_TYPE_PUBLIC_IDENTITY		0x02
#define SPEC_EVT_ADDR_TYPE_RANDOM_IDENTITY		0x03
/* Anonymous advertiser, LE Extended Advertising Report only. */
#define SPEC_EVT_ADDR_TYPE_ANONYMOUS			0xFF

/*
 * =========================================================================
 * (d) Direct_Address_Type -- (c) plus one extra value.
 *
 * Vol 4 Part E, LE Extended Advertising Report, text lines 106271-106281,
 * verbatim:
 *   0x00  Public Device Address
 *   0x01  Non-resolvable Private Address or Static Device Address
 *   0x02  Resolvable Private Address (resolved by Controller; Own_Address_Type
 *         was 0x00 or 0x02)
 *   0x03  Resolvable Private Address (resolved by Controller; Own_Address_Type
 *         was 0x01 or 0x03)
 *   0xFE  Resolvable Private Address (Controller unable to resolve)
 *
 * 0xFE is the value that matters for interoperability.  It appears when a
 * bonded peer sends DIRECTED advertising at us using an RPA as TargetA that
 * our controller could not resolve.  The controller only reports it at all if
 * the scanning filter policy is 0x02 or 0x03; under policy 0x00 or 0x01 the
 * report is suppressed entirely and the reconnection attempt is invisible to
 * the host.  A host that caps its scanning filter policy at 0x01 therefore
 * cannot see directed reconnects it failed to resolve.
 * =========================================================================
 */
#define SPEC_DIRECT_ADDR_TYPE_PUBLIC			0x00
#define SPEC_DIRECT_ADDR_TYPE_RANDOM			0x01
#define SPEC_DIRECT_ADDR_TYPE_RPA_RESOLVED_PUBLIC	0x02
#define SPEC_DIRECT_ADDR_TYPE_RPA_RESOLVED_RANDOM	0x03
#define SPEC_DIRECT_ADDR_TYPE_RPA_UNRESOLVED		0xFE

/*
 * Scanning filter policy, Vol 4 Part E Section 7.8.10 / 7.8.64.  Policies
 * 0x02 and 0x03 are the "extended" ones: they add, to policies 0x00 and 0x01
 * respectively, directed advertising PDUs whose TargetA is an RPA the
 * controller could not resolve.
 */
#define SPEC_SCAN_FILTER_POLICY_ALL			0x00
#define SPEC_SCAN_FILTER_POLICY_ACCEPT_LIST		0x01
#define SPEC_SCAN_FILTER_POLICY_ALL_PLUS_UNRES_DIRECTED	0x02
#define SPEC_SCAN_FILTER_POLICY_ACCEPT_PLUS_UNRES_DIRECTED 0x03
#define SPEC_SCAN_FILTER_POLICY_MAX			0x03

/*
 * =========================================================================
 * Resolvable private address format.
 *
 * Vol 6 Part B Section 1.3.2.2, text lines 131830-131838, verbatim:
 *   "The prand and hash are concatenated to generate the random address in
 *    the following manner:
 *        randomAddress = prand || hash
 *    The least significant octet of hash becomes the least significant octet
 *    of randomAddress and the most significant octet of prand becomes the
 *    most significant octet of randomAddress."
 *
 * In a little-endian six-octet address array a[0..5], where a[0] is the least
 * significant octet:
 *        a[0..2] = hash        a[3..5] = prand
 * The two most significant bits of a[5] are the address-type marker and are
 * NOT part of the 22-bit random part.
 *
 * Text lines 131810-131811, verbatim:
 *   "At least one bit of the random part of prand shall be 0"
 *   "At least one bit of the random part of prand shall be 1"
 * -- i.e. the 22 random bits may be neither all-zero nor all-one.  The same
 * pair of requirements applies to a non-resolvable private address over its
 * own random part (text lines 131793-131794), together with the additional
 * requirement that it "shall not be equal to the public address".
 * =========================================================================
 */
#define SPEC_RPA_HASH_OFFSET			0	/* a[0..2] */
#define SPEC_RPA_HASH_LEN			3
#define SPEC_RPA_PRAND_OFFSET			3	/* a[3..5] */
#define SPEC_RPA_PRAND_LEN			3

/* Random address type markers: the two most significant bits of a[5]. */
#define SPEC_RANDOM_ADDR_TYPE_MASK		0xC0
#define SPEC_RANDOM_ADDR_NON_RESOLVABLE		0x00
#define SPEC_RANDOM_ADDR_RESOLVABLE		0x40
/* 0x80 is reserved for future use. */
#define SPEC_RANDOM_ADDR_STATIC			0xC0
/* The 22 random bits of prand live below the marker in a[5]. */
#define SPEC_RPA_PRAND_RANDOM_MASK_MSO		0x3F

/*
 * =========================================================================
 * Privacy modes.
 *
 * Vol 3 Part C Section 10.7, text lines 67018-67024, verbatim:
 *   "Device Privacy Mode: When a device is in device privacy mode, it is only
 *    concerned about its own privacy. It should accept advertising packets
 *    from peer devices that contain their Identity Addresses as well as their
 *    private address, even if the peer device has distributed its IRK."
 *   "Network Privacy Mode. When a device is in network privacy mode, it shall
 *    not accept advertising packets containing the Identity Address of peer
 *    devices that have distributed their IRK."
 *
 * Vol 4 Part E Section 7.8.38, text line 115140, verbatim:
 *   "The added device shall be set to Network Privacy mode."
 * -- so an entry is Network Privacy until LE Set Privacy Mode says otherwise,
 * and LE Set Privacy Mode is a BT 5.0 command that a 4.2 controller rejects
 * with Unknown HCI Command (0x01).
 *
 * Vol 3 Part C Section 10.7, text lines 67057-67061, verbatim:
 *   "To select device privacy mode, the Host shall so instruct the Controller
 *    for each peer in the resolving list."
 *   "If the Host requires network privacy mode, then it shall only populate
 *    entries in the Controller's resolving list that have non-zero IRKs and
 *    shall not instruct the Controller to use device privacy mode."
 *
 * And text lines 67050-67052, verbatim:
 *   "A device identity consists of the peer's Identity Address and a local
 *    and peer's IRK pair. The local or peer's IRK shall be an all-zero key if
 *    not applicable for the particular device identity."
 * -- an all-zero PEER IRK is an explicitly contemplated resolving-list entry,
 * not an error.  It is how a host asks the controller to generate a LOCAL RPA
 * toward a peer that never distributed an IRK of its own.  It is only barred
 * when the host requires network privacy mode for that peer.
 * =========================================================================
 */
#define SPEC_PRIVACY_MODE_NETWORK		0x00	/* the default */
#define SPEC_PRIVACY_MODE_DEVICE		0x01
#define SPEC_PRIVACY_MODE_MAX			0x01
/* Unknown HCI Command: what a pre-5.0 controller returns for 7.8.77. */
#define SPEC_ERR_UNKNOWN_HCI_COMMAND		0x01

/*
 * =========================================================================
 * RPA timeout, Vol 4 Part E Section 7.8.45, text lines 115640-115646.
 *   Range: 0x0001 to 0x0E10 seconds (1 s to 1 hour).
 * Text line 115630, verbatim:
 *   "If the Controller supports version [v2] of this command, then the default
 *    behavior shall be to use the range 8 to 15 minutes. Otherwise the default
 *    timeout shall be 15 minutes."
 *
 * The GAP-side bound on the same quantity is in spec_extref_gap_timers.h:
 * TGAP(private_addr_int), recommended 15 min, "shall not be greater than
 * 1 hour" (Vol 3 Part C, text line 67197).  The HCI maximum and the GAP
 * maximum coincide at one hour; the 15-minute figure is a recommendation on
 * one side and a controller default on the other, not a requirement on either.
 * =========================================================================
 */
#define SPEC_RPA_TIMEOUT_SEC_MIN		0x0001
#define SPEC_RPA_TIMEOUT_SEC_MAX		0x0E10	/* 3600 */
#define SPEC_RPA_TIMEOUT_SEC_CONTROLLER_DEFAULT	900	/* 15 minutes */

/*
 * =========================================================================
 * When the privacy-related commands are DISALLOWED.
 *
 * These four condition sets are subtly different from one another.  A host
 * that quiesces for one and reuses the same quiesce for another will be
 * wrong.  All quotes verbatim.
 *
 * 1. LE Set Random Address (7.8.4), text lines 112088-112090:
 *      MC "Any of advertising (created using legacy advertising commands),
 *          scanning, or creating a connection are enabled in the Controller."
 *          -> Command Disallowed (0x0C)
 *    Note the parenthesis: EXTENDED advertising being enabled does NOT block
 *    this command, because (text lines 112078-112080) "If the extended
 *    advertising commands are in use, this command only affects the address
 *    used for scanning and initiating.  The addresses used for advertising
 *    are set by the HCI_LE_Set_Advertising_Set_Random_Address command".
 *    Scanning of ANY kind blocks it -- there is no exemption for a passive
 *    scan, a mesh scan, or a scan the host considers "background".
 *
 * 2. LE Clear / Add To / Remove From Filter Accept List (7.8.15/16/17),
 *    text lines 113172-113177 (identical text in all three), verbatim:
 *      "This command shall not be used when:
 *       - any advertising filter policy uses the Filter Accept List and
 *         advertising is enabled,
 *       - the scanning filter policy uses the Filter Accept List and scanning
 *         is enabled, or
 *       - the initiator filter policy uses the Filter Accept List and an
 *         HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection
 *         command is pending."
 *    This one is CONDITIONAL on a policy that actually uses the list.  A host
 *    that advertises with filter policy 0x00 may edit the accept list freely;
 *    a host that advertises with 0x01, 0x02 or 0x03 may not.
 *
 * 3. LE Add To / Remove From Resolving List (7.8.38/7.8.39), text lines
 *    115128-115136, verbatim:
 *      "This command shall not be used when address resolution is enabled in
 *       the Controller and:
 *       - Advertising (other than periodic advertising) is enabled,
 *       - Scanning is enabled, or
 *       - an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
 *         HCI_LE_Periodic_Advertising_Create_Sync command is pending.
 *       This command may be used at any time when address resolution is
 *       disabled in the Controller."
 *    Conditional on address resolution being ENABLED.  Turning resolution off
 *    first removes the need to quiesce anything.
 *
 * 4. LE Set Address Resolution Enable (7.8.44), text lines 115540-115545,
 *    verbatim:
 *      "This command shall not be used when:
 *       - Advertising (other than periodic advertising) is enabled,
 *       - Scanning is enabled, or
 *       - an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
 *         HCI_LE_Periodic_Advertising_Create_Sync command is pending."
 *    UNCONDITIONAL.  This is the one that cannot be dodged: the command used
 *    to escape condition (3) is itself the most restricted of the four.  Any
 *    resolving-list edit therefore needs a full advertising + scanning +
 *    initiating quiesce around the enable/disable pair regardless.
 * =========================================================================
 */

/* Bit flags naming what each command requires be quiesced.  Provided so a
 * test can express the four condition sets as data rather than as prose. */
#define SPEC_QUIESCE_LEGACY_ADV		0x01
#define SPEC_QUIESCE_EXT_ADV		0x02
#define SPEC_QUIESCE_SCANNING		0x04
#define SPEC_QUIESCE_INITIATING		0x08
#define SPEC_QUIESCE_PERIODIC_SYNC	0x10

/* 7.8.4: legacy advertising, scanning, initiating.  Extended adv exempt. */
#define SPEC_QUIESCE_SET_RANDOM_ADDRESS					\
	(SPEC_QUIESCE_LEGACY_ADV | SPEC_QUIESCE_SCANNING |		\
	 SPEC_QUIESCE_INITIATING)

/* 7.8.15/16/17: only when a policy that uses the accept list is active. */
#define SPEC_QUIESCE_FILTER_ACCEPT_LIST_IF_IN_USE			\
	(SPEC_QUIESCE_LEGACY_ADV | SPEC_QUIESCE_EXT_ADV |		\
	 SPEC_QUIESCE_SCANNING | SPEC_QUIESCE_INITIATING)

/* 7.8.38/39: only while address resolution is enabled.  Periodic adv exempt. */
#define SPEC_QUIESCE_RESOLVING_LIST_IF_RESOLUTION_ON			\
	(SPEC_QUIESCE_LEGACY_ADV | SPEC_QUIESCE_EXT_ADV |		\
	 SPEC_QUIESCE_SCANNING | SPEC_QUIESCE_INITIATING |		\
	 SPEC_QUIESCE_PERIODIC_SYNC)

/* 7.8.44: unconditional.  Periodic advertising is exempt; nothing else is. */
#define SPEC_QUIESCE_SET_ADDR_RESOLUTION_ENABLE				\
	(SPEC_QUIESCE_LEGACY_ADV | SPEC_QUIESCE_EXT_ADV |		\
	 SPEC_QUIESCE_SCANNING | SPEC_QUIESCE_INITIATING |		\
	 SPEC_QUIESCE_PERIODIC_SYNC)

/*
 * =========================================================================
 * Which address a privacy-enabled device uses in which role.
 *
 * Vol 3 Part C Section 10.7.1, text lines 67065-67069, verbatim:
 *   "The privacy-enabled Peripheral shall use a resolvable private address as
 *    the advertiser's device address when in connectable mode."
 *   "A Peripheral shall use non-resolvable or resolvable private addresses
 *    when in non-connectable mode as defined in Section 9.3.2."
 *
 * Vol 3 Part C Section 10.7.2, text line 67127, verbatim:
 *   "The privacy-enabled Central shall use a resolvable private address as
 *    the initiator's device address."
 *
 * Vol 3 Part C Section 10.7.1.1, text lines 67092-67096, verbatim:
 *   "A privacy-enabled Peripheral shall use either the undirected connectable
 *    mode as defined in Section 9.3.4 or directed connectable mode as defined
 *    in Section 9.3.3. The directed connectable mode shall only be used if the
 *    peer device supports Address Resolution in the Controller."
 *   "The Host shall enable resolvable private address generation by enabling
 *    it in the Controller and populating the resolving list."
 *   "By default, network privacy mode is used when private addresses are
 *    resolved and generated by the Controller."
 *
 * Vol 3 Part C Section 10.7, text lines 67053-67056, verbatim -- the rule
 * that governs every host/controller reference to a peer under privacy:
 *   "When address resolution is enabled in the Controller, all references to
 *    peer devices that are included in the resolving list from Host to the
 *    Controller shall be done using the peer's device Identity Address.
 *    Likewise, all incoming events from the Controller to the Host will use
 *    the peer's device identity, if the peer's device address has been
 *    resolved."
 * -- this is the rule that makes a Filter Accept List populated with identity
 * addresses correct, and one populated with observed on-air RPAs wrong.
 * =========================================================================
 */

#endif /* SPEC_EXTREF_GAP_PRIVACY_H */

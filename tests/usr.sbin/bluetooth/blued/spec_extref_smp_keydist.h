/*
 * EXTERNAL REFERENCE ORACLE: SMP Key Distribution / Generation field under
 * LE Secure Connections.
 *
 * Hand-written (this is a bitmask semantics question, not a table of sample
 * data, so there is nothing to extract mechanically).  Every constant and
 * every claim below is traceable to a named external source; nothing here was
 * derived from blued.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   Vol 3, Part H, Section 3.6.1, Figure 3.11 (text line 78606) -- the LE Key
 *   Distribution format: bit 0 EncKey, bit 1 IdKey, bit 2 "Previously used"
 *   (the field formerly named SignKey/CSRK), bit 3 LinkKey, bits 4..7 RFU.
 *
 *   Vol 3, Part H, Section 3.6.1 (text lines 78620-78628), verbatim:
 *     "In LE legacy pairing, EncKey is a 1-bit field that is set to one to
 *      indicate that the device shall distribute LTK using the Encryption
 *      Information command followed by EDIV and Rand using the Central
 *      Identification command.
 *      In LE Secure Connections pairing, when SMP is running on the LE
 *      transport, then the EncKey field shall be ignored. EDIV and Rand shall
 *      be set to zero and shall not be distributed."
 *
 *   Vol 3, Part H, Section 3.6.1 (text lines 78641-78648), verbatim:
 *     "LinkKey is a 1-bit field. When SMP is running on the LE transport, the
 *      LinkKey field is set to one to indicate that the device would like to
 *      derive the Link Key from the LTK. When LinkKey is set to 1 by both
 *      devices in the initiator and responder Key Distribution / Generation
 *      fields, the procedures for calculating the BR/EDR link key from the LTK
 *      shall be used. Devices not supporting LE Secure Connections shall set
 *      this bit to zero and ignore it on reception."
 *
 *   Vol 3, Part H, Section 3.6.1 (text lines 78655-78659), verbatim:
 *     "The Peripheral shall not set to one any flag in the Initiator Key
 *      Distribution / Generation or Responder Key Distribution / Generation
 *      field of the Pairing Response command that the Central has set to zero
 *      in the Initiator Key Distribution / Generation and Responder Key
 *      Distribution / Generation fields of the Pairing Request command."
 *
 * BLUEZ (the reference implementation of SMP for the BlueZ stack lives in the
 * Linux kernel, not in the bluez userspace repository):
 *   linux/net/bluetooth/smp.c, fetched from
 *   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/net/bluetooth/smp.c
 *
 *   smp.c:52-53
 *     /-* Keys which are not distributed with Secure Connections *-/
 *     #define SMP_SC_NO_DIST (SMP_DIST_ENC_KEY | SMP_DIST_LINK_KEY)
 *
 *   smp.c:626 build_pairing_cmd() -- builds BOTH the Pairing Request and the
 *   Pairing Response on-the-wire masks.  It applies NO Secure Connections
 *   stripping whatsoever.  Under SC it in fact ADDS a bit (smp.c:655-657):
 *       if (hci_dev_test_flag(hdev, HCI_SC_ENABLED) &&
 *           (authreq & SMP_AUTH_SC)) {
 *               if (hci_dev_test_flag(hdev, HCI_SSP_ENABLED)) {
 *                       local_dist  |= SMP_DIST_LINK_KEY;
 *                       remote_dist |= SMP_DIST_LINK_KEY;
 *               }
 *   and the responder's advertised fields are only the spec's subset rule
 *   (smp.c:695-696):
 *       rsp->init_key_dist = req->init_key_dist & remote_dist;
 *       rsp->resp_key_dist = req->resp_key_dist & local_dist;
 *   So EncKey stays SET on the wire in BlueZ's Pairing Response under SC.
 *
 *   The SC stripping is applied only to the INTERNAL masks -- what we expect
 *   to receive and what we actually transmit in phase 3 -- and it clears BOTH
 *   EncKey and LinkKey, because under SC both of those keys are GENERATED
 *   locally rather than sent:
 *     smp.c:1244-1251 (smp_distribute_keys(), the "what do I send" mask):
 *         if (hcon->type == LE_LINK && (*keydist & SMP_DIST_LINK_KEY))
 *                 sc_generate_link_key(smp);
 *         if (hcon->type == ACL_LINK && (*keydist & SMP_DIST_ENC_KEY))
 *                 sc_generate_ltk(smp);
 *         /-* Clear the keys which are generated but not distributed *-/
 *         *keydist &= ~SMP_SC_NO_DIST;
 *     smp.c:1767-1768, 1831-1832, 1948-1949, 1977-1978 (the "what do I expect
 *     to receive" mask, smp->remote_key_dist):
 *         /-* Clear bits which are generated but not distributed *-/
 *         smp->remote_key_dist &= ~SMP_SC_NO_DIST;
 *
 *   BlueZ userspace carries an independent second implementation that agrees:
 *   bluez/emulator/smp.c:58
 *         #define SC_NO_DIST	(DIST_ENC_KEY | DIST_LINK_KEY)
 *   applied at emulator/smp.c:442-443 and 463-464 and 472-473, again to the
 *   local/remote distribution masks and not to the emitted response fields.
 *   (bluez snapshot commit 92305dc06ab8a6d89af2dae1d725cc4d51462ad1.)
 *
 * ANSWER
 * ------
 * Under LE Secure Connections, BlueZ clears TWO bits, not one: EncKey AND
 * LinkKey -- and it clears them from the internal distribute/expect masks,
 * NOT from the Key Distribution fields it puts on the wire.  IdKey and bit 2
 * are untouched in both places.
 *
 * BIT 2 IS NO LONGER "SignKey" IN CORE 6.3
 * ----------------------------------------
 * Core 6.3 has REMOVED LE data signing.  The strings "SignKey", "CSRK",
 * "Signing" and "Signed Write" do not occur anywhere in
 * Core_Specification_6_3.txt.  What remains are removal markers:
 *   Vol 3, Part H, Figure 3.11 (text line 78608) labels bit 2
 *     "Previously used".
 *   Vol 3, Part H, Table 3.3 (text line 78005): SMP command code "0x0A
 *     Previously used" -- 0x0A was Signing Information.
 *   Vol 3, Part F (text line 71333): "Note: Attribute Opcode 0xD2 is
 *     previously used (see [Vol 1] Part E, Section 2.4.2)." -- 0xD2 was
 *     Signed Write Command.
 *   Vol 1, Part E, Section 2.4.2 (text line 18182) defines the term:
 *     "The term \"Previously used\" ... indicates that a field or value was
 *      used for a removed feature ... Devices that do not implement that
 *      feature shall treat the field or value as reserved for future use."
 * Linux net/bluetooth/smp.c still implements SMP_DIST_SIGN for interoperation
 * with peers built against Core 4.x/5.x, so continuing to set bit 2 is
 * defensible on interop grounds -- but it cannot be justified by citing
 * Core 6.3, which no longer defines it.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_SMP_KEYDIST_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_SMP_KEYDIST_H

#include <stdint.h>

/* Core 6.3, Vol 3, Part H, Section 3.6.1, Figure 3.11 (text line 78606). */
#define BT_EXTREF_SMP_DIST_ENC_KEY	0x01
#define BT_EXTREF_SMP_DIST_ID_KEY	0x02
#define BT_EXTREF_SMP_DIST_SIGN		0x04
#define BT_EXTREF_SMP_DIST_LINK_KEY	0x08
#define BT_EXTREF_SMP_DIST_RFU_MASK	0xf0

/*
 * linux/net/bluetooth/smp.c:53
 *   #define SMP_SC_NO_DIST (SMP_DIST_ENC_KEY | SMP_DIST_LINK_KEY)
 * bluez/emulator/smp.c:58
 *   #define SC_NO_DIST (DIST_ENC_KEY | DIST_LINK_KEY)
 *
 * The set of bits BlueZ clears from the internal key-distribution masks once
 * Secure Connections has been selected.  Value 0x09.
 */
#define BT_EXTREF_SMP_SC_NO_DIST \
	(BT_EXTREF_SMP_DIST_ENC_KEY | BT_EXTREF_SMP_DIST_LINK_KEY)

/*
 * Which mask each stripping applies to.  This distinction is the whole point
 * of this header: BlueZ does the stripping in a different PLACE from where a
 * naive reading would put it.
 *
 * linux/net/bluetooth/smp.c:626 build_pairing_cmd() -- the on-the-wire
 * Pairing Request / Pairing Response Key Distribution fields.  No SC
 * stripping.  Set to 1 to record "BlueZ leaves the wire mask alone".
 */
#define BT_EXTREF_SMP_BLUEZ_WIRE_MASK_UNSTRIPPED_UNDER_SC 1

/*
 * linux/net/bluetooth/smp.c:1251 and :1768 -- the internal
 * distribute/expect masks.  SC stripping applies here, and clears 0x09.
 */
#define BT_EXTREF_SMP_BLUEZ_INTERNAL_MASK_SC_CLEARED \
	BT_EXTREF_SMP_SC_NO_DIST

/*
 * Worked example of BlueZ's responder behaviour on an LE transport with
 * Secure Connections selected, HCI_BONDABLE, HCI_PRIVACY and
 * HCI_RPA_RESOLVING set, HCI_SSP_ENABLED set, and an initiator that requested
 * everything (0x0f in both fields).
 *
 * Derivation, from linux/net/bluetooth/smp.c:636-657 and :694-696 only:
 *   local_dist  = SMP_DIST_ENC_KEY | SMP_DIST_SIGN          (line 637) = 0x05
 *   remote_dist = SMP_DIST_ENC_KEY | SMP_DIST_SIGN          (line 638) = 0x05
 *   remote_dist |= SMP_DIST_ID_KEY  (HCI_RPA_RESOLVING, 645)          = 0x07
 *   local_dist  |= SMP_DIST_ID_KEY  (HCI_PRIVACY, 648)                = 0x07
 *   local_dist  |= SMP_DIST_LINK_KEY (SC && SSP, 656)                 = 0x0f
 *   remote_dist |= SMP_DIST_LINK_KEY (SC && SSP, 657)                 = 0x0f
 *   rsp->init_key_dist = req->init_key_dist & remote_dist = 0x0f & 0x0f = 0x0f
 *   rsp->resp_key_dist = req->resp_key_dist & local_dist  = 0x0f & 0x0f = 0x0f
 */
#define BT_EXTREF_SMP_BLUEZ_SC_RSP_INIT_KEY_DIST 0x0f
#define BT_EXTREF_SMP_BLUEZ_SC_RSP_RESP_KEY_DIST 0x0f

/*
 * The same responder's INTERNAL masks after the SC stripping at
 * linux/net/bluetooth/smp.c:1768 / :1251: 0x0f & ~0x09 == 0x06, i.e. IdKey
 * and SignKey only.  EncKey and LinkKey are both gone, because both are
 * generated (sc_generate_ltk / sc_generate_link_key) rather than transmitted.
 */
#define BT_EXTREF_SMP_BLUEZ_SC_INTERNAL_KEY_DIST 0x06

/*
 * Legacy (non-SC) responder in the same configuration, for contrast: no
 * stripping anywhere, and LinkKey is never offered because line 656/657 is
 * guarded on SC.  0x07 = EncKey | IdKey | SignKey.
 */
#define BT_EXTREF_SMP_BLUEZ_LEGACY_RSP_KEY_DIST 0x07

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_SMP_KEYDIST_H */

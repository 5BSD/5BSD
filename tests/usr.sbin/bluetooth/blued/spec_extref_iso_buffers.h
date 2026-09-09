/*
 * EXTERNAL REFERENCE ORACLE: controller buffer discovery and host-to-controller
 * packet-based flow control for ACL, LE ACL and ISO data.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from ng_hci, ng_btsocket_iso or
 * blued.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   (line numbers are lines of that .txt file)
 *
 * --- Vol 4, Part E, Section 4.1 (.txt lines 86555-86562), verbatim:
 *       "The Host shall use separate packet based flow control for each set of
 *        buffers."
 *       "If a BR/EDR/LE Controller does not implement separate buffers, then
 *        all ACL Data shall use the BR/EDR buffer management"
 *
 * --- Vol 4, Part E, Section 4.1.1 (.txt lines 86581-86592), verbatim:
 *       "When the packet based flow control mechanism is enabled, on
 *        initialization, a Host that supports LE shall issue the
 *        HCI_LE_Read_Buffer_Size command (see Section 7.8.2). ... A Controller
 *        that supports BR/EDR and LE may return zero for the total number of
 *        HCI ACL packets used to transmit ACL data for an LE transport. In this
 *        case the Host shall then send all BR/EDR and LE data using the HCI ACL
 *        Data packets into the buffers identified using the
 *        HCI_Read_Buffer_Size command. A Controller that does not support
 *        BR/EDR shall not return zero for the total number of HCI ACL packets
 *        used to transmit ACL data for an LE transport."
 *     The last sentence is the one that matters for an LE-only dongle: there is
 *     no BR/EDR pool to fall back to, so a host that never reads the LE pool has
 *     no credits at all.
 *
 * --- Vol 4, Part E, Section 4.1.1 (.txt lines 86593-86597), verbatim:
 *       "When the packet-based flow control mechanism is enabled, on
 *        initialization, a Host that supports isochronous data over HCI in
 *        either the Connected Isochronous Stream Central role, Connected
 *        Isochronous Stream Peripheral role, or Isochronous Broadcaster role
 *        shall issue the HCI_LE_Read_Buffer_Size command."
 *     and (.txt lines 86606-86609):
 *       "the ISO_Data_Packet_Length and Total_Num_ISO_Data_Packets return
 *        parameters are only available when using v2 or above"
 *     -- so an ISO-capable host must specifically issue the v2 form.
 *
 * --- Vol 4, Part E, Section 4.1.1 (.txt lines 86636-86645): the Host debits
 *     its free-buffer count by one for every HCI Data packet and every HCI ISO
 *     Data packet it sends, per link type.
 *
 * --- Vol 4, Part E, Section 4.1.1 (.txt lines 86653-86654), verbatim -- the
 *     hard prohibition:
 *       "The Host shall not send an HCI Data packet or HCI ISO Data packet to
 *        the Controller when its count of the free buffer space for the
 *        corresponding link type is zero."
 *
 * --- Vol 4, Part E, Section 4.3 (.txt lines 86754-86766), verbatim:
 *       "When the Host receives an HCI_Disconnection_Complete event, the Host
 *        shall assume that all unacknowledged HCI Data packets that have been
 *        sent to the Controller for the returned Handle have been flushed, and
 *        that the corresponding data buffers have been freed."
 *
 * --- Vol 4, Part E, Section 7.3.37 (.txt lines 96027-96029): Synchronous Flow
 *     Control defaults to DISABLED, and while it is disabled
 *       "No HCI_Number_Of_Completed_Packets events shall be sent from the
 *        Controller for synchronous Connection_Handles."
 *     A host that debits SCO credits without enabling it will never get them
 *     back.
 *
 * --- Vol 4, Part E, Section 7.4.5 (.txt lines 100238-100246), verbatim:
 *       "shall be issued by the Host before it sends any data to the
 *        Controller"
 *       "For a device supporting BR/EDR and LE, if the HCI_LE_Read_Buffer_Size
 *        command returned zero for the number of buffers, then buffers returned
 *        by Read_Buffer_Size are shared between BR/EDR and LE."
 *
 * --- Vol 4, Part E, Section 7.7.19 (.txt lines 103118-103124), verbatim:
 *       "shall not specify a given Handle before the Controller has sent the
 *        event indicating that the corresponding connection or BIG has been
 *        created or after it has sent the event indicating disconnection ... or
 *        indicating that the BIG has been terminated"
 *     and (.txt lines 103136-103156): Handle[i] is 2 octets in the range
 *     0x0000-0x0EFF and is a "Connection_Handle or BIS_Handle";
 *     Num_Completed_Packets[i] is 2 octets.
 *
 * --- Vol 4, Part E, Section 7.8.2 (.txt lines 111915-111926), verbatim:
 *       "If the Controller supports HCI ISO Data packets, it shall return
 *        non-zero values for the ISO_Data_Packet_Length and
 *        Total_Num_ISO_Data_Packets parameters."
 *       "If the Controller returns a length value of zero for ACL data packets,
 *        the Host shall use the HCI_Read_Buffer_Size command to determine the
 *        size of the data buffers (shared between BR/EDR and LE transports)."
 *     Note that this section's fallback trigger is the LENGTH being zero, while
 *     Sections 4.1.1 and 7.4.5 give the fallback trigger as the packet COUNT
 *     being zero.  Both triggers exist and they are different fields; an
 *     implementation that keys on only one of them has a hole.
 *
 * --- Vol 4, Part E, Section 7.8.2 return parameters (.txt lines 111969-112000):
 *     LE_ACL_Data_Packet_Length is 2 octets, "0x0000 = No dedicated LE Buffer
 *     exists. Use the HCI_Read_Buffer_Size command"; Total_Num_LE_ACL_Data_
 *     Packets is ONE octet, "0x00 = No dedicated LE Buffer exists";
 *     ISO_Data_Packet_Length is 2 octets, "0x0000 = No dedicated ISO Buffer
 *     exists"; Total_Num_ISO_Data_Packets is ONE octet, "0x00 = No dedicated
 *     ISO Buffer exists".
 *
 * REFERENCE IMPLEMENTATIONS
 * -------------------------
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac)
 *   subsys/bluetooth/host/hci_core.c -- issues LE Read Buffer Size v2 when the
 *     controller advertises it and falls back to v1 otherwise, gated on the
 *     Supported Commands bit; tracks bt_dev.le.acl_pkts and bt_dev.le.iso_pkts
 *     as separate counting semaphores so a caller BLOCKS rather than
 *     overrunning; on an over-large Number Of Completed Packets count it drops
 *     the surplus (hci_core.c:740-745).
 *   Zephyr also enables controller-to-host flow control by default in
 *     host-only builds.
 *
 * NIMBLE (1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845)
 *   nimble/host/src/ble_hs_hci.c -- maintains a single outstanding-packet
 *     budget; on an over-large Number Of Completed Packets count it resets the
 *     host (ble_hs_hci_evt.c:312).  Controller-to-host flow control is
 *     implemented but off by default.  Connection teardown does not return
 *     bhc_outstanding_pkts to the pool.
 *
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1)
 *   The host-side credit scheduler is in the Linux kernel
 *   (net/bluetooth/hci_core.c), which is NOT present in the cloned tree --
 *   verified absent, so no BlueZ behavioural claim is made.  In userspace,
 *   src/shared/hci.c contains no flow-control logic at all; monitor/packet.c
 *   keeps a passive credit shadow that does track ISO separately from ACL.
 */

#ifndef SPEC_EXTREF_ISO_BUFFERS_H
#define SPEC_EXTREF_ISO_BUFFERS_H

#include <stdint.h>

/* Command opcodes referenced above (OGF/OCF as printed in the spec tables). */
#define SPEC_EXTREF_HCI_OCF_READ_BUFFER_SIZE		0x0005u	/* OGF 0x04 */
#define SPEC_EXTREF_HCI_OCF_LE_READ_BUFFER_SIZE_V1	0x0002u	/* OGF 0x08 */
#define SPEC_EXTREF_HCI_OCF_LE_READ_BUFFER_SIZE_V2	0x0060u	/* OGF 0x08 */
#define SPEC_EXTREF_HCI_OCF_SET_CTLR_TO_HOST_FC		0x0031u	/* OGF 0x03 */
#define SPEC_EXTREF_HCI_OCF_HOST_BUFFER_SIZE		0x0033u	/* OGF 0x03 */
#define SPEC_EXTREF_HCI_OCF_HOST_NUM_COMPLETED_PKTS	0x0035u	/* OGF 0x03 */
#define SPEC_EXTREF_HCI_OCF_WRITE_SYNC_FLOW_CONTROL	0x002Fu	/* OGF 0x03 */
#define SPEC_EXTREF_HCI_EVT_NUM_COMPLETED_PACKETS	0x13u

/*
 * Sec 7.8.2: the ISO buffer parameters exist ONLY in the v2 form.  A host that
 * intends to move ISO data over HCI must issue v2; v1 cannot report them.
 */
#define SPEC_EXTREF_ISO_BUFFERS_REQUIRE_LE_RBS_V2	1

/* Sec 7.8.2 sentinels.  Note the packet COUNTS are one octet, not two. */
#define SPEC_EXTREF_LE_ACL_LEN_NO_DEDICATED_BUFFER	0x0000u
#define SPEC_EXTREF_LE_ACL_COUNT_NO_DEDICATED_BUFFER	0x00u
#define SPEC_EXTREF_ISO_LEN_NO_DEDICATED_BUFFER		0x0000u
#define SPEC_EXTREF_ISO_COUNT_NO_DEDICATED_BUFFER	0x00u
#define SPEC_EXTREF_LE_ACL_COUNT_FIELD_OCTETS		1u
#define SPEC_EXTREF_ISO_COUNT_FIELD_OCTETS		1u

/*
 * The BR/EDR-pool fallback has TWO independent triggers, in two different
 * sections.  An implementation must honour both.
 */
#define SPEC_EXTREF_LE_FALLBACK_ON_ZERO_COUNT		1	/* Sec 4.1.1, 7.4.5 */
#define SPEC_EXTREF_LE_FALLBACK_ON_ZERO_LENGTH		1	/* Sec 7.8.2       */
#define SPEC_EXTREF_LE_USES_BREDR_POOL(len, count)			\
	((len) == SPEC_EXTREF_LE_ACL_LEN_NO_DEDICATED_BUFFER ||		\
	 (count) == SPEC_EXTREF_LE_ACL_COUNT_NO_DEDICATED_BUFFER)

/*
 * Sec 4.1.1: on an LE-only controller a zero LE packet count is illegal, so a
 * host seeing one on such a controller is looking at a value it never read
 * rather than at a legitimate "share the BR/EDR pool" signal.
 */
#define SPEC_EXTREF_LE_ONLY_CTLR_MAY_RETURN_ZERO_COUNT	0

/* Sec 4.1.1: the hard prohibition, and its corollary. */
#define SPEC_EXTREF_MAY_SEND_DATA(free_count)		((free_count) > 0u)

/* Sec 7.7.19 field ranges. */
#define SPEC_EXTREF_NCP_HANDLE_MAX			0x0EFFu
#define SPEC_EXTREF_NCP_HANDLE_INCLUDES_BIS		1
#define SPEC_EXTREF_NCP_COUNT_FIELD_OCTETS		2u

/*
 * Sec 4.3: after Disconnection Complete every unacknowledged packet for that
 * handle is deemed flushed and its buffer freed.  ISO adds the BIG-terminated
 * case via Sec 7.7.19's "or indicating that the BIG has been terminated".
 */
#define SPEC_EXTREF_DISCONNECT_RECLAIMS_CREDITS		1

/*
 * Sec 7.3.37: Synchronous Flow Control is DISABLED by default, and no
 * Number Of Completed Packets is reported for synchronous handles while it is.
 * Debiting an SCO/eSCO credit without first enabling it is a one-way ratchet.
 */
#define SPEC_EXTREF_SYNC_FLOW_CONTROL_DEFAULT_ENABLED	0

/*
 * Sec 4.2: controller-to-host flow control is opt-in.  Not enabling it is
 * spec-legal; it is listed here so a test can assert the choice deliberately
 * rather than by omission.
 */
#define SPEC_EXTREF_CTLR_TO_HOST_FC_IS_OPTIONAL		1

#endif /* SPEC_EXTREF_ISO_BUFFERS_H */

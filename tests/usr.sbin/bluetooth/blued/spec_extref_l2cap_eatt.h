/*
 * EXTERNAL REFERENCE ORACLE: Enhanced ATT bearers (EATT, Bluetooth 5.2) --
 * bearer establishment preconditions, ATT_MTU derivation, the per-bearer
 * transaction rules, and the collision-retry backoff.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from blued's att.c.
 *
 * A NOTE ON SECTION NUMBERS, because this is where this tree keeps going
 * wrong: the EATT sections are Vol 3 Part **G** Sections 5.3, 5.3.1, 5.3.2 and
 * 5.4, and the Exchange-MTU restriction is Vol 3 Part **G** Section 4.2.
 * Several in-tree comments attribute these to Vol 3 Part F, which has no such
 * sections.  Part F Section 3.4.2 is the Exchange MTU *PDU format* and states
 * no bearer restriction at all.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   (line numbers are lines of that .txt file)
 *
 * --- Vol 3, Part G, Section 4.2 (.txt lines 73160-73164), verbatim:
 *       "If an ATT PDU is supported on any ATT bearer, then it shall be
 *        supported on all supported ATT bearers with the following exception:
 *        - The Exchange MTU sub-procedure shall only be supported on the LE
 *          Fixed Channel Unenhanced ATT bearer."
 *     This -- not any section of Part F -- is the rule that forbids
 *     ATT_EXCHANGE_MTU_REQ on an Enhanced ATT bearer.
 *
 * --- Vol 3, Part G, Section 5.3.1 ATT_MTU (.txt lines 74805-74813), verbatim:
 *       "The ATT_MTU for the Enhanced ATT bearer shall be set to the minimum
 *        of the MTU field values of the two devices; these values come from
 *        the L2CAP_CREDIT_BASED_CONNECTION_REQ and
 *        L2CAP_CREDIT_BASED_CONNECTION_RSP signaling packets or the latest
 *        L2CAP_CREDIT_BASED_RECONFIGURE_REQ packets.
 *        Note: The minimum ATT_MTU for an Enhanced ATT bearer is 64 octets."
 *     Two separate obligations: take the MINIMUM of the two directions, and
 *     re-derive it after a RECONFIGURE.
 *
 * --- Vol 3, Part G, Section 5.3.2 Channel Requirements (.txt lines
 *     74815-74831), verbatim:
 *       "All Attribute Protocol messages sent by GATT over an L2CAP Enhanced
 *        Credit Based Flow Control mode channel are sent using one of the
 *        dynamic channel IDs derived by connecting using a fixed PSM.
 *        All packets sent on this L2CAP channel shall be Attribute PDUs.
 *        The flow specification for the Attribute Protocol shall be best
 *        effort.
 *        The information payload of the L2CAP K-frame shall be a single
 *        Attribute PDU.
 *        The underlying ACL connection shall be encrypted before the channel
 *        is created and shall remain encrypted (other than to refresh the key)
 *        thereafter."
 *
 * --- Vol 3, Part G, Section 5.4 L2CAP collision mitigation (.txt lines
 *     74834-74841), verbatim:
 *       "If both devices request L2CAP connections simultaneously and both
 *        devices have limited resources, a device may reject the incoming
 *        request and find its own request is also rejected. In this situation,
 *        the Central may retry immediately but the Peripheral shall wait a
 *        minimum of 100 ms before retrying; on LE connections, the Peripheral
 *        shall wait at least 2 x (connPeripheralLatency + 1) x connInterval if
 *        that is longer."
 *     Note the shape: the "shall" binds a retrying PERIPHERAL.  A device that
 *     never retries at all does not violate this sentence -- but it also never
 *     recovers from a transient refusal.
 *
 * --- Vol 3, Part F, Section 3.2.8 (.txt lines 69535-69539), verbatim:
 *       "When using an L2CAP channel with a dynamically allocated CID, the
 *        ATT_MTU shall be set to the L2CAP MTU size."
 *       "The ATT_MTU value is a per ATT bearer value. A device with multiple
 *        ATT bearers may have a different ATT_MTU value for each ATT bearer."
 *
 * --- Vol 3, Part F, Section 3.3.2 (.txt lines 69699-69704, 69728), verbatim:
 *       "Once a client sends a request to a server, that client shall send no
 *        other request to the same server on the same ATT bearer until a
 *        response PDU has been received."
 *       "No other indications shall be sent to the same client from this
 *        server on the same ATT bearer until a confirmation PDU has been
 *        received."
 *       "On an Enhanced ATT bearer, notifications shall always be processed
 *        when received."
 *     The flow-control scope is THE BEARER, in both directions.  An
 *     implementation that keeps indication state per *connection* and accepts
 *     a confirmation arriving on any bearer is not implementing this sentence.
 *
 * --- Vol 3, Part F, Section 3.3.3 (.txt lines 69751-69752, 69766-69781),
 *     verbatim:
 *       "A transaction shall always be performed on one ATT bearer, and shall
 *        not be split over multiple ATT bearers."
 *       "No more Attribute Protocol requests, commands, indications or
 *        notifications shall be sent to the target device on this ATT bearer.
 *        To send another Attribute Protocol PDU, a new ATT bearer must be
 *        established..."
 *       "If the ATT bearer is terminated during a transaction, then the
 *        transaction shall be considered to be closed..."
 *     i.e. the 30-second transaction timeout kills ONE bearer, not the link.
 *
 * --- Vol 3, Part G, Section 4.14 (.txt lines 74680-74681), verbatim:
 *       "No further GATT procedures shall be performed on that ATT bearer. A
 *        new GATT procedure shall only be performed on another ATT bearer."
 *
 * --- Vol 3, Part G, Section 6.2.1 (.txt lines 74888-74896), verbatim note:
 *       "Note: Unlike BR/EDR, it is not necessary to check the Server
 *        Supported Features characteristic before attempting to establish an
 *        Enhanced ATT bearer."
 *
 * --- The EATT PSM and the channel count come from Vol 3 Part A Section 4.25
 *     ("up to five", .txt line 53144) and the Assigned Numbers fixed-PSM
 *     allocation; see spec_extref_l2cap_ecfc.h for the L2CAP side.
 *
 * REFERENCE IMPLEMENTATIONS
 * -------------------------
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1)
 *   - Channel count is the `gatt_channels` main.conf option; the shipped
 *     default is 1, i.e. EATT off unless configured.
 *   - Initiates only when it is the connection initiator, which is BlueZ's
 *     collision avoidance: it drops an inbound EATT bearer while its own
 *     request is outstanding.
 *   - Derives the bearer MTU from `l2cap_options.omtu` alone
 *     (`io_get_mtu()`), not min(imtu, omtu) -- a divergence from .txt
 *     74807-74811.
 *   - Answers an Exchange MTU Request on an enhanced bearer with
 *     Request Not Supported rather than dropping the channel.
 *   - Writes the peer's Client Supported Features characteristic
 *     (src/device.c:6326-6331) so the peer server learns EATT support.
 *
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac)
 *   - CONFIG_BT_EATT_MAX default 3, range 1..16.
 *   - subsys/bluetooth/host/att.c:3605-3679 implements Section 5.4 verbatim,
 *     including the 100 ms peripheral floor and the
 *     2 x (latency + 1) x interval alternative.
 *   - bt_att_mtu() = MIN(chan->chan.rx.mtu, chan->chan.tx.mtu)
 *     (subsys/bluetooth/host/att.c:140) -- agrees with .txt 74807-74811.
 *   - subsys/bluetooth/host/att.c:3448-3455 re-derives the bearer MTU after an
 *     L2CAP reconfigure.
 *   - Disconnects the channel on an Exchange MTU Request over EATT.
 *
 * NIMBLE (1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845)
 *   - nimble/host/src/ble_eatt.c requests exactly one channel per ACL
 *     (num = 1) and carries a TODO acknowledging the limitation.
 *   - nimble/host/src/ble_eatt.c:271-285 disconnects the channel on an
 *     unsupported request opcode -- which includes ATT_EXCHANGE_MTU_REQ --
 *     quoting the Section 4.2 exception.
 *   - Falls back to the unenhanced bearer when all EATT channels are busy.
 *
 * On the Exchange-MTU reaction the ecosystem is split: BlueZ answers
 * Request Not Supported, Zephyr and NimBLE tear the channel down.  The spec
 * says only that the sub-procedure "shall only be supported on" the
 * unenhanced bearer; it does not mandate a reaction.  Answering an error is
 * the interoperable choice.
 */

#ifndef SPEC_EXTREF_L2CAP_EATT_H
#define SPEC_EXTREF_L2CAP_EATT_H

#include <stdint.h>

/* Vol 3 Part G Sec 5.3.1 note (.txt line 74813) and Part A Sec 4.25. */
#define SPEC_EXTREF_EATT_MTU_MIN		64u
/* Vol 3 Part A Sec 4.25 (.txt line 53144): "up to five" channels per REQ. */
#define SPEC_EXTREF_EATT_MAX_CHANNELS_PER_REQ	5u

/*
 * ATT_MTU derivation, Vol 3 Part G Sec 5.3.1: the minimum of the two devices'
 * MTU fields -- i.e. of our receive MTU and the peer's receive MTU, which on a
 * socket API are the incoming and outgoing MTUs of the channel.
 */
#define SPEC_EXTREF_EATT_ATT_MTU(imtu, omtu)				\
	((imtu) < (omtu) ? (imtu) : (omtu))

/*
 * Sec 5.3.1 also binds the ATT_MTU to "the latest
 * L2CAP_CREDIT_BASED_RECONFIGURE_REQ packets", so the derivation above must be
 * re-run after every reconfigure, not only at bearer creation.
 */
#define SPEC_EXTREF_EATT_MTU_REDERIVED_ON_RECONFIGURE	1

/* Sec 5.3.2: preconditions that are "shall". */
#define SPEC_EXTREF_EATT_REQUIRES_ENCRYPTION_BEFORE_OPEN	1
#define SPEC_EXTREF_EATT_REQUIRES_ENCRYPTION_THEREAFTER		1
#define SPEC_EXTREF_EATT_ONE_ATT_PDU_PER_KFRAME			1

/* Vol 3 Part G Sec 4.2: Exchange MTU is unenhanced-bearer-only. */
#define SPEC_EXTREF_EATT_EXCHANGE_MTU_FORBIDDEN			1

/*
 * Vol 3 Part F Sec 3.3.2 / 3.3.3: flow control and transaction scope are
 * PER BEARER.  A request, its response, an indication and its confirmation all
 * belong to one bearer.
 */
#define SPEC_EXTREF_EATT_ONE_OUTSTANDING_REQ_PER_BEARER		1
#define SPEC_EXTREF_EATT_ONE_OUTSTANDING_IND_PER_BEARER		1
#define SPEC_EXTREF_EATT_TRANSACTION_NOT_SPLIT_ACROSS_BEARERS	1
/* Sec 3.3.3 / Sec 4.14: a timeout kills the bearer, not the connection. */
#define SPEC_EXTREF_EATT_TIMEOUT_SCOPE_IS_BEARER		1
/* Sec 3.3.2: notifications are always processed on an enhanced bearer. */
#define SPEC_EXTREF_EATT_NOTIFICATIONS_ALWAYS_PROCESSED		1

/* Vol 3 Part F Sec 3.3.3 transaction timeout, in seconds. */
#define SPEC_EXTREF_ATT_TRANSACTION_TIMEOUT_SEC			30u

/*
 * Vol 3 Part G Sec 5.4 collision mitigation.  The Central may retry
 * immediately; a retrying Peripheral shall wait at least the larger of 100 ms
 * and 2 x (connPeripheralLatency + 1) x connInterval.
 *
 * conn_interval is in 1.25 ms units (Vol 6 Part B), so the second term in
 * milliseconds is 2 * (latency + 1) * interval * 5 / 4.
 */
#define SPEC_EXTREF_EATT_CENTRAL_RETRY_DELAY_MS			0u
#define SPEC_EXTREF_EATT_PERIPH_RETRY_FLOOR_MS			100u
#define SPEC_EXTREF_EATT_PERIPH_RETRY_LL_MS(latency, interval)		\
	((2u * ((latency) + 1u) * (interval) * 5u) / 4u)
#define SPEC_EXTREF_EATT_PERIPH_RETRY_MS(latency, interval)		\
	(SPEC_EXTREF_EATT_PERIPH_RETRY_LL_MS((latency), (interval)) >	\
	    SPEC_EXTREF_EATT_PERIPH_RETRY_FLOOR_MS ?			\
	    SPEC_EXTREF_EATT_PERIPH_RETRY_LL_MS((latency), (interval)) :	\
	    SPEC_EXTREF_EATT_PERIPH_RETRY_FLOOR_MS)

/*
 * Vol 3 Part G Sec 6.2.1 (.txt lines 74888-74896): on LE, a client need not
 * read the Server Supported Features characteristic before opening an
 * enhanced bearer.  Recorded so nobody adds a gate the spec disclaims.
 */
#define SPEC_EXTREF_EATT_LE_NEEDS_SSF_CHECK_FIRST		0

/*
 * Vol 3 Part H Tables 3.1 and 3.2 (.txt lines 77950-77972): the SMP fixed
 * channel MTU.  Included here because a stack that pins every LE fixed channel
 * at 23 octets cannot carry the 65-octet Pairing Public Key.
 */
#define SPEC_EXTREF_SMP_CHANNEL_MTU_LEGACY			23u
#define SPEC_EXTREF_SMP_CHANNEL_MTU_SECURE_CONNECTIONS		65u

#endif /* SPEC_EXTREF_L2CAP_EATT_H */

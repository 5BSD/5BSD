/*
 * EXTERNAL REFERENCE ORACLE: L2CAP Enhanced Credit Based Flow Control mode
 * (Bluetooth 5.2) -- the L2CAP_CREDIT_BASED_* signalling commands (0x17-0x1A),
 * the credit rules, and the mandatory disconnect conditions.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from ng_l2cap or from blued.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   (line numbers are lines of that .txt file)
 *
 * --- Vol 3, Part A, Section 3.4.2 (L2CAP SDU Length field), .txt lines
 *     51957-51961, verbatim:
 *       "The first K-frame of the SDU shall contain the L2CAP SDU Length field
 *        that shall specify the total number of octets in the SDU. The value
 *        shall not be greater than the peer device's MTU for the channel. All
 *        subsequent K-frames that are part of the same SDU shall not contain
 *        the L2CAP SDU Length field."
 *
 * --- Vol 3, Part A, Section 3.4.3 (Information Payload field), .txt lines
 *     51964-51976, verbatim -- the three MANDATORY disconnect conditions:
 *       "The number of octets contained in the first K-frame information
 *        payload of the SDU is equal to the PDU Length minus 2 octets. All
 *        subsequent K-frames of the same SDU contain the number of octets in
 *        the information payload equal to the PDU Length.
 *        If the SDU length field value exceeds the receiver's MTU, the
 *        receiver shall disconnect the channel. If the payload size of any
 *        K-frame exceeds the receiver's MPS, the receiver shall disconnect the
 *        channel. If the sum of the payload sizes for the K-frames exceeds the
 *        specified SDU length, the receiver shall disconnect the channel."
 *
 * --- Vol 3, Part A, Table 4.2 (.txt lines 52078-52102): codes 0x17, 0x18,
 *     0x19 and 0x1A are permitted on BOTH signalling CIDs, "0x0001 and
 *     0x0005".  ECBFC is not LE-only.
 *
 * --- Vol 3, Part A, Section 4.25 L2CAP_CREDIT_BASED_CONNECTION_REQ
 *     (code 0x17), .txt lines 53143-53145, verbatim:
 *       "L2CAP_CREDIT_BASED_CONNECTION_REQ packets are sent to create and
 *        configure up to five L2CAP channels between two devices."
 *
 *     Field rules, .txt lines 53164-53192, verbatim:
 *       "The MTU field specifies the maximum SDU size (in octets) that the
 *        L2CAP layer entity sending the L2CAP_CREDIT_BASED_CONNECTION_REQ
 *        packet can receive on each of the Source CID channels. L2CAP
 *        implementations shall support a minimum MTU size of 64 octets for
 *        these channels."
 *       "The MPS field specifies the maximum PDU payload size (in octets) ...
 *        L2CAP implementations shall support a minimum MPS of 64 octets and
 *        may support an MPS up to 65533 octets for these channels."
 *       "The initial credit value shall be in the range of 1 to 65535."
 *       "The Source CID is an array of up to 5 two-octet values ... Each entry
 *        in the array shall be non-zero and represents a request for a
 *        channel."
 *
 * --- Vol 3, Part A, Section 4.26 / Table 4.17 (.txt lines 53238-53259).  The
 *     Result values, transcribed in full below.  Note the wording that
 *     distinguishes ALL from SOME:
 *       0x0004 "Some connections refused - insufficient resources available"
 *       0x0009 "Some connections refused - invalid Source CID"
 *       0x000A "Some connections refused - Source CID already allocated"
 *     and the governing sentence at .txt lines 53240-53241:
 *       "The Destination CID, MTU, MPS and Initial Credits fields shall be
 *        ignored when the Result field indicates that all connections were
 *        refused or all connections are pending."
 *
 *     The per-CID outcome rule, .txt lines 53276-53281, verbatim:
 *       "The order of the Destination CIDs shall correspond to the order of the
 *        Source IDs in the corresponding L2CAP_CREDIT_BASED_CONNECTION_REQ
 *        packet. If a Destination CID is non-zero, the channel was
 *        established. If a Destination CID is 0x0000, the channel was not
 *        established. If a device receives an
 *        L2CAP_CREDIT_BASED_CONNECTION_RSP packet with an already-assigned
 *        Destination CID, then both the original channel and the new channel
 *        shall not be used."
 *
 *     This is the text that settles partial success: a responder that can host
 *     three of five requested channels answers 0x0004 with three non-zero and
 *     two zero Destination CIDs.  Refusing all five is not what the
 *     specification describes.
 *
 * --- Vol 3, Part A, Section 4.27 L2CAP_CREDIT_BASED_RECONFIGURE_REQ (code
 *     0x19), .txt lines 53287-53289 and 53305-53317, verbatim:
 *       "A device shall send an L2CAP_CREDIT_BASED_RECONFIGURE_REQ packet when
 *        its receive MTU or MPS values have changed compared to when the
 *        channel was created or last reconfigured."
 *       "The MTU field shall be greater than or equal to the greatest current
 *        MTU size of these channels."
 *       "If more than one channel is being configured, the MPS field shall be
 *        greater than or equal to the current MPS size of each of these
 *        channels. If only one channel is being configured, the MPS field may
 *        be less than the current MPS of that channel."
 *     and .txt lines 53322-53325, verbatim:
 *       "The Destination CID is an array of up to 5 two-octet values which
 *        shall be non-zero and represent the channel endpoints on the device
 *        sending the L2CAP_CREDIT_BASED_RECONFIGURE_REQ packet."
 *     -- i.e. in the RECONFIGURE_REQ the "Destination CID" array holds the
 *     SENDER's own endpoints, the opposite convention to a CONNECTION_REQ.
 *
 * --- Vol 3, Part A, Section 10.2 Enhanced Credit Based Flow Control Mode,
 *     .txt lines 58125-58148, verbatim (the whole credit contract):
 *       "The ACL logical transport shall have an infinite Automatic Flush
 *        Timeout.
 *        The number of credits (K-frames) that can be received by a device on
 *        an L2CAP channel is determined during connection establishment.
 *        K-frames shall only be sent on an L2CAP channel if the device has a
 *        credit count greater than zero for that L2CAP channel. For each
 *        K-frame sent, the sending device shall decrease the credit count for
 *        that L2CAP channel by one. The peer device may return credits for an
 *        L2CAP channel at any time by sending an
 *        L2CAP_FLOW_CONTROL_CREDIT_IND packet. When a credit packet is
 *        received by a device, it shall increment the credit count for that
 *        L2CAP channel by the value of the Credits field in this packet. The
 *        number of credits returned for an L2CAP channel may exceed the
 *        initial credits provided in the L2CAP_CREDIT_BASED_CONNECTION_REQ or
 *        L2CAP_CREDIT_BASED_CONNECTION_RSP packet. The device sending the
 *        L2CAP_FLOW_CONTROL_CREDIT_IND packet shall ensure that the number of
 *        credits returned for an L2CAP channel does not cause the credit count
 *        to exceed 65535. The device receiving the credit packet shall
 *        disconnect the L2CAP channel if the credit count exceeds 65535. The
 *        device shall also disconnect the L2CAP channel if it receives a
 *        K-frame on an L2CAP channel from the peer device that has a credit
 *        count of zero. If a device receives an
 *        L2CAP_FLOW_CONTROL_CREDIT_IND packet with credit value set to zero,
 *        the packet shall be ignored. A device shall not send credit values of
 *        zero in L2CAP_FLOW_CONTROL_CREDIT_IND packets."
 *
 *     Read carefully, that paragraph says credits "may be returned at any
 *     time".  It does NOT say credits may be withheld until an SDU completes.
 *     A receiver that only replenishes on SDU completion can starve a peer
 *     whose SDU needs more K-frames than the initial credit grant.
 *
 * REFERENCE IMPLEMENTATIONS -- when credits are returned
 * -----------------------------------------------------
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac):
 *   subsys/bluetooth/host/l2cap.c:2799-2810 -- on the FIRST K-frame of an SDU,
 *     grants credits sized for the whole remaining SDU,
 *     DIV_ROUND_UP(remaining, mps).
 *   subsys/bluetooth/host/l2cap.c:2657-2671 -- mid-SDU top-up while
 *     reassembling.
 *   subsys/bluetooth/host/l2cap.c:2580 -- bt_l2cap_chan_recv_complete() grants
 *     from the application's consume point, so credits track buffer space.
 *
 * NIMBLE (1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845):
 *   nimble/host/src/ble_l2cap_coc.c:302-308 -- grants one credit per K-frame
 *     consumed, mid-SDU included.
 *   nimble/host/src/ble_l2cap_coc.c:649 -- ble_l2cap_coc_recv_ready() is the
 *     application-driven grant.
 *
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1): the ECRED state
 *   machine lives in the Linux kernel (net/bluetooth/l2cap_core.c), which is
 *   NOT present in the cloned tree -- no BlueZ behavioural citation is made
 *   here.  The userspace tree carries only the wire structs, the btmon
 *   decoder, and the bthost peer emulator; bthost grants one credit per
 *   K-frame received (tools/bthost.c:3159-3182), mid-SDU included.
 *
 * All three of the available references therefore return credits per K-frame
 * or better, never only on SDU completion.
 */

#ifndef SPEC_EXTREF_L2CAP_ECFC_H
#define SPEC_EXTREF_L2CAP_ECFC_H

#include <stdint.h>

/* Signalling command codes -- Table 4.2, .txt lines 52078-52102. */
#define SPEC_EXTREF_L2CAP_CMD_FLOW_CONTROL_CREDIT_IND	0x16u
#define SPEC_EXTREF_L2CAP_CMD_CREDIT_BASED_CON_REQ	0x17u
#define SPEC_EXTREF_L2CAP_CMD_CREDIT_BASED_CON_RSP	0x18u
#define SPEC_EXTREF_L2CAP_CMD_CREDIT_RECONFIG_REQ	0x19u
#define SPEC_EXTREF_L2CAP_CMD_CREDIT_RECONFIG_RSP	0x1Au

/* All four are permitted on BOTH signalling channels. */
#define SPEC_EXTREF_L2CAP_SIG_CID_ACL_U			0x0001u
#define SPEC_EXTREF_L2CAP_SIG_CID_LE_U			0x0005u
#define SPEC_EXTREF_L2CAP_ECFC_ON_ACL_U			1
#define SPEC_EXTREF_L2CAP_ECFC_ON_LE_U			1

/* Section 4.25 field ranges. */
#define SPEC_EXTREF_L2CAP_ECFC_MAX_CHANNELS		5u	/* "up to five" */
#define SPEC_EXTREF_L2CAP_ECFC_MTU_MIN			64u
#define SPEC_EXTREF_L2CAP_ECFC_MPS_MIN			64u
#define SPEC_EXTREF_L2CAP_ECFC_MPS_MAX			65533u
#define SPEC_EXTREF_L2CAP_ECFC_INITIAL_CREDITS_MIN	1u
#define SPEC_EXTREF_L2CAP_ECFC_INITIAL_CREDITS_MAX	65535u
#define SPEC_EXTREF_L2CAP_ECFC_CID_ARRAY_MIN_OCTETS	2u
#define SPEC_EXTREF_L2CAP_ECFC_CID_ARRAY_MAX_OCTETS	10u

/* Section 10.2 credit ceiling; exceeding it is a MANDATORY disconnect. */
#define SPEC_EXTREF_L2CAP_ECFC_CREDIT_COUNT_MAX		65535u

/*
 * Table 4.17 Result values, transcribed in full.  The comment on each records
 * whether the specification's own wording is "All" or "Some" -- the
 * distinction that governs whether a per-CID Destination CID array is
 * meaningful in the response.
 */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_ALL_SUCCESS		0x0000u	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_SPSM_UNSUPPORTED	0x0002u	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_SOME_NO_RESOURCES	0x0004u	/* Some */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_NO_AUTHENTICATION	0x0005u	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_NO_AUTHORIZATION	0x0006u	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_KEY_SIZE		0x0007u	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_NO_ENCRYPTION	0x0008u	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_SOME_INVALID_SCID	0x0009u	/* Some */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_SOME_SCID_ALLOCATED	0x000Au	/* Some */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_UNACCEPTABLE_PARAMS	0x000Bu	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_INVALID_PARAMS	0x000Cu	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_PENDING_NO_INFO	0x000Du	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_PENDING_AUTHEN	0x000Eu	/* All  */
#define SPEC_EXTREF_L2CAP_ECFC_RSP_PENDING_AUTHOR	0x000Fu	/* All  */

/* Section 4.26: a zero Destination CID means "this one channel was refused". */
#define SPEC_EXTREF_L2CAP_ECFC_DCID_NOT_ESTABLISHED	0x0000u

/*
 * Non-zero iff the Result code is one whose wording is "Some ...", i.e. one
 * where the Destination CID array carries a per-channel outcome and a
 * conformant requester must accept partial success.
 */
#define SPEC_EXTREF_L2CAP_ECFC_RESULT_IS_PARTIAL(r)			\
	((r) == SPEC_EXTREF_L2CAP_ECFC_RSP_SOME_NO_RESOURCES ||		\
	 (r) == SPEC_EXTREF_L2CAP_ECFC_RSP_SOME_INVALID_SCID ||		\
	 (r) == SPEC_EXTREF_L2CAP_ECFC_RSP_SOME_SCID_ALLOCATED)

/*
 * Section 3.4.3 -- the three conditions on which the receiver SHALL disconnect
 * the channel.  Pinned as flags so a test can assert each is implemented
 * separately rather than assuming one check covers all three.
 */
#define SPEC_EXTREF_L2CAP_ECFC_DISC_SDULEN_GT_MTU	1
#define SPEC_EXTREF_L2CAP_ECFC_DISC_KFRAME_GT_MPS	1
#define SPEC_EXTREF_L2CAP_ECFC_DISC_SUM_GT_SDULEN	1
/* Section 10.2 adds two more mandatory disconnects. */
#define SPEC_EXTREF_L2CAP_ECFC_DISC_CREDITS_GT_65535	1
#define SPEC_EXTREF_L2CAP_ECFC_DISC_KFRAME_AT_ZERO_CRED	1
/* ... and one mandatory silent-ignore. */
#define SPEC_EXTREF_L2CAP_ECFC_IGNORE_ZERO_CREDIT_IND	1

/*
 * Section 4.27 reconfigure constraints.  Both are "shall".
 */
#define SPEC_EXTREF_L2CAP_ECFC_RECFG_MTU_NO_REDUCE	1
/* MPS may only be reduced when exactly one channel is being reconfigured. */
#define SPEC_EXTREF_L2CAP_ECFC_RECFG_MPS_MAY_REDUCE(nchan)	((nchan) == 1)
/* In RECONFIGURE_REQ the CID array holds the SENDER's own endpoints. */
#define SPEC_EXTREF_L2CAP_ECFC_RECFG_CIDS_ARE_SENDERS	1

/*
 * Credit-return timing.  The specification permits returning credits "at any
 * time"; every available reference implementation returns them per K-frame or
 * sooner.  A receiver that returns credits only on SDU completion can stall a
 * peer whose SDU spans more K-frames than the credit grant:
 *
 *   deadlock iff  ceil(sdu_len / peer_mps) > credits_granted
 *
 * With the minimum legal MPS of 64 and a grant of 65 credits, any SDU larger
 * than 65*64 = 4160 octets deadlocks.  This is the check to write a test
 * around; it is not a value taken from our own code.
 */
#define SPEC_EXTREF_L2CAP_ECFC_KFRAMES_FOR_SDU(sdu, mps)		\
	(((sdu) + (mps) - 1u) / (mps))

#endif /* SPEC_EXTREF_L2CAP_ECFC_H */

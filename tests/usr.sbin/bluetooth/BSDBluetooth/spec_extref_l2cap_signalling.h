/*
 * EXTERNAL REFERENCE ORACLE: L2CAP signalling rules (Command Reject, the
 * signalling MTU, per-channel command sets, identifier handling) and the LE
 * fixed-channel sizes for ATT and SMP.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from ng_l2cap.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   (line numbers are lines of that .txt file)
 *
 * --- Vol 3, Part A, Section 4 (.txt lines 51993-52003), verbatim:
 *       "Multiple commands may be sent in a single C-frame over fixed channel
 *        CID 0x0001 while only one command per C-frame shall be sent over
 *        fixed channel CID 0x0005. ... All L2CAP implementations shall support
 *        the reception of C-frames with a payload size that does not exceed
 *        the signaling MTU. The minimum supported payload size for the C-frame
 *        (MTUsig) is defined in Table 4.1. L2CAP implementations should not
 *        use C-frames that exceed the MTUsig of the peer device. If a device
 *        receives a C-frame that exceeds its MTUsig then it shall send an
 *        L2CAP_COMMAND_REJECT_RSP packet containing the supported MTUsig.
 *        Implementations shall be able to handle the reception of multiple
 *        commands in an L2CAP packet sent over fixed channel CID 0x0001."
 *
 * --- Vol 3, Part A, Table 4.1 (.txt lines 52028-52032), verbatim:
 *       "ACL-U not supporting Extended Flow Specification        48 octets
 *        ACL-U supporting the Extended Flow Specification feature 672 octets
 *        LE-U                                                     23 octets"
 *     and Section 4 (.txt lines 51055-51056): MTUsig "corresponds to the
 *     maximum size of a C-frame, omitting the size of the Basic L2CAP header".
 *
 * --- Vol 3, Part A, Section 4 (.txt lines 52064-52068), verbatim:
 *       "When a packet is received with a Code field that is unknown or
 *        disallowed on the signaling channel it is received on, an
 *        L2CAP_COMMAND_REJECT_RSP ... is sent in response"
 *     -- note "or disallowed on the signaling channel it is received on":
 *     a command that is legal on CID 0x0001 must still be rejected when it
 *     arrives on CID 0x0005.  Table 4.2 (.txt lines 52078-52102) is the
 *     code-to-channel map.
 *
 * --- Vol 3, Part A, Section 4 (.txt lines 52122-52126), verbatim:
 *       "A device receiving a duplicate request on a particular signaling
 *        channel should reply with a duplicate response on the same signaling
 *        channel. A command response with an invalid identifier or duplicate
 *        response or indication shall be silently discarded. Signaling
 *        identifier 0x00 is an invalid identifier and shall never be used in
 *        any command."
 *
 * --- Vol 3, Part A, Section 4.1 (.txt lines 52133-52141): a Command Reject
 *     shall be sent for an unknown code or where the corresponding response is
 *     inappropriate; the identifier shall match the rejected command; and
 *       "L2CAP_COMMAND_REJECT_RSP packets should not be sent in response to an
 *        identified response packet."
 *     (SHOULD, not SHALL -- this is why the references differ here.)
 *
 * --- Vol 3, Part A, Section 4.1 (.txt lines 52143-52148): an oversized
 *     multi-command C-frame produces a SINGLE reject whose identifier is that
 *     of the first *request* in the frame; "If only responses are recognized,
 *     the packet shall be silently discarded."
 *
 * --- Vol 3, Part A, Table 4.3 (.txt lines 52168-52173), verbatim:
 *       "0x0000  Command not understood
 *        0x0001  Signaling MTU exceeded
 *        0x0002  Invalid CID in request
 *        Other   Reserved for future use"
 *
 * --- Vol 3, Part A, Section 4.1 Reason Data and Table 4.4 (.txt lines
 *     52176-52194), verbatim:
 *       "If the Reason code is 0x0000, 'Command not understood', no Reason
 *        Data field is used. If the Reason code is 0x0001, 'Signaling MTU
 *        Exceeded', the 2-octet Reason Data field represents the maximum
 *        signaling MTU the sender of this packet can accept. If a command
 *        refers to an invalid channel then the Reason code 0x0002 will be
 *        returned. ... The Reason Data field shall be 4 octets containing the
 *        local (first) and remote (second) channel endpoints (relative to the
 *        sender of the L2CAP_COMMAND_REJECT_RSP packet) of the disputed
 *        channel. The remote endpoint is the source CID from the rejected
 *        command. The local endpoint is the destination CID from the rejected
 *        command. If the rejected command contains only one of the channel
 *        endpoints, the other one shall be replaced by the null CID 0x0000."
 *       Table 4.4:  0x0000 -> 0 octets
 *                   0x0001 -> 2 octets, Actual MTUsig
 *                   0x0002 -> 4 octets, Requested CIDs
 *
 * --- Vol 3, Part A, Section 3.1 (.txt line 51866), verbatim:
 *       "Check the CID. If the PDU contains an unknown CID then it shall be
 *        ignored."
 *     Discard, not disconnect.
 *
 * --- Vol 3, Part A, Sections 6.2.1 and 6.2.2 (.txt lines 54751-54810): the
 *     RTX timer has a minimum initial value of 1 s and a maximum initial value
 *     of 60 s, doubling on each retransmission; the ERTX timer has a minimum
 *     initial value of 60 s and a maximum initial value of 300 s.  60 s / 300 s
 *     are the maxima of the legal ranges, not the mandated values.
 *
 * --- Vol 3, Part H, Tables 3.1 and 3.2 (.txt lines 77950-77972): the SMP
 *     fixed channel MTU is 23 without LE Secure Connections and 65 with it.
 *     The ATT fixed channel default ATT_MTU is 23 (Vol 3 Part G, .txt lines
 *     74752-74781) but ATT negotiates upward with the Exchange MTU
 *     sub-procedure, so 23 is an initial value, not a channel ceiling.
 *
 * --- Vol 6, Part B, Section 4.5.2 (.txt lines 140253-140259) and its HCI
 *     restatement in Vol 4 Part E (.txt lines 112863-112866): the connection
 *     supervision timeout constraint, verbatim in the HCI form:
 *       "Supervision_Timeout (ms) > (1 + Max_Latency) x Connection_Interval_Max
 *        x 2"
 *     With Supervision_Timeout in 10 ms units and Connection_Interval in
 *     1.25 ms units this is
 *       timeout * 10 > (1 + latency) * interval * 1.25 * 2
 *     i.e. timeout * 4 > (1 + latency) * interval.
 *     The factor is FOUR.  A validator using eight accepts timeouts half the
 *     required length.  (The Vol 6 form additionally multiplies by
 *     connSubrateFactor, which is 1 unless Connection Subrating is in use.)
 *
 * REFERENCE IMPLEMENTATIONS
 * -------------------------
 * BLUEZ: L2CAP lives in the Linux kernel (net/bluetooth/l2cap_core.c), which
 *   is NOT present in the cloned bluez tree -- verified absent.  The bluez
 *   repository carries only decoders (monitor/l2cap.c, tools/parser/l2cap.c),
 *   the PTS driver (tools/l2cap-tester.c) and the qualification documents.
 *   No BlueZ behavioural claim is made in this header.
 *
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac):
 *   subsys/bluetooth/host/l2cap.c and subsys/bluetooth/host/classic/l2cap_br.c
 *   -- rejects unknown codes with reason 0x0000 on both channels, rejects
 *   identifier 0x00 on receive on both channels, and sizes its BR/EDR
 *   signalling buffer at the 48-octet Table 4.1 floor.
 *
 * NIMBLE (1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845):
 *   nimble/host/src/ble_l2cap_sig.c -- rejects unknown codes via a NULL
 *   dispatch slot; silently drops commands whose length does not match instead
 *   of rejecting them; no-ops rather than rejecting an unexpected response.
 */

#ifndef SPEC_EXTREF_L2CAP_SIGNALLING_H
#define SPEC_EXTREF_L2CAP_SIGNALLING_H

#include <stdint.h>

/* Fixed CIDs, Vol 3 Part A Tables 2.1 and 2.3. */
#define SPEC_EXTREF_L2CAP_CID_NULL		0x0000u
#define SPEC_EXTREF_L2CAP_CID_SIG_ACL_U		0x0001u
#define SPEC_EXTREF_L2CAP_CID_ATT		0x0004u
#define SPEC_EXTREF_L2CAP_CID_SIG_LE_U		0x0005u
#define SPEC_EXTREF_L2CAP_CID_SMP		0x0006u

/* Table 4.1 minimum MTUsig, excluding the 4-octet basic L2CAP header. */
#define SPEC_EXTREF_L2CAP_MTUSIG_ACL_U		48u
#define SPEC_EXTREF_L2CAP_MTUSIG_ACL_U_EFS	672u
#define SPEC_EXTREF_L2CAP_MTUSIG_LE_U		23u

/* Multiple commands per C-frame: allowed on ACL-U, forbidden on LE-U. */
#define SPEC_EXTREF_L2CAP_MULTI_CMD_ON_ACL_U	1
#define SPEC_EXTREF_L2CAP_MULTI_CMD_ON_LE_U	0

/* Table 4.3 reason codes. */
#define SPEC_EXTREF_L2CAP_REJ_NOT_UNDERSTOOD	0x0000u
#define SPEC_EXTREF_L2CAP_REJ_MTU_EXCEEDED	0x0001u
#define SPEC_EXTREF_L2CAP_REJ_INVALID_CID	0x0002u

/* Table 4.4 reason-data lengths, in octets. */
#define SPEC_EXTREF_L2CAP_REJ_DATA_LEN(reason)				\
	((reason) == SPEC_EXTREF_L2CAP_REJ_NOT_UNDERSTOOD ? 0u :	\
	 (reason) == SPEC_EXTREF_L2CAP_REJ_MTU_EXCEEDED   ? 2u :	\
	 (reason) == SPEC_EXTREF_L2CAP_REJ_INVALID_CID    ? 4u : 0u)

/*
 * Invalid-CID reason data ordering, relative to the SENDER of the reject:
 * first the local endpoint (= the destination CID of the rejected command),
 * then the remote endpoint (= the source CID of the rejected command), with
 * the null CID substituted for whichever the rejected command omitted.
 */
#define SPEC_EXTREF_L2CAP_REJ_CID_LOCAL_FIRST	1

/* Identifier rules. */
#define SPEC_EXTREF_L2CAP_IDENT_INVALID		0x00u
#define SPEC_EXTREF_L2CAP_IDENT_VALID(i)	((i) != SPEC_EXTREF_L2CAP_IDENT_INVALID)
/* A response with an unmatched identifier is discarded, never rejected. */
#define SPEC_EXTREF_L2CAP_UNMATCHED_RSP_IS_DISCARD	1
/* Rejecting an identified response is discouraged (SHOULD NOT), not forbidden. */
#define SPEC_EXTREF_L2CAP_REJECT_RSP_IS_SHOULD_NOT	1

/* Sections 6.2.1 / 6.2.2 timer bounds, in seconds. */
#define SPEC_EXTREF_L2CAP_RTX_INITIAL_MIN_SEC	1u
#define SPEC_EXTREF_L2CAP_RTX_INITIAL_MAX_SEC	60u
#define SPEC_EXTREF_L2CAP_ERTX_INITIAL_MIN_SEC	60u
#define SPEC_EXTREF_L2CAP_ERTX_INITIAL_MAX_SEC	300u

/* Section 3.1: a PDU on an unknown CID is IGNORED, not a link error. */
#define SPEC_EXTREF_L2CAP_UNKNOWN_CID_IS_DISCARD	1

/*
 * LE fixed-channel sizes.  23 is the ATT_MTU *default*; ATT raises it with the
 * Exchange MTU sub-procedure, so it must not be enforced as a channel ceiling
 * in either direction.  The SMP channel MTU is a fixed configuration value and
 * is 65 whenever LE Secure Connections is supported.
 */
#define SPEC_EXTREF_ATT_MTU_DEFAULT		23u
#define SPEC_EXTREF_ATT_MTU_IS_NEGOTIABLE	1
#define SPEC_EXTREF_SMP_MTU_LEGACY		23u
#define SPEC_EXTREF_SMP_MTU_SC			65u
/* Largest SMP PDU: Pairing Public Key, 1 opcode + 64 key octets. */
#define SPEC_EXTREF_SMP_PDU_MAX_SC		65u

/*
 * Connection supervision timeout constraint, in the native HCI/L2CAP units:
 * timeout in 10 ms units, interval in 1.25 ms units.  The multiplier is 4.
 */
#define SPEC_EXTREF_LE_SUPERVISION_TIMEOUT_OK(timeout, latency, interval)	\
	((uint32_t)(timeout) * 4u > (uint32_t)((latency) + 1u) * (interval))

#endif /* SPEC_EXTREF_L2CAP_SIGNALLING_H */

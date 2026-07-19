/*
 * ng_l2cap_cmds.c
 */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Maksim Yevmenkin <m_evmenkin@yahoo.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: ng_l2cap_cmds.c,v 1.2 2003/09/08 19:11:45 max Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/endian.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_var.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_cmds.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_evnt.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_llpi.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_ulpi.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_misc.h>

/******************************************************************************
 ******************************************************************************
 **                    L2CAP commands processing module
 ******************************************************************************
 ******************************************************************************/

/*
 * LE Credit-Based Flow Control: send continuation K-frames for an SDU.
 *
 * `frag` is the unsent remainder of an SDU as a bare data fragment chain
 * (no L2CAP headers yet).  Segment it into K-frames of at most `mps`
 * bytes of payload, consume one remote credit per frame, and append the
 * resulting ACL packet chains onto con->tx_pkt.  Shared by the initial
 * L2CA_WRITE path and the credit-resume path so both segment identically.
 *
 * ng_l2cap_lp_send() asserts con->tx_pkt == NULL, so we detach the ACL
 * chain the caller already built for this SDU (the earlier K-frames, or
 * anything else queued), let each lp_send build a fresh chain, splice
 * them together, and restore the combined chain into con->tx_pkt before
 * returning on EVERY path.  The caller is responsible for flushing
 * con->tx_pkt to the link afterwards.
 *
 * Ownership: this helper takes ownership of `frag`.
 *   - SDU complete: `frag` fully consumed, returns 0.
 *   - Stall (peer out of credits mid-SDU): remainder parked in
 *     ch->tx_sdu_pending, token/len recorded, returns EINPROGRESS.
 *     This is a WAIT condition per Core Spec Vol 3 Part A Section 10.1,
 *     NOT a disconnect: the K-frames already appended stay queued and
 *     the peer resumes us with an LE Flow Control Credit.
 *   - Fatal error (mbuf alloc / lp_send failure): unsent remainder
 *     freed, returns the errno.
 *
 * lp_send() frees the mbuf it is handed on failure, so on a send error
 * we free only `next_frag` (the still-unsent remainder), never the mbuf
 * we just passed in -- no double free.
 */
int
ng_l2cap_le_coc_tx_frags(ng_l2cap_con_p con, ng_l2cap_chan_p ch,
    struct mbuf *frag, u_int16_t mps, u_int32_t token, u_int16_t sdu_len)
{
	struct mbuf	*saved_tx = NULL;
	struct mbuf	*saved_last = NULL;
	int		 error = 0;

	/*
	 * Detach any ACL chain the caller already built for this SDU so
	 * lp_send's con->tx_pkt == NULL assertion holds.  Reattached
	 * (with the new K-frames spliced on) before every return.
	 */
	saved_tx = con->tx_pkt;
	con->tx_pkt = NULL;
	for (saved_last = saved_tx;
	     saved_last != NULL && saved_last->m_nextpkt != NULL;
	     saved_last = saved_last->m_nextpkt)
		;

	while (frag != NULL) {
		struct mbuf	*next_frag;

		if (ch->credits_remote == 0) {
			/*
			 * Credit exhaustion mid-SDU: STALL, do not
			 * disconnect (Core Spec Vol 3 Part A Section 10.1
			 * -- running out of peer credits is a WAIT
			 * condition).  Park the unsent remainder; the
			 * already-appended K-frames remain queued in
			 * saved_tx for the caller to flush.  We resume
			 * from ng_l2cap_process_flow_control_credit() when
			 * the peer grants more credits.
			 */
			/*
			 * A channel may have only one partially emitted SDU.  Queue
			 * selection normally prevents a second write from reaching
			 * this helper while that SDU is stalled, but keep the helper
			 * safe if a future caller violates that contract: never
			 * overwrite (and leak/reorder) the older remainder.
			 */
			if (ch->tx_sdu_pending != NULL) {
				NG_FREE_M(frag);
				con->tx_pkt = saved_tx;
				return (EBUSY);
			}
			ch->tx_sdu_pending = frag;
			ch->tx_pending_token = token;
			ch->tx_pending_len = sdu_len;
			con->tx_pkt = saved_tx;
			return (EINPROGRESS);
		}

		if (frag->m_pkthdr.len > mps) {
			next_frag = m_split(frag, mps, M_NOWAIT);
			if (next_frag == NULL) {
				/* frag not yet handed to lp_send: free it */
				NG_FREE_M(frag);
				error = ENOBUFS;
				break;
			}
		} else
			next_frag = NULL;

		ch->credits_remote--;
		error = ng_l2cap_lp_send(con, ch->dcid, frag);
		/*
		 * lp_send() consumed `frag` (freeing it on error).  The
		 * still-unsent remainder is next_frag from here on.
		 */
		frag = next_frag;

		if (error != 0) {
			/* No K-frame reached the peer; its credit is unspent. */
			ch->credits_remote++;
			NG_FREE_M(frag);	/* free unsent remainder */
			frag = NULL;
			break;
		}

		/* Splice this K-frame's ACL chain onto the saved chain */
		if (saved_last != NULL)
			saved_last->m_nextpkt = con->tx_pkt;
		else
			saved_tx = con->tx_pkt;
		con->tx_pkt = NULL;

		if (saved_last == NULL)
			saved_last = saved_tx;
		while (saved_last != NULL && saved_last->m_nextpkt != NULL)
			saved_last = saved_last->m_nextpkt;
	}

	/* Restore the combined ACL chain for the caller to flush */
	con->tx_pkt = saved_tx;
	return (error);
} /* ng_l2cap_le_coc_tx_frags */

/*
 * Process L2CAP command queue on connection
 */

void
ng_l2cap_con_wakeup(ng_l2cap_con_p con)
{
	ng_l2cap_p	 l2cap = con->l2cap;
	ng_l2cap_cmd_p	 cmd = NULL;
	struct mbuf	*m = NULL;
	int		 error = 0;

	/*
	 * Find the first runnable command in the queue.  Credit-based writes
	 * are ordered per channel: once an SDU stalls part-way through, later
	 * socket records for that channel must remain queued until its parked
	 * remainder is completely emitted.  Commands for other channels may
	 * still make progress while this channel waits for credits.
	 */
	TAILQ_FOREACH(cmd, &con->cmd_list, next) {
		KASSERT((cmd->con == con),
("%s: %s - invalid connection pointer!\n",
			__func__, NG_NODE_NAME(con->l2cap->node)));

		if (cmd->flags & NG_L2CAP_CMD_PENDING)
			continue;
		if (cmd->code == NGM_L2CAP_L2CA_WRITE && cmd->ch != NULL &&
		    cmd->ch->tx_sdu_pending != NULL)
			continue;
		break;
	}

	if (cmd == NULL)
		return;

	/* Detach command packet */
	m = cmd->aux;
	cmd->aux = NULL;

	/* Process command */
	switch (cmd->code) {
	case NG_L2CAP_DISCON_RSP:
	case NG_L2CAP_ECHO_RSP:
	case NG_L2CAP_INFO_RSP:
		/*
		 * Do not check return ng_l2cap_lp_send() value, because
		 * in these cases we do not really have a graceful way out.
		 * ECHO and INFO responses are internal to the stack and not
		 * visible to user. REJect is just being nice to remote end
		 * (otherwise remote end will timeout anyway). DISCON is
		 * probably most interesting here, however, if it fails
		 * there is nothing we can do anyway.
		 */

		(void) ng_l2cap_lp_send(con,
				(con->linktype == NG_HCI_LINK_ACL) ?
				NG_L2CAP_SIGNAL_CID :
				NG_L2CAP_LESIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		ng_l2cap_free_cmd(cmd);
		break;
	case NG_L2CAP_CMD_REJ:
		(void) ng_l2cap_lp_send(con,
					(con->linktype == NG_HCI_LINK_ACL)?
					NG_L2CAP_SIGNAL_CID:
					NG_L2CAP_LESIGNAL_CID
					, m);
		ng_l2cap_unlink_cmd(cmd);
		ng_l2cap_free_cmd(cmd);
		break;
		
	case NG_L2CAP_CON_REQ:
		error = ng_l2cap_lp_send(con, NG_L2CAP_SIGNAL_CID, m);
		if (error != 0) {
			ng_l2cap_l2ca_con_rsp(cmd->ch, cmd->token,
				NG_L2CAP_NO_RESOURCES, 0);
			ng_l2cap_free_chan(cmd->ch); /* will free commands */
		} else
			ng_l2cap_command_timeout(cmd,
				bluetooth_l2cap_rtx_timeout());
		break;
	case NG_L2CAP_CON_RSP:
		error = ng_l2cap_lp_send(con, NG_L2CAP_SIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		if (cmd->ch != NULL) {
			ng_l2cap_l2ca_con_rsp_rsp(cmd->ch, cmd->token,
				(error == 0)? NG_L2CAP_SUCCESS : 
					NG_L2CAP_NO_RESOURCES);
			if (error != 0)
				ng_l2cap_free_chan(cmd->ch);
		}
		ng_l2cap_free_cmd(cmd);
		break;

	case NG_L2CAP_CFG_REQ:
		error = ng_l2cap_lp_send(con, NG_L2CAP_SIGNAL_CID, m);
		if (error != 0) {
			ng_l2cap_l2ca_cfg_rsp(cmd->ch, cmd->token,
				NG_L2CAP_NO_RESOURCES);
			ng_l2cap_unlink_cmd(cmd);
			ng_l2cap_free_cmd(cmd);
		} else
			ng_l2cap_command_timeout(cmd,
				bluetooth_l2cap_rtx_timeout());
		break;

	case NG_L2CAP_CFG_RSP:
		error = ng_l2cap_lp_send(con, NG_L2CAP_SIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		if (cmd->ch != NULL)
			ng_l2cap_l2ca_cfg_rsp_rsp(cmd->ch, cmd->token,
				(error == 0)? NG_L2CAP_SUCCESS :
					NG_L2CAP_NO_RESOURCES);
		ng_l2cap_free_cmd(cmd);
		break;

	case NG_L2CAP_DISCON_REQ:
		error = ng_l2cap_lp_send(con,
		    (con->linktype == NG_HCI_LINK_ACL) ?
		    NG_L2CAP_SIGNAL_CID : NG_L2CAP_LESIGNAL_CID, m);
		ng_l2cap_l2ca_discon_rsp(cmd->ch, cmd->token,
			(error == 0)? NG_L2CAP_SUCCESS : NG_L2CAP_NO_RESOURCES);
		if (error != 0)
			ng_l2cap_free_chan(cmd->ch); /* XXX free channel */
		else
			ng_l2cap_command_timeout(cmd,
				bluetooth_l2cap_rtx_timeout());
		break;

	case NG_L2CAP_ECHO_REQ:
		error = ng_l2cap_lp_send(con, NG_L2CAP_SIGNAL_CID, m);
		if (error != 0) {
			ng_l2cap_l2ca_ping_rsp(con, cmd->token,
					NG_L2CAP_NO_RESOURCES, NULL);
			ng_l2cap_unlink_cmd(cmd);
			ng_l2cap_free_cmd(cmd);
		} else
			ng_l2cap_command_timeout(cmd, 
				bluetooth_l2cap_rtx_timeout());
		break;

	case NG_L2CAP_INFO_REQ:
		error = ng_l2cap_lp_send(con, NG_L2CAP_SIGNAL_CID, m);
		if (error != 0) {
			ng_l2cap_l2ca_get_info_rsp(con, cmd->token, 
				NG_L2CAP_NO_RESOURCES, NULL);
			ng_l2cap_unlink_cmd(cmd);
			ng_l2cap_free_cmd(cmd);
		} else
			ng_l2cap_command_timeout(cmd, 
				bluetooth_l2cap_rtx_timeout());
		break;

	case NGM_L2CAP_L2CA_WRITE: {
		int	length = m->m_pkthdr.len;

		if (cmd->ch->dcid == NG_L2CAP_CLT_CID) {
			m = ng_l2cap_prepend(m, sizeof(ng_l2cap_clt_hdr_t));
			if (m == NULL)
				error = ENOBUFS;
			else
                		mtod(m, ng_l2cap_clt_hdr_t *)->psm =
							htole16(cmd->ch->psm);
		} else if ((cmd->ch->idtype == NG_L2CAP_L2CA_IDTYPE_LE ||
			   cmd->ch->idtype == NG_L2CAP_L2CA_IDTYPE_ECBFC) &&
			   cmd->ch->mps_remote > 0) {
			/*
			 * LE Credit Based Flow Control mode:
			 * Segment the SDU into K-frames per Core Spec
			 * Vol 3 Part A Section 3.4.3.  The first K-frame
			 * carries a 2-byte SDU Length field; continuation
			 * K-frames do not.  Each K-frame consumes one
			 * credit from the remote peer's allowance.
			 *
			 * ng_l2cap_lp_send() asserts con->tx_pkt == NULL,
			 * so after each call we save the resulting ACL
			 * chain and restore it at the end.
			 */
			u_int16_t	sdu_len = m->m_pkthdr.len;
			u_int16_t	mps = cmd->ch->mps_remote;
			u_int16_t	first_payload;
			struct mbuf	*frag;

			/* Sanity check MPS to avoid underflow in (mps - 2) */
			if (mps < 2) {
				NG_FREE_M(m);
				error = EINVAL;
				goto le_coc_write_done;
			}

			/* Check we have at least one credit */
			if (cmd->ch->credits_remote == 0) {
				NG_FREE_M(m);
				error = ENOBUFS;
				goto le_coc_write_done;
			}

			/*
			 * First K-frame: SDU Length (2 bytes) + data.
			 * Payload (after L2CAP header) must be <= MPS.
			 * So first frame carries at most MPS-2 bytes of
			 * SDU data.
			 */
			first_payload = (sdu_len > (mps - 2)) ?
			    (mps - 2) : sdu_len;

			/* Split off the remainder after first_payload */
			if (m->m_pkthdr.len > first_payload) {
				frag = m_split(m, first_payload, M_NOWAIT);
				if (frag == NULL) {
					NG_FREE_M(m);
					error = ENOBUFS;
					goto le_coc_write_done;
				}
			} else
				frag = NULL;

			/* Prepend SDU Length to first fragment */
			m = ng_l2cap_prepend(m, sizeof(u_int16_t));
			if (m == NULL) {
				NG_FREE_M(frag);
				error = ENOBUFS;
				goto le_coc_write_done;
			}
			*mtod(m, u_int16_t *) = htole16(sdu_len);

			/* Send first K-frame */
			cmd->ch->credits_remote--;
			error = ng_l2cap_lp_send(con, cmd->ch->dcid, m);
			m = NULL;
			if (error != 0) {
				/* lp_send rejected the K-frame, so retain its credit. */
				cmd->ch->credits_remote++;
				NG_FREE_M(frag);
				goto le_coc_write_done;
			}

			/*
			 * Send the continuation K-frames.  con->tx_pkt
			 * currently holds the first K-frame's ACL chain;
			 * the helper saves/restores it around each send,
			 * splices the continuation frames on, and either
			 * completes the SDU, stalls on credit exhaustion,
			 * or fails.  On every outcome con->tx_pkt is left
			 * holding the frames we did emit, for our caller
			 * (ng_l2cap_lp_deliver) to flush.
			 */
			error = ng_l2cap_le_coc_tx_frags(con, cmd->ch, frag,
			    mps, cmd->token, length);

			if (error == EINPROGRESS) {
				/*
				 * Stalled mid-SDU: the peer ran out of TX
				 * credits.  Per Core Spec Vol 3 Part A
				 * §10.1 this is a WAIT condition, NOT a
				 * disconnect.  The K-frames within credit
				 * are queued in con->tx_pkt; the remainder
				 * is parked in cmd->ch->tx_sdu_pending and
				 * will be sent when the peer grants credits
				 * (ng_l2cap_process_flow_control_credit).
				 * Defer the L2CA_WRITE response until the
				 * SDU completes.  token and length are now
				 * captured in the channel, so reclaim the
				 * command.
				 */
				ng_l2cap_unlink_cmd(cmd);
				ng_l2cap_free_cmd(cmd);
				break;
			}

le_coc_write_done:
			ng_l2cap_l2ca_write_rsp(cmd->ch, cmd->token,
			    (error == 0) ? NG_L2CAP_SUCCESS :
			    NG_L2CAP_NO_RESOURCES, length);

			ng_l2cap_unlink_cmd(cmd);
			ng_l2cap_free_cmd(cmd);
			break;
		}

		if (error == 0)
			error = ng_l2cap_lp_send(con, cmd->ch->dcid, m);

		ng_l2cap_l2ca_write_rsp(cmd->ch, cmd->token,
			(error == 0)? NG_L2CAP_SUCCESS : NG_L2CAP_NO_RESOURCES,
			length);

		ng_l2cap_unlink_cmd(cmd);
		ng_l2cap_free_cmd(cmd);
		} break;
	case NG_L2CAP_CMD_PARAM_UPDATE_RESPONSE:
		error = ng_l2cap_lp_send(con, NG_L2CAP_LESIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		ng_l2cap_free_cmd(cmd);
		break;

	case NG_L2CAP_LE_CREDIT_CON_REQ:
		error = ng_l2cap_lp_send(con, NG_L2CAP_LESIGNAL_CID, m);
		if (error != 0) {
			ng_l2cap_l2ca_con_rsp(cmd->ch, cmd->token,
				NG_L2CAP_NO_RESOURCES, 0);
			ng_l2cap_free_chan(cmd->ch);
		} else
			ng_l2cap_command_timeout(cmd,
				bluetooth_l2cap_rtx_timeout());
		break;

	case NG_L2CAP_LE_CREDIT_CON_RSP:
		error = ng_l2cap_lp_send(con, NG_L2CAP_LESIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		if (cmd->ch != NULL) {
			(void)ng_l2cap_l2ca_con_rsp_rsp(cmd->ch, cmd->token,
			    error == 0 ? NG_L2CAP_SUCCESS : NG_L2CAP_NO_RESOURCES);
			if (error != 0) {
				ng_l2cap_l2ca_discon_ind(cmd->ch);
				ng_l2cap_free_chan(cmd->ch);
			}
		}
		ng_l2cap_free_cmd(cmd);
		break;

	case NG_L2CAP_CREDIT_CON_REQ:
		/*
		 * Enhanced Credit Based Connection Request (0x17):
		 * needs linktype-based CID + timeout, like LE CoC.
		 */
		error = ng_l2cap_lp_send(con,
		    (con->linktype == NG_HCI_LINK_ACL) ?
		    NG_L2CAP_SIGNAL_CID : NG_L2CAP_LESIGNAL_CID, m);
		if (error != 0) {
			ng_l2cap_l2ca_con_rsp(cmd->ch, cmd->token,
				NG_L2CAP_NO_RESOURCES, 0);
			ng_l2cap_free_chan(cmd->ch);
		} else
			ng_l2cap_command_timeout(cmd,
				bluetooth_l2cap_rtx_timeout());
		break;

	case NG_L2CAP_CREDIT_RECONFIG_REQ:
		/*
		 * Enhanced Credit Based Reconfigure Request (0x19) is a
		 * *request*: it expects a matching Reconfigure Response
		 * (0x1A) from the peer.  Like CFG_REQ/CREDIT_CON_REQ it must
		 * stay PENDING with an RTX timer so the response can be paired
		 * via ng_l2cap_cmd_by_ident() -- which only matches PENDING
		 * commands.  Freeing it here (as a fire-and-forget response
		 * would) drops the response and wedges the channel at
		 * reconfig_pending forever (spec Vol 3 Part A Section 4.27).
		 * Valid on both CID 0x0001 (BR/EDR) and 0x0005 (LE) per
		 * Table 4.2, so select the signaling CID by link type.
		 */
		error = ng_l2cap_lp_send(con,
		    (con->linktype == NG_HCI_LINK_ACL) ?
		    NG_L2CAP_SIGNAL_CID : NG_L2CAP_LESIGNAL_CID, m);
		if (error != 0) {
			/*
			 * Never reached the peer: clear the guard so a later
			 * reconfigure is not rejected with EBUSY, then drop
			 * the command.
			 */
			if (cmd->ch != NULL)
				cmd->ch->reconfig_pending = 0;
			ng_l2cap_unlink_cmd(cmd);
			ng_l2cap_free_cmd(cmd);
		} else
			ng_l2cap_command_timeout(cmd,
				bluetooth_l2cap_rtx_timeout());
		break;

	case NG_L2CAP_FLOW_CONTROL_CREDIT:
		error = ng_l2cap_lp_send(con,
		    (con->linktype == NG_HCI_LINK_ACL) ?
		    NG_L2CAP_SIGNAL_CID : NG_L2CAP_LESIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		if (error != 0 && cmd->ch != NULL) {
			/* The grant never reached the peer: restore wire accounting. */
			if (cmd->ch->credits_local >= cmd->token)
				cmd->ch->credits_local -= cmd->token;
			ng_l2cap_l2ca_discon_ind(cmd->ch);
			ng_l2cap_free_chan(cmd->ch);
		}
		ng_l2cap_free_cmd(cmd);
		break;

	case NG_L2CAP_CREDIT_CON_RSP:
		error = ng_l2cap_lp_send(con,
		    (con->linktype == NG_HCI_LINK_ACL) ?
		    NG_L2CAP_SIGNAL_CID : NG_L2CAP_LESIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		if (cmd->ecbfc_group_id != 0) {
			ng_l2cap_chan_p ch, ch_next;

			LIST_FOREACH_SAFE(ch, &l2cap->chan_list, next, ch_next) {
				if (ch->con == con &&
				    ch->idtype == NG_L2CAP_L2CA_IDTYPE_ECBFC &&
				    ch->ecbfc_group_id == cmd->ecbfc_group_id) {
					if (error != 0) {
						ng_l2cap_l2ca_discon_ind(ch);
						ng_l2cap_free_chan(ch);
					} else {
						/* The signaling transaction is complete. */
						ch->ident = 0;
						ch->ecbfc_group_id = 0;
						ch->ecbfc_group_count = 0;
						ch->ecbfc_group_index = 0;
						ch->ecbfc_response_seen = 0;
						ch->ecbfc_response_result = 0;
					}
				}
			}
		}
		ng_l2cap_free_cmd(cmd);
		break;

	case NG_L2CAP_CREDIT_RECONFIG_RSP:
		/*
		 * Codes 0x16-0x1A are valid on both CID 0x0001 (BR/EDR)
		 * and CID 0x0005 (LE) per spec Table 4.2.  Select the
		 * correct signaling CID based on the link type.  These are
		 * terminal (a credit grant, or a response we are sending);
		 * no reply is expected, so free after send.
		 */
		(void) ng_l2cap_lp_send(con,
		    (con->linktype == NG_HCI_LINK_ACL) ?
		    NG_L2CAP_SIGNAL_CID : NG_L2CAP_LESIGNAL_CID, m);
		ng_l2cap_unlink_cmd(cmd);
		ng_l2cap_free_cmd(cmd);
		break;

	case NG_L2CAP_CMD_PARAM_UPDATE_REQUEST:
		/* TBD -- for now, clean up the unsent command */
		NG_FREE_M(m);
		ng_l2cap_unlink_cmd(cmd);
		ng_l2cap_free_cmd(cmd);
		break;

	default:
		NG_L2CAP_ERR(
"%s: %s - unexpected command code=%d\n",
			__func__, NG_NODE_NAME(l2cap->node), cmd->code);
		NG_FREE_M(m);
		ng_l2cap_unlink_cmd(cmd);
		ng_l2cap_free_cmd(cmd);
		break;
	}
} /* ng_l2cap_con_wakeup */

/*
 * We have failed to open ACL connection to the remote unit. Could be negative
 * confirmation or timeout. So fail any "delayed" commands, notify upper layer,
 * remove all channels and remove connection descriptor.
 */

void
ng_l2cap_con_fail(ng_l2cap_con_p con, u_int16_t result)
{
	ng_l2cap_p	l2cap = con->l2cap;
	ng_l2cap_cmd_p	cmd = NULL;
	ng_l2cap_chan_p	ch = NULL;

	NG_L2CAP_INFO(
"%s: %s - ACL connection failed, result=%d\n",
		__func__, NG_NODE_NAME(l2cap->node), result);

	/* Connection is dying */
	con->flags |= NG_L2CAP_CON_DYING;

	/* Clean command queue */
	while (!TAILQ_EMPTY(&con->cmd_list)) {
		cmd = TAILQ_FIRST(&con->cmd_list);

		ng_l2cap_unlink_cmd(cmd);
		if (cmd->flags & NG_L2CAP_CMD_PENDING)
			ng_l2cap_command_untimeout(cmd);

		KASSERT((cmd->con == con),
("%s: %s - invalid connection pointer!\n",
			__func__, NG_NODE_NAME(l2cap->node)));

		switch (cmd->code) {
		case NG_L2CAP_CMD_REJ:
		case NG_L2CAP_DISCON_RSP:
		case NG_L2CAP_ECHO_RSP:
		case NG_L2CAP_INFO_RSP:
		case NG_L2CAP_CMD_PARAM_UPDATE_RESPONSE:
		case NG_L2CAP_LE_CREDIT_CON_RSP:
			break;

		case NG_L2CAP_CON_REQ:
		case NG_L2CAP_LE_CREDIT_CON_REQ:
		case NG_L2CAP_CREDIT_CON_REQ:
			ng_l2cap_l2ca_con_rsp(cmd->ch, cmd->token, result, 0);
			break;

		case NG_L2CAP_CON_RSP:
			if (cmd->ch != NULL)
				ng_l2cap_l2ca_con_rsp_rsp(cmd->ch, cmd->token,
					result);
			break;

		case NG_L2CAP_CFG_REQ:
		case NG_L2CAP_CFG_RSP:
		case NGM_L2CAP_L2CA_WRITE:
			ng_l2cap_l2ca_discon_ind(cmd->ch);
			break;

		case NG_L2CAP_DISCON_REQ:
			ng_l2cap_l2ca_discon_rsp(cmd->ch, cmd->token,
				NG_L2CAP_SUCCESS);
			break;

		case NG_L2CAP_ECHO_REQ:
			ng_l2cap_l2ca_ping_rsp(cmd->con, cmd->token,
				result, NULL);
			break;

		case NG_L2CAP_INFO_REQ:
			ng_l2cap_l2ca_get_info_rsp(cmd->con, cmd->token,
				result, NULL);
			break;

		case NG_L2CAP_FLOW_CONTROL_CREDIT:
		case NG_L2CAP_CMD_PARAM_UPDATE_REQUEST:
		case NG_L2CAP_CREDIT_CON_RSP:
		case NG_L2CAP_CREDIT_RECONFIG_RSP:
			break;

		default:
			NG_L2CAP_ERR(
"%s: %s - unexpected command code=%d\n",
				__func__, NG_NODE_NAME(l2cap->node), cmd->code);
			break;
		}

		if (cmd->ch != NULL)
			ng_l2cap_free_chan(cmd->ch);

		ng_l2cap_free_cmd(cmd);
	}

	/*
	 * There still might be channels (in OPEN state?) that
	 * did not submit any commands, so disconnect them
	 */

	LIST_FOREACH(ch, &l2cap->chan_list, next)
		if (ch->con == con)
			ng_l2cap_l2ca_discon_ind(ch);

	/* Free connection descriptor */
	ng_l2cap_free_con(con);
} /* ng_l2cap_con_fail */

/*
 * Process L2CAP command timeout. In general - notify upper layer and destroy
 * channel. Do not pay much attention to return code, just do our best.
 */

void
ng_l2cap_process_command_timeout(node_p node, hook_p hook, void *arg1, int arg2)
{
	ng_l2cap_p	l2cap = NULL;
	ng_l2cap_con_p	con = NULL;
	ng_l2cap_cmd_p	cmd = NULL;
	u_int16_t	con_handle = (arg2 & 0x0ffff);
	u_int8_t	ident = ((arg2 >> 16) & 0xff);

	if (NG_NODE_NOT_VALID(node)) {
		printf("%s: Netgraph node is not valid\n", __func__);
		return;
	}

	l2cap = (ng_l2cap_p) NG_NODE_PRIVATE(node);

	con = ng_l2cap_con_by_handle(l2cap, con_handle);
	if (con == NULL) {
		NG_L2CAP_ALERT(
"%s: %s - could not find connection, con_handle=%d\n",
			__func__, NG_NODE_NAME(node), con_handle);
		return;
	}

	cmd = ng_l2cap_cmd_by_ident(con, ident);
	if (cmd == NULL) {
		NG_L2CAP_ALERT(
"%s: %s - could not find command, con_handle=%d, ident=%d\n",
			__func__, NG_NODE_NAME(node), con_handle, ident);
		return;
	}

	cmd->flags &= ~NG_L2CAP_CMD_PENDING;
	ng_l2cap_unlink_cmd(cmd);

	switch (cmd->code) {
 	case NG_L2CAP_CON_REQ:
	case NG_L2CAP_LE_CREDIT_CON_REQ:
	case NG_L2CAP_CREDIT_CON_REQ:
		ng_l2cap_l2ca_con_rsp(cmd->ch, cmd->token, NG_L2CAP_TIMEOUT, 0);
		ng_l2cap_free_chan(cmd->ch);
		break;

	case NG_L2CAP_CFG_REQ:
		ng_l2cap_l2ca_cfg_rsp(cmd->ch, cmd->token, NG_L2CAP_TIMEOUT);
		break;

 	case NG_L2CAP_DISCON_REQ:
		ng_l2cap_l2ca_discon_rsp(cmd->ch, cmd->token, NG_L2CAP_TIMEOUT);
		ng_l2cap_free_chan(cmd->ch); /* XXX free channel */
		break;

	case NG_L2CAP_ECHO_REQ:
		/* Echo request timed out. Let the upper layer know */
		ng_l2cap_l2ca_ping_rsp(cmd->con, cmd->token,
			NG_L2CAP_TIMEOUT, NULL);
		break;

	case NG_L2CAP_INFO_REQ:
		/* Info request timed out. Let the upper layer know */
		ng_l2cap_l2ca_get_info_rsp(cmd->con, cmd->token,
			NG_L2CAP_TIMEOUT, NULL);
		break;

	case NG_L2CAP_CREDIT_RECONFIG_REQ:
		/*
		 * Reconfigure Response never arrived: clear the guard so a
		 * subsequent reconfigure is not rejected with EBUSY.  The
		 * pending MTU/MPS are discarded (never applied), so the
		 * channel keeps its pre-request values (spec Vol 3 Part A
		 * Section 4.27).
		 */
		if (cmd->ch != NULL)
			cmd->ch->reconfig_pending = 0;
		break;

	case NG_L2CAP_FLOW_CONTROL_CREDIT:
	case NG_L2CAP_CMD_PARAM_UPDATE_REQUEST:
	case NG_L2CAP_CMD_PARAM_UPDATE_RESPONSE:
		break;

	default:
		NG_L2CAP_ERR(
"%s: %s - unexpected command code=%d\n",
			__func__, NG_NODE_NAME(l2cap->node), cmd->code);
		break;
	}

	ng_l2cap_free_cmd(cmd);
} /* ng_l2cap_process_command_timeout */

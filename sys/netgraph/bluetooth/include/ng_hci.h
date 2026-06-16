/*
 * ng_hci.h
 */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 Maksim Yevmenkin <m_evmenkin@yahoo.com>
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
 * $Id: ng_hci.h,v 1.2 2003/03/18 00:09:37 max Exp $
 */

/*
 * This file contains everything that application needs to know about
 * Host Controller Interface (HCI). All information was obtained from
 * Bluetooth Specification Book v1.1.
 *
 * This file can be included by both kernel and userland applications.
 *
 * NOTE: Here and after Bluetooth device is called a "unit". Bluetooth
 *       specification refers to both devices and units. They are the
 *       same thing (i think), so to be consistent word "unit" will be
 *       used.
 */

#ifndef _NETGRAPH_HCI_H_
#define _NETGRAPH_HCI_H_

/**************************************************************************
 **************************************************************************
 **     Netgraph node hook name, type name and type cookie and commands
 **************************************************************************
 **************************************************************************/

/* Node type name and type cookie */
#define NG_HCI_NODE_TYPE			"hci"
#define NGM_HCI_COOKIE				1000774184

/* Netgraph node hook names */
#define NG_HCI_HOOK_DRV				"drv" /* Driver <-> HCI */
#define NG_HCI_HOOK_ACL				"acl" /* HCI <-> Upper */
#define NG_HCI_HOOK_SCO				"sco" /* HCI <-> Upper */ 
#define NG_HCI_HOOK_RAW				"raw" /* HCI <-> Upper */ 

/**************************************************************************
 **************************************************************************
 **                   Common defines and types (HCI)
 **************************************************************************
 **************************************************************************/

/* All sizes are in bytes */
#define NG_HCI_BDADDR_SIZE			6   /* unit address */
#define NG_HCI_LAP_SIZE				3   /* unit LAP */
#define NG_HCI_KEY_SIZE				16  /* link key */
#define NG_HCI_PIN_SIZE				16  /* link PIN */
#define NG_HCI_EVENT_MASK_SIZE			8   /* event mask */
#define NG_HCI_LE_EVENT_MASK_SIZE		8   /* event mask */
#define NG_HCI_CLASS_SIZE			3   /* unit class */
#define NG_HCI_FEATURES_SIZE			8   /* LMP features */
#define NG_HCI_UNIT_NAME_SIZE			248 /* unit name size */
#define NG_HCI_COMMANDS_SIZE			64  /*Command list BMP size*/
#define NG_HCI_EXTINQ_MAX			240 /**/
/* HCI specification */
#define NG_HCI_SPEC_V10				0x00 /* v1.0 */
#define NG_HCI_SPEC_V11				0x01 /* v1.1 */
/* 0x02 - 0xFF - reserved for future use */

/* LMP features */
/* ------------------- byte 0 --------------------*/
#define NG_HCI_LMP_3SLOT			0x01
#define NG_HCI_LMP_5SLOT			0x02
#define NG_HCI_LMP_ENCRYPTION			0x04
#define NG_HCI_LMP_SLOT_OFFSET			0x08
#define NG_HCI_LMP_TIMING_ACCURACY		0x10
#define NG_HCI_LMP_SWITCH			0x20
#define NG_HCI_LMP_HOLD_MODE			0x40
#define NG_HCI_LMP_SNIFF_MODE			0x80
/* ------------------- byte 1 --------------------*/
#define NG_HCI_LMP_PARK_MODE			0x01
#define NG_HCI_LMP_RSSI				0x02
#define NG_HCI_LMP_CHANNEL_QUALITY		0x04
#define NG_HCI_LMP_SCO_LINK			0x08
#define NG_HCI_LMP_HV2_PKT			0x10
#define NG_HCI_LMP_HV3_PKT			0x20
#define NG_HCI_LMP_ULAW_LOG			0x40
#define NG_HCI_LMP_ALAW_LOG			0x80
/* ------------------- byte 2 --------------------*/
#define NG_HCI_LMP_CVSD				0x01
#define NG_HCI_LMP_PAGING_SCHEME		0x02
#define NG_HCI_LMP_POWER_CONTROL		0x04
#define NG_HCI_LMP_TRANSPARENT_SCO		0x08
#define NG_HCI_LMP_FLOW_CONTROL_LAG0		0x10
#define NG_HCI_LMP_FLOW_CONTROL_LAG1		0x20
#define NG_HCI_LMP_FLOW_CONTROL_LAG2		0x40
/* ------------------- byte 6 --------------------*/
#define	NG_HCI_LMP_SECURE_SIMPLE_PAIRING	0x08

/* Link types */
#define NG_HCI_LINK_SCO				0x00 /* Voice */
#define NG_HCI_LINK_ACL				0x01 /* Data */
#define NG_HCI_LINK_LE_PUBLIC			0x02 /* LE Public*/
#define NG_HCI_LINK_LE_RANDOM			0x03 /* LE Random*/
#define NG_HCI_LINK_ISO_CIS			0x05 /* CIS (Connected Isochronous) */
#define NG_HCI_LINK_ISO_BIS			0x06 /* BIS (Broadcast Isochronous) */

/* Packet types */
				/* 0x0001 - 0x0004 - reserved for future use */
#define NG_HCI_PKT_DM1				0x0008 /* ACL link */
#define NG_HCI_PKT_DH1				0x0010 /* ACL link */
#define NG_HCI_PKT_HV1				0x0020 /* SCO link */
#define NG_HCI_PKT_HV2				0x0040 /* SCO link */
#define NG_HCI_PKT_HV3				0x0080 /* SCO link */
				/* 0x0100 - 0x0200 - reserved for future use */
#define NG_HCI_PKT_DM3				0x0400 /* ACL link */
#define NG_HCI_PKT_DH3				0x0800 /* ACL link */
				/* 0x1000 - 0x2000 - reserved for future use */
#define NG_HCI_PKT_DM5				0x4000 /* ACL link */
#define NG_HCI_PKT_DH5				0x8000 /* ACL link */

/* 
 * Connection modes/Unit modes
 *
 * This is confusing. It means that one of the units change its mode
 * for the specific connection. For example one connection was put on 
 * hold (but i could be wrong :) 
 */

#define NG_HCI_UNIT_MODE_ACTIVE			0x00
#define NG_HCI_UNIT_MODE_HOLD			0x01
#define NG_HCI_UNIT_MODE_SNIFF			0x02
#define NG_HCI_UNIT_MODE_PARK			0x03
/* 0x04 - 0xFF - reserved for future use */

/* Page scan modes */
#define NG_HCI_MANDATORY_PAGE_SCAN_MODE		0x00
#define NG_HCI_OPTIONAL_PAGE_SCAN_MODE1		0x01
#define NG_HCI_OPTIONAL_PAGE_SCAN_MODE2		0x02
#define NG_HCI_OPTIONAL_PAGE_SCAN_MODE3		0x03
/* 0x04 - 0xFF - reserved for future use */

/* Page scan repetition modes */
#define NG_HCI_SCAN_REP_MODE0			0x00
#define NG_HCI_SCAN_REP_MODE1			0x01
#define NG_HCI_SCAN_REP_MODE2			0x02
/* 0x03 - 0xFF - reserved for future use */

/* Page scan period modes */
#define NG_HCI_PAGE_SCAN_PERIOD_MODE0		0x00
#define NG_HCI_PAGE_SCAN_PERIOD_MODE1		0x01
#define NG_HCI_PAGE_SCAN_PERIOD_MODE2		0x02
/* 0x03 - 0xFF - reserved for future use */

/* Scan enable */
#define NG_HCI_NO_SCAN_ENABLE			0x00
#define NG_HCI_INQUIRY_ENABLE_PAGE_DISABLE	0x01
#define NG_HCI_INQUIRY_DISABLE_PAGE_ENABLE	0x02
#define NG_HCI_INQUIRY_ENABLE_PAGE_ENABLE	0x03
/* 0x04 - 0xFF - reserved for future use */

/* Hold mode activities */
#define NG_HCI_HOLD_MODE_NO_CHANGE		0x00
#define NG_HCI_HOLD_MODE_SUSPEND_PAGE_SCAN	0x01
#define NG_HCI_HOLD_MODE_SUSPEND_INQUIRY_SCAN	0x02
#define NG_HCI_HOLD_MODE_SUSPEND_PERIOD_INQUIRY	0x04
/* 0x08 - 0x80 - reserved for future use */

/* Connection roles */
#define NG_HCI_ROLE_MASTER			0x00
#define NG_HCI_ROLE_SLAVE			0x01
/* 0x02 - 0xFF - reserved for future use */

/* Key flags */
#define NG_HCI_USE_SEMI_PERMANENT_LINK_KEYS	0x00
#define NG_HCI_USE_TEMPORARY_LINK_KEY		0x01
/* 0x02 - 0xFF - reserved for future use */

/* Pin types */
#define NG_HCI_PIN_TYPE_VARIABLE		0x00
#define NG_HCI_PIN_TYPE_FIXED			0x01

/* Link key types */
#define NG_HCI_LINK_KEY_TYPE_COMBINATION_KEY	0x00
#define NG_HCI_LINK_KEY_TYPE_LOCAL_UNIT_KEY	0x01
#define NG_HCI_LINK_KEY_TYPE_REMOTE_UNIT_KEY	0x02
/* 0x03 - 0xFF - reserved for future use */

/* Encryption modes */
#define NG_HCI_ENCRYPTION_MODE_NONE		0x00
#define NG_HCI_ENCRYPTION_MODE_P2P		0x01
#define NG_HCI_ENCRYPTION_MODE_ALL		0x02
/* 0x03 - 0xFF - reserved for future use */

/* Quality of service types */
#define NG_HCI_SERVICE_TYPE_NO_TRAFFIC		0x00
#define NG_HCI_SERVICE_TYPE_BEST_EFFORT		0x01
#define NG_HCI_SERVICE_TYPE_GUARANTEED		0x02
/* 0x03 - 0xFF - reserved for future use */

/* Link policy settings */
#define NG_HCI_LINK_POLICY_DISABLE_ALL_LM_MODES	0x0000
#define NG_HCI_LINK_POLICY_ENABLE_ROLE_SWITCH	0x0001 /* Master/Slave switch */
#define NG_HCI_LINK_POLICY_ENABLE_HOLD_MODE	0x0002
#define NG_HCI_LINK_POLICY_ENABLE_SNIFF_MODE	0x0004
#define NG_HCI_LINK_POLICY_ENABLE_PARK_MODE	0x0008
/* 0x0010 - 0x8000 - reserved for future use */

/* Event masks */
#define NG_HCI_EVMSK_DEFAULT			0x00001fffffffffff
#define NG_HCI_EVMSK_ALL		 	0x1fffffffffffffff	
#define NG_HCI_EVMSK_NONE			0x0000000000000000
#define NG_HCI_EVMSK_INQUIRY_COMPL		0x0000000000000001
#define NG_HCI_EVMSK_INQUIRY_RESULT		0x0000000000000002
#define NG_HCI_EVMSK_CON_COMPL			0x0000000000000004
#define NG_HCI_EVMSK_CON_REQ			0x0000000000000008
#define NG_HCI_EVMSK_DISCON_COMPL		0x0000000000000010
#define NG_HCI_EVMSK_AUTH_COMPL			0x0000000000000020
#define NG_HCI_EVMSK_REMOTE_NAME_REQ_COMPL	0x0000000000000040
#define NG_HCI_EVMSK_ENCRYPTION_CHANGE		0x0000000000000080
#define NG_HCI_EVMSK_CHANGE_CON_LINK_KEY_COMPL	0x0000000000000100
#define NG_HCI_EVMSK_MASTER_LINK_KEY_COMPL	0x0000000000000200
#define NG_HCI_EVMSK_READ_REMOTE_FEATURES_COMPL	0x0000000000000400
#define NG_HCI_EVMSK_READ_REMOTE_VER_INFO_COMPL	0x0000000000000800
#define NG_HCI_EVMSK_QOS_SETUP_COMPL		0x0000000000001000
#define NG_HCI_EVMSK_COMMAND_COMPL		0x0000000000002000
#define NG_HCI_EVMSK_COMMAND_STATUS		0x0000000000004000
#define NG_HCI_EVMSK_HARDWARE_ERROR		0x0000000000008000
#define NG_HCI_EVMSK_FLUSH_OCCUR		0x0000000000010000
#define NG_HCI_EVMSK_ROLE_CHANGE		0x0000000000020000
#define NG_HCI_EVMSK_NUM_COMPL_PKTS		0x0000000000040000
#define NG_HCI_EVMSK_MODE_CHANGE		0x0000000000080000
#define NG_HCI_EVMSK_RETURN_LINK_KEYS		0x0000000000100000
#define NG_HCI_EVMSK_PIN_CODE_REQ		0x0000000000200000
#define NG_HCI_EVMSK_LINK_KEY_REQ		0x0000000000400000
#define NG_HCI_EVMSK_LINK_KEY_NOTIFICATION	0x0000000000800000
#define NG_HCI_EVMSK_LOOPBACK_COMMAND		0x0000000001000000
#define NG_HCI_EVMSK_DATA_BUFFER_OVERFLOW	0x0000000002000000
#define NG_HCI_EVMSK_MAX_SLOT_CHANGE		0x0000000004000000
#define NG_HCI_EVMSK_READ_CLOCK_OFFSET_COMLETE	0x0000000008000000
#define NG_HCI_EVMSK_CON_PKT_TYPE_CHANGED	0x0000000010000000
#define NG_HCI_EVMSK_QOS_VIOLATION		0x0000000020000000
#define NG_HCI_EVMSK_PAGE_SCAN_MODE_CHANGE	0x0000000040000000
#define NG_HCI_EVMSK_PAGE_SCAN_REP_MODE_CHANGE	0x0000000080000000
#define NG_HCI_EVMSK_FLOW_SPEC_COMPL		0x0000000100000000
#define NG_HCI_EVMSK_INQUIRY_RESULT_W_RSSI	0x0000000200000000
#define NG_HCI_EVMSK_READ_REM_EXT_FEAT_COMPL	0x0000000400000000

/* 0x0000000800000000 -	0x0000080000000000 - not in use */ 

#define NG_HCI_EVMSK_SYNC_CONN_COMPL		0x0000100000000000
#define NG_HCI_EVMSK_SYNC_CONN_CHANGED		0x0000200000000000
#define NG_HCI_EVMSK_SNIFF_SUBRATING		0x0000400000000000
#define NG_HCI_EVMSK_EXT_INQUIRY_RESULT		0x0000800000000000
#define NG_HCI_EVMSK_ENC_KEY_REFRESH_COMPL	0x0001000000000000
#define NG_HCI_EVMSK_IO_CAPABILITY_REQ		0x0002000000000000
#define NG_HCI_EVMSK_IO_CAPABILITY_RESP		0x0004000000000000
#define NG_HCI_EVMSK_USER_CONFIRMATION_REQ	0x0008000000000000
#define NG_HCI_EVMSK_USER_PASSKEY_REQ		0x0010000000000000
#define NG_HCI_EVMSK_REM_OOB_DATA_REQ		0x0020000000000000
#define NG_HCI_EVMSK_SIMPLE_PAIRING_COMPL	0x0040000000000000
#define NG_HCI_EVMSK_LINK_SUPERV_TO_CHANGED	0x0080000000000000
#define NG_HCI_EVMSK_ENH_FLUSH_COMPL		0x0100000000000000
#define NG_HCI_EVMSK_USER_PASSKEY_NOTIFICATION	0x0200000000000000
#define NG_HCI_EVMSK_KEYPRESS_NOTIFICATION	0x0400000000000000
#define NG_HCI_EVMSK_REM_HOST_SUPP_FEAT_NOTIFI	0x0800000000000000
#define NG_HCI_EVMSK_LE_META			0x1000000000000000
/* 0x1000000100000000 - 0x8000000000000000 - reserved for future use */

/* LE events masks*/
#define NG_HCI_LEEVMSK_ALL			0x00000003ffffffff
#define NG_HCI_LEEVMSK_NONE			0x0000000000000000
#define NG_HCI_LEEVMSK_DEFAULT			0x000000000000001f
#define NG_HCI_LEEVMSK_CONN_COMPLETE		0x0000000000000001
#define NG_HCI_LEEVMSK_ADV_REP			0x0000000000000002
#define NG_HCI_LEEVMSK_CONN_UPDATE		0x0000000000000004
#define NG_HCI_LEEVMSK_READ_REM_FEAT_REQ	0x0000000000000008
#define NG_HCI_LEEVMSK_LONG_TERM_KEY_REQ	0x0000000000000010
#define NG_HCI_LEEVMSK_REM_CONN_PARAM_REQ	0x0000000000000020
#define NG_HCI_LEEVMSK_DATA_LENGTH_CHG		0x0000000000000040
#define NG_HCI_LEEVMSK_RD_LOC_P256_PK_COMPL	0x0000000000000080
#define NG_HCI_LEEVMSK_GEN_DHKEY_COMPL		0x0000000000000100
#define NG_HCI_LEEVMSK_ENH_CONN_COMPL		0x0000000000000200
#define NG_HCI_LEEVMSK_DIR_ADV_REP		0x0000000000000400
#define NG_HCI_LEEVMSK_PHY_UPD_COMPL		0x0000000000000800
#define NG_HCI_LEEVMSK_EXT_ADV_REP		0x0000000000001000
#define NG_HCI_LEEVMSK_PER_ADV_SYNC_EST		0x0000000000002000
#define NG_HCI_LEEVMSK_PER_ADV_REP		0x0000000000004000
#define NG_HCI_LEEVMSK_PER_ADV_SYNC_LOST	0x0000000000008000
#define NG_HCI_LEEVMSK_SCAN_TIMEOUT		0x0000000000010000
#define NG_HCI_LEEVMSK_ADV_SET_TERM		0x0000000000020000
#define NG_HCI_LEEVMSK_SCAN_REQ_RCVD		0x0000000000040000
#define NG_HCI_LEEVMSK_CHAN_SEL_ALGO		0x0000000000080000
#define NG_HCI_LEEVMSK_CONNLESS_IQ_REP		0x0000000000100000
#define NG_HCI_LEEVMSK_CONN_IQ_REP		0x0000000000200000
#define NG_HCI_LEEVMSK_CTE_REQ_FAILED		0x0000000000400000
#define NG_HCI_LEEVMSK_PER_ADV_SYN_TRF_RCVD	0x0000000000800000
#define NG_HCI_LEEVMSK_CIS_EST			0x0000000001000000
#define NG_HCI_LEEVMSK_CIS_REQ			0x0000000002000000
#define NG_HCI_LEEVMSK_CREATE_BIG_COMPL		0x0000000004000000
#define NG_HCI_LEEVMSK_TERM_BIG_COMPL		0x0000000008000000
#define NG_HCI_LEEVMSK_BIG_SYNC_EST		0x0000000010000000
#define NG_HCI_LEEVMSK_BIG_SYNC_LOST		0x0000000020000000
#define NG_HCI_LEEVMSK_REQ_PEER_SCA_COMPL	0x0000000040000000
#define NG_HCI_LEEVMSK_PATH_LOSS_THRESHOLD	0x0000000080000000
#define NG_HCI_LEEVMSK_TX_PWR_REP		0x0000000100000000
#define NG_HCI_LEEVMSK_BIGINFO_ADV_REP		0x0000000200000000
/* 0x0000000400000000 - 0x8000000000000000 - reserved for future use */

/* Filter types */
#define NG_HCI_FILTER_TYPE_NONE			0x00
#define NG_HCI_FILTER_TYPE_INQUIRY_RESULT	0x01
#define NG_HCI_FILTER_TYPE_CON_SETUP		0x02
/* 0x03 - 0xFF - reserved for future use */

/* Filter condition types for NG_HCI_FILTER_TYPE_INQUIRY_RESULT */
#define NG_HCI_FILTER_COND_INQUIRY_NEW_UNIT	0x00
#define NG_HCI_FILTER_COND_INQUIRY_UNIT_CLASS	0x01
#define NG_HCI_FILTER_COND_INQUIRY_BDADDR	0x02
/* 0x03 - 0xFF - reserved for future use */

/* Filter condition types for NG_HCI_FILTER_TYPE_CON_SETUP */
#define NG_HCI_FILTER_COND_CON_ANY_UNIT		0x00
#define NG_HCI_FILTER_COND_CON_UNIT_CLASS	0x01
#define NG_HCI_FILTER_COND_CON_BDADDR		0x02
/* 0x03 - 0xFF - reserved for future use */

/* Xmit level types */
#define NG_HCI_XMIT_LEVEL_CURRENT		0x00
#define NG_HCI_XMIT_LEVEL_MAXIMUM		0x01
/* 0x02 - 0xFF - reserved for future use */

/* Host to Host Controller flow control */
#define NG_HCI_H2HC_FLOW_CONTROL_NONE		0x00
#define NG_HCI_H2HC_FLOW_CONTROL_ACL		0x01
#define NG_HCI_H2HC_FLOW_CONTROL_SCO		0x02
#define NG_HCI_H2HC_FLOW_CONTROL_BOTH		0x03	/* ACL and SCO */
/* 0x04 - 0xFF - reserved future use */

/* Country codes */
#define NG_HCI_COUNTRY_CODE_NAM_EUR_JP		0x00
#define NG_HCI_COUNTRY_CODE_FRANCE		0x01
/* 0x02 - 0xFF - reserved future use */

/* Loopback modes */
#define NG_HCI_LOOPBACK_NONE			0x00
#define NG_HCI_LOOPBACK_LOCAL			0x01
#define NG_HCI_LOOPBACK_REMOTE			0x02
/* 0x03 - 0xFF - reserved future use */

/**************************************************************************
 **************************************************************************
 **                 Link level defines, headers and types
 **************************************************************************
 **************************************************************************/

/* 
 * Macro(s) to combine OpCode and extract OGF (OpCode Group Field) 
 * and OCF (OpCode Command Field) from OpCode.
 */

#define NG_HCI_OPCODE(gf,cf)		((((gf) & 0x3f) << 10) | ((cf) & 0x3ff))
#define NG_HCI_OCF(op)			((op) & 0x3ff)
#define NG_HCI_OGF(op)			(((op) >> 10) & 0x3f)

/* 
 * Marco(s) to extract/combine connection handle, BC (Broadcast) and 
 * PB (Packet boundary) flags.
 */

#define NG_HCI_CON_HANDLE(h)		((h) & 0x0fff)
#define NG_HCI_PB_FLAG(h)		(((h) & 0x3000) >> 12)
#define NG_HCI_BC_FLAG(h)		(((h) & 0xc000) >> 14)
#define NG_HCI_MK_CON_HANDLE(h, pb, bc) \
	(((h) & 0x0fff) | (((pb) & 3) << 12) | (((bc) & 3) << 14))

/* PB flag values */
#define	NG_HCI_LE_PACKET_START		0x0
#define	NG_HCI_PACKET_FRAGMENT		0x1 
#define	NG_HCI_PACKET_START		0x2
					/* 11 for AMP packet, not supported */

/* BC flag values */
#define NG_HCI_POINT2POINT		0x0 /* only Host controller to Host */
#define NG_HCI_BROADCAST_ACTIVE		0x1 /* both directions */
#define NG_HCI_BROADCAST_PICONET	0x2 /* both directions */
					/* 11 - reserved for future use */

/* HCI command packet header */
#define NG_HCI_CMD_PKT			0x01
#define NG_HCI_CMD_PKT_SIZE		0xff /* without header */
typedef struct {
	u_int8_t	type;   /* MUST be 0x1 */
	u_int16_t	opcode; /* OpCode */
	u_int8_t	length; /* parameter(s) length in bytes */
} __attribute__ ((packed)) ng_hci_cmd_pkt_t;

/* ACL data packet header */
#define NG_HCI_ACL_DATA_PKT		0x02
#define NG_HCI_ACL_PKT_SIZE		0xffff /* without header */
typedef struct {
	u_int8_t	type;        /* MUST be 0x2 */
	u_int16_t	con_handle;  /* connection handle + PB + BC flags */
	u_int16_t	length;      /* payload length in bytes */
} __attribute__ ((packed)) ng_hci_acldata_pkt_t;

/* SCO data packet header */
#define NG_HCI_SCO_DATA_PKT		0x03
#define NG_HCI_SCO_PKT_SIZE		0xff /* without header */
typedef struct {
	u_int8_t	type;       /* MUST be 0x3 */
	u_int16_t	con_handle; /* connection handle + reserved bits */
	u_int8_t	length;     /* payload length in bytes */
} __attribute__ ((packed)) ng_hci_scodata_pkt_t;

/* HCI ISO data packet header (Core Spec Vol 4 Part E §5.4.5) */
#define NG_HCI_ISO_DATA_PKT		0x05
#define NG_HCI_ISO_PKT_SIZE		0xffff /* without header */
typedef struct {
	u_int8_t	type;        /* MUST be 0x5 */
	u_int16_t	con_handle;  /* connection handle + PB_Flag + TS_Flag */
	u_int16_t	length;      /* ISO data load length (14 bits + RFU) */
} __attribute__ ((packed)) ng_hci_isodata_pkt_t;

/* ISO data packet con_handle field macros */
#define NG_HCI_ISO_CON_HANDLE(h)	((h) & 0x0fff)
#define NG_HCI_ISO_PB_FLAG(h)		(((h) & 0x3000) >> 12)
#define NG_HCI_ISO_TS_FLAG(h)		(((h) & 0x4000) >> 14)
#define NG_HCI_ISO_DATA_LENGTH(l)	((l) & 0x3fff)

/* HCI event packet header */
#define NG_HCI_EVENT_PKT		0x04
#define NG_HCI_EVENT_PKT_SIZE		0xff /* without header */
typedef struct {
	u_int8_t	type;   /* MUST be 0x4 */
	u_int8_t	event;  /* event */
	u_int8_t	length; /* parameter(s) length in bytes */
} __attribute__ ((packed)) ng_hci_event_pkt_t;

/* Bluetooth unit address */
typedef struct {
	u_int8_t	b[NG_HCI_BDADDR_SIZE];
} __attribute__ ((packed)) bdaddr_t;
typedef bdaddr_t *	bdaddr_p;

/* Any BD_ADDR. */
#define NG_HCI_BDADDR_ANY	(&(const bdaddr_t){ { 0, 0, 0, 0, 0, 0 } })

/* HCI status return parameter */
typedef struct {
	u_int8_t	status; /* 0x00 - success */
} __attribute__ ((packed)) ng_hci_status_rp;

/**************************************************************************
 **************************************************************************
 **        Upper layer protocol interface. LP_xxx event parameters
 **************************************************************************
 **************************************************************************/

/* Connection Request Event */
#define NGM_HCI_LP_CON_REQ			1  /* Upper -> HCI */
typedef struct {
	u_int16_t	link_type; /* type of connection */
	bdaddr_t	bdaddr;    /* remote unit address */
} ng_hci_lp_con_req_ep;

/*
 * XXX XXX XXX
 *
 * NOTE: This request is not defined by Bluetooth specification, 
 * but i find it useful :)
 */
#define NGM_HCI_LP_DISCON_REQ			2 /* Upper -> HCI */
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	reason;	    /* reason to disconnect (only low byte) */
} ng_hci_lp_discon_req_ep;

/* Connection Confirmation Event */
#define NGM_HCI_LP_CON_CFM			3  /* HCI -> Upper */
typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int8_t	link_type;  /* link type */
	u_int16_t	con_handle; /* con_handle */
	bdaddr_t	bdaddr;     /* remote unit address */
} ng_hci_lp_con_cfm_ep;

/* Connection Indication Event */
#define NGM_HCI_LP_CON_IND			4  /* HCI -> Upper */
typedef struct {
	u_int8_t	link_type;                 /* link type */
	u_int8_t	uclass[NG_HCI_CLASS_SIZE]; /* unit class */
	bdaddr_t	bdaddr;                    /* remote unit address */
} ng_hci_lp_con_ind_ep;

/* Connection Response Event */
#define NGM_HCI_LP_CON_RSP			5  /* Upper -> HCI */
typedef struct {
	u_int8_t	status;    /* 0x00 - accept connection */
	u_int8_t	link_type; /* link type */
	bdaddr_t	bdaddr;    /* remote unit address */
} ng_hci_lp_con_rsp_ep;

/* Disconnection Indication Event */
#define NGM_HCI_LP_DISCON_IND			6  /* HCI -> Upper */
typedef struct {
	u_int8_t	reason;     /* reason to disconnect (only low byte) */
	u_int8_t	link_type;  /* link type */
	u_int16_t	con_handle; /* connection handle */
} ng_hci_lp_discon_ind_ep;

/* QoS Setup Request Event */
#define NGM_HCI_LP_QOS_REQ			7  /* Upper -> HCI */
typedef struct {
	u_int16_t	con_handle;      /* connection handle */
	u_int8_t	flags;           /* reserved */
	u_int8_t	service_type;    /* service type */
	u_int32_t	token_rate;      /* bytes/sec */
	u_int32_t	peak_bandwidth;  /* bytes/sec */
	u_int32_t	latency;         /* msec */
	u_int32_t	delay_variation; /* msec */
} ng_hci_lp_qos_req_ep;

/* QoS Conformition Event */
#define NGM_HCI_LP_QOS_CFM			8  /* HCI -> Upper */
typedef struct {
	u_int16_t	status;          /* 0x00 - success  (only low byte) */
	u_int16_t	con_handle;      /* connection handle */
} ng_hci_lp_qos_cfm_ep;

/* QoS Violation Indication Event */
#define NGM_HCI_LP_QOS_IND			9  /* HCI -> Upper */
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} ng_hci_lp_qos_ind_ep;
/*Encryption Change event*/
#define NGM_HCI_LP_ENC_CHG 			10 /* HCI->Upper*/
typedef struct {
	uint16_t con_handle;
	uint8_t status;
	uint8_t link_type; 
}ng_hci_lp_enc_change_ep;
/**************************************************************************
 **************************************************************************
 **                    HCI node command/event parameters
 **************************************************************************
 **************************************************************************/

/* Debug levels */
#define NG_HCI_ALERT_LEVEL		1
#define NG_HCI_ERR_LEVEL		2
#define NG_HCI_WARN_LEVEL		3
#define NG_HCI_INFO_LEVEL		4

/* Unit states */
#define NG_HCI_UNIT_CONNECTED		(1 << 0)
#define NG_HCI_UNIT_INITED		(1 << 1)
#define NG_HCI_UNIT_READY	(NG_HCI_UNIT_CONNECTED|NG_HCI_UNIT_INITED)
#define NG_HCI_UNIT_COMMAND_PENDING	(1 << 2)

/* Connection state */
#define NG_HCI_CON_CLOSED		0 /* connection closed */
#define NG_HCI_CON_W4_LP_CON_RSP	1 /* wait for LP_ConnectRsp */
#define NG_HCI_CON_W4_CONN_COMPLETE	2 /* wait for Connection_Complete evt */
#define NG_HCI_CON_OPEN			3 /* connection open */

/* Get HCI node (unit) state (see states above) */
#define NGM_HCI_NODE_GET_STATE			100  /* HCI -> User */
typedef u_int16_t	ng_hci_node_state_ep;

/* Turn on "inited" bit */
#define NGM_HCI_NODE_INIT			101 /* User -> HCI */
/* No parameters */

/* Get/Set node debug level (see debug levels above) */
#define NGM_HCI_NODE_GET_DEBUG			102 /* HCI -> User */
#define NGM_HCI_NODE_SET_DEBUG			103 /* User -> HCI */
typedef u_int16_t	ng_hci_node_debug_ep;

/* Get node buffer info */
#define NGM_HCI_NODE_GET_BUFFER			104 /* HCI -> User */
typedef struct {
	u_int8_t	cmd_free; /* number of free command packets */
	u_int8_t	sco_size; /* max. size of SCO packet */
	u_int16_t	sco_pkts; /* number of SCO packets */
	u_int16_t	sco_free; /* number of free SCO packets */
	u_int16_t	acl_size; /* max. size of ACL packet */
	u_int16_t	acl_pkts; /* number of ACL packets */
	u_int16_t	acl_free; /* number of free ACL packets */
} ng_hci_node_buffer_ep;

/* Get BDADDR */
#define NGM_HCI_NODE_GET_BDADDR			105 /* HCI -> User */
/* bdaddr_t -- BDADDR */

/* Get features */
#define NGM_HCI_NODE_GET_FEATURES		106 /* HCI -> User */
/* features[NG_HCI_FEATURES_SIZE] -- features */

#define NGM_HCI_NODE_GET_STAT			107 /* HCI -> User */
typedef struct {
	u_int32_t	cmd_sent;   /* number of HCI commands sent */
	u_int32_t	evnt_recv;  /* number of HCI events received */
	u_int32_t	acl_recv;   /* number of ACL packets received */
	u_int32_t	acl_sent;   /* number of ACL packets sent */
	u_int32_t	sco_recv;   /* number of SCO packets received */
	u_int32_t	sco_sent;   /* number of SCO packets sent */
	u_int32_t	bytes_recv; /* total number of bytes received */
	u_int32_t	bytes_sent; /* total number of bytes sent */
} ng_hci_node_stat_ep;

#define NGM_HCI_NODE_RESET_STAT			108 /* User -> HCI */
/* No parameters */

#define NGM_HCI_NODE_FLUSH_NEIGHBOR_CACHE	109 /* User -> HCI */

#define NGM_HCI_NODE_GET_NEIGHBOR_CACHE		110 /* HCI -> User */
typedef struct {
	u_int32_t	num_entries;	/* number of entries */
} ng_hci_node_get_neighbor_cache_ep;

typedef struct {
	u_int16_t	page_scan_rep_mode;             /* page rep scan mode */
	u_int16_t	page_scan_mode;                 /* page scan mode */
	u_int16_t	clock_offset;                   /* clock offset */
	bdaddr_t	bdaddr;                         /* bdaddr */
	u_int8_t	features[NG_HCI_FEATURES_SIZE]; /* features */
	uint8_t 	addrtype;
	uint8_t		extinq_size; /* MAX 240*/
	uint8_t		extinq_data[NG_HCI_EXTINQ_MAX];
} ng_hci_node_neighbor_cache_entry_ep;

#define NG_HCI_MAX_NEIGHBOR_NUM \
	((0xffff - sizeof(ng_hci_node_get_neighbor_cache_ep))/sizeof(ng_hci_node_neighbor_cache_entry_ep))

#define NGM_HCI_NODE_GET_CON_LIST		111 /* HCI -> User */
typedef struct {
	u_int32_t	num_connections; /* number of connections */
} ng_hci_node_con_list_ep;

typedef struct {
	u_int8_t	link_type;       /* ACL or SCO */
	u_int8_t	encryption_mode; /* none, p2p, ... */
	u_int8_t	mode;            /* ACTIVE, HOLD ... */
	u_int8_t	role;            /* MASTER/SLAVE */
	u_int16_t	state;           /* connection state */
	u_int16_t	reserved;        /* place holder */
	u_int16_t	pending;         /* number of pending packets */
	u_int16_t	queue_len;       /* number of packets in queue */
	u_int16_t	con_handle;      /* connection handle */
	bdaddr_t	bdaddr;          /* remote bdaddr */
} ng_hci_node_con_ep;

#define NG_HCI_MAX_CON_NUM \
	((0xffff - sizeof(ng_hci_node_con_list_ep))/sizeof(ng_hci_node_con_ep))

#define NGM_HCI_NODE_UP				112 /* HCI -> Upper */
typedef struct {
	u_int16_t	pkt_size;    /* max. ACL/SCO packet size (w/out hdr) */
	u_int16_t	num_pkts;    /* ACL/SCO packet queue size */
	u_int16_t	le_pkt_size; /* max. LE ACL packet size (0=shared) */
	u_int16_t	le_num_pkts; /* LE ACL packet queue size (0=shared) */
	bdaddr_t	bdaddr;	     /* bdaddr */
} ng_hci_node_up_ep;

#define NGM_HCI_SYNC_CON_QUEUE			113 /* HCI -> Upper */
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	completed;  /* number of completed packets */
} ng_hci_sync_con_queue_ep;

#define NGM_HCI_NODE_GET_LINK_POLICY_SETTINGS_MASK	114 /* HCI -> User */
#define NGM_HCI_NODE_SET_LINK_POLICY_SETTINGS_MASK	115 /* User -> HCI */
typedef u_int16_t	ng_hci_node_link_policy_mask_ep;

#define NGM_HCI_NODE_GET_PACKET_MASK		116 /* HCI -> User */
#define NGM_HCI_NODE_SET_PACKET_MASK		117 /* User -> HCI */
typedef u_int16_t	ng_hci_node_packet_mask_ep;

#define NGM_HCI_NODE_GET_ROLE_SWITCH		118 /* HCI -> User */
#define NGM_HCI_NODE_SET_ROLE_SWITCH		119 /* User -> HCI */
typedef u_int16_t	ng_hci_node_role_switch_ep;

#define	NGM_HCI_NODE_LIST_NAMES			200 /* HCI -> User */

/**************************************************************************
 **************************************************************************
 **             Link control commands and return parameters
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_LINK_CONTROL			0x01 /* OpCode Group Field */

#define NG_HCI_OCF_INQUIRY			0x0001
typedef struct {
	u_int8_t	lap[NG_HCI_LAP_SIZE]; /* LAP */
	u_int8_t	inquiry_length; /* (N x 1.28) sec */
	u_int8_t	num_responses;  /* Max. # of responses before halted */
} __attribute__ ((packed)) ng_hci_inquiry_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_INQUIRY_CANCEL		0x0002
/* No command parameter(s) */
typedef ng_hci_status_rp	ng_hci_inquiry_cancel_rp;

#define NG_HCI_OCF_PERIODIC_INQUIRY		0x0003
typedef struct {
	u_int16_t	max_period_length; /* Max. and min. amount of time */
	u_int16_t	min_period_length; /* between consecutive inquiries */
	u_int8_t	lap[NG_HCI_LAP_SIZE]; /* LAP */
	u_int8_t	inquiry_length;    /* (inquiry_length * 1.28) sec */
	u_int8_t	num_responses;     /* Max. # of responses */
} __attribute__ ((packed)) ng_hci_periodic_inquiry_cp;

typedef ng_hci_status_rp	ng_hci_periodic_inquiry_rp;

#define NG_HCI_OCF_EXIT_PERIODIC_INQUIRY	0x0004
/* No command parameter(s) */
typedef ng_hci_status_rp	ng_hci_exit_periodic_inquiry_rp;

#define NG_HCI_OCF_CREATE_CON			0x0005
typedef struct {
	bdaddr_t	bdaddr;             /* destination address */
	u_int16_t	pkt_type;           /* packet type */
	u_int8_t	page_scan_rep_mode; /* page scan repetition mode */
	u_int8_t	page_scan_mode;     /* page scan mode */
	u_int16_t	clock_offset;       /* clock offset */
	u_int8_t	accept_role_switch; /* accept role switch? 0x00 - no */
} __attribute__ ((packed)) ng_hci_create_con_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_DISCON			0x0006
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int8_t	reason;     /* reason to disconnect */
} __attribute__ ((packed)) ng_hci_discon_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_ADD_SCO_CON			0x0007
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	pkt_type;   /* packet type */
} __attribute__ ((packed)) ng_hci_add_sco_con_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_SETUP_SCO_CON		0x0028
typedef struct {
	u_int16_t	con_handle;
	u_int32_t	tx_bandwidth;
	u_int32_t	rx_bandwidth;
	u_int16_t	max_latency;
	u_int16_t	voice_setting;
	u_int8_t	retransmission_effort;
	u_int16_t	pkt_type;
} __attribute__ ((packed)) ng_hci_setup_sco_con_cp;
/* No return parameter(s) — generates Command_Status */

#define NG_HCI_OCF_ACCEPT_SCO_CON		0x0029
typedef struct {
	bdaddr_t	bdaddr;
	u_int32_t	tx_bandwidth;
	u_int32_t	rx_bandwidth;
	u_int16_t	max_latency;
	u_int16_t	content_format;
	u_int8_t	retransmission_effort;
	u_int16_t	pkt_type;
} __attribute__ ((packed)) ng_hci_accept_sco_con_cp;
/* No return parameter(s) — generates Command_Status */

#define NG_HCI_OCF_REJECT_SCO_CON		0x002a
/* Reject_Synchronous_Connection_Request: bdaddr(6) + reason(1). Command_Status. */
typedef struct {
	bdaddr_t	bdaddr;  /* remote address */
	u_int8_t	reason;  /* reason code */
} __attribute__ ((packed)) ng_hci_reject_sco_con_cp;

#define NG_HCI_OCF_CREATE_CON_CANCEL		0x0008
typedef struct {
	bdaddr_t	bdaddr; /* BD_ADDR */
} __attribute__ ((packed)) ng_hci_create_con_cancel_cp;

typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* BD_ADDR */
} __attribute__ ((packed)) ng_hci_create_con_cancel_rp;

#define NG_HCI_OCF_ACCEPT_CON			0x0009
typedef struct {
	bdaddr_t	bdaddr; /* address of unit to be connected */
	u_int8_t	role;   /* connection role */
} __attribute__ ((packed)) ng_hci_accept_con_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_REJECT_CON			0x000a
typedef struct {
	bdaddr_t	bdaddr; /* remote address */
	u_int8_t	reason; /* reason to reject */
} __attribute__ ((packed)) ng_hci_reject_con_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_LINK_KEY_REP			0x000b
typedef struct {
	bdaddr_t	bdaddr;               /* remote address */
	u_int8_t	key[NG_HCI_KEY_SIZE]; /* key */
} __attribute__ ((packed)) ng_hci_link_key_rep_cp;

typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* unit address */
} __attribute__ ((packed)) ng_hci_link_key_rep_rp;

#define NG_HCI_OCF_LINK_KEY_NEG_REP		0x000c
typedef struct {
	bdaddr_t	bdaddr; /* remote address */
} __attribute__ ((packed)) ng_hci_link_key_neg_rep_cp;

typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* unit address */
} __attribute__ ((packed)) ng_hci_link_key_neg_rep_rp;

#define NG_HCI_OCF_PIN_CODE_REP			0x000d
typedef struct {
	bdaddr_t	bdaddr;               /* remote address */
	u_int8_t	pin_size;             /* pin code length (in bytes) */
	u_int8_t	pin[NG_HCI_PIN_SIZE]; /* pin code */
} __attribute__ ((packed)) ng_hci_pin_code_rep_cp;

typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* unit address */
} __attribute__ ((packed)) ng_hci_pin_code_rep_rp;

#define NG_HCI_OCF_PIN_CODE_NEG_REP		0x000e
typedef struct {
	bdaddr_t	bdaddr;  /* remote address */
} __attribute__ ((packed)) ng_hci_pin_code_neg_rep_cp;

typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* unit address */
} __attribute__ ((packed)) ng_hci_pin_code_neg_rep_rp;

#define NG_HCI_OCF_CHANGE_CON_PKT_TYPE		0x000f
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	pkt_type;   /* packet type */
} __attribute__ ((packed)) ng_hci_change_con_pkt_type_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_AUTH_REQ			0x0011
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_auth_req_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_SET_CON_ENCRYPTION		0x0013
typedef struct {
	u_int16_t	con_handle;        /* connection handle */
	u_int8_t	encryption_enable; /* 0x00 - disable, 0x01 - enable */
} __attribute__ ((packed)) ng_hci_set_con_encryption_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_CHANGE_CON_LINK_KEY		0x0015
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_change_con_link_key_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_MASTER_LINK_KEY		0x0017
typedef struct {
	u_int8_t	key_flag; /* key flag */
} __attribute__ ((packed)) ng_hci_master_link_key_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_REMOTE_NAME_REQ		0x0019
typedef struct {
	bdaddr_t	bdaddr;             /* remote address */
	u_int8_t	page_scan_rep_mode; /* page scan repetition mode */
	u_int8_t	page_scan_mode;     /* page scan mode */
	u_int16_t	clock_offset;       /* clock offset */
} __attribute__ ((packed)) ng_hci_remote_name_req_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_REMOTE_NAME_REQ_CANCEL	0x001a
/* struct: bdaddr(6). Returns: status(1) + bdaddr(6). Command_Complete. */
typedef struct {
	bdaddr_t	bdaddr;  /* remote address */
} __attribute__ ((packed)) ng_hci_remote_name_req_cancel_cp;

typedef struct {
	u_int8_t	status;  /* 0x00 - success */
	bdaddr_t	bdaddr;  /* remote address */
} __attribute__ ((packed)) ng_hci_remote_name_req_cancel_rp;

#define NG_HCI_OCF_READ_REMOTE_FEATURES		0x001b
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_remote_features_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_READ_REMOTE_EXTENDED_FEATURES	0x001c
/* Read_Remote_Extended_Features: con_handle(2) + page_number(1). Command_Status. */
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int8_t	page_number; /* page number */
} __attribute__ ((packed)) ng_hci_read_remote_extended_features_cp;

#define NG_HCI_OCF_READ_REMOTE_VER_INFO		0x001d
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_remote_ver_info_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_READ_CLOCK_OFFSET		 0x001f
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_clock_offset_cp;
/* No return parameter(s) */

#define	NG_HCI_IO_CAPABILITY_REQUEST_REPLY		0x002b
typedef struct {
	bdaddr_t	bdaddr;
	u_int8_t	io_capability;
	u_int8_t	oob_data_present;
	u_int8_t	authentication_requirements;
} __attribute__ ((packed)) ng_hci_io_capability_request_reply_cp;

typedef struct {
	u_int8_t	status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_io_capability_request_reply_rp;

#define	NG_HCI_USER_CONFIRMATION_REQUEST_REPLY		0x002c
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_user_confirmation_request_reply_cp;

typedef struct {
	u_int8_t	status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_user_confirmation_request_reply_rp;

#define	NG_HCI_USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY	0x002d
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__((packed)) ng_hci_user_confirmation_request_negative_reply_cp;

typedef struct {
	u_int8_t	status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_user_confirmation_request_negative_reply_rp;

#define	NG_HCI_IO_CAPABILITY_REQUEST_NEGATIVE_REPLY	0x0034
typedef struct {
	bdaddr_t	bdaddr;
	u_int8_t	reason;
} __attribute__ ((packed)) ng_hci_io_capability_request_negative_reply_cp;

typedef struct {
	u_int8_t	status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_io_capability_request_negative_reply_rp;

#define NG_HCI_OCF_USER_PASSKEY_REQ_REP		0x002e
typedef struct {
	bdaddr_t	bdaddr;         /* remote address */
	u_int32_t	numeric_value;  /* passkey 0-999999 */
} __attribute__ ((packed)) ng_hci_user_passkey_req_rep_cp;

typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* remote address */
} __attribute__ ((packed)) ng_hci_user_passkey_req_rep_rp;

#define NG_HCI_OCF_USER_PASSKEY_REQ_NEG_REP	0x002f
typedef struct {
	bdaddr_t	bdaddr; /* remote address */
} __attribute__ ((packed)) ng_hci_user_passkey_req_neg_rep_cp;

typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* remote address */
} __attribute__ ((packed)) ng_hci_user_passkey_req_neg_rep_rp;

/**************************************************************************
 **************************************************************************
 **        Link policy commands and return parameters
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_LINK_POLICY			0x02 /* OpCode Group Field */

#define NG_HCI_OCF_HOLD_MODE			0x0001
typedef struct {
	u_int16_t	con_handle;   /* connection handle */
	u_int16_t	max_interval; /* (max_interval * 0.625) msec */
	u_int16_t	min_interval; /* (max_interval * 0.625) msec */
} __attribute__ ((packed)) ng_hci_hold_mode_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_SNIFF_MODE			0x0003
typedef struct {
	u_int16_t	con_handle;   /* connection handle */
	u_int16_t	max_interval; /* (max_interval * 0.625) msec */
	u_int16_t	min_interval; /* (max_interval * 0.625) msec */
	u_int16_t	attempt;      /* (2 * attempt - 1) * 0.625 msec */
	u_int16_t	timeout;      /* (2 * attempt - 1) * 0.625 msec */
} __attribute__ ((packed)) ng_hci_sniff_mode_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_EXIT_SNIFF_MODE		0x0004
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_exit_sniff_mode_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_PARK_MODE			0x0005
typedef struct {
	u_int16_t	con_handle;   /* connection handle */
	u_int16_t	max_interval; /* (max_interval * 0.625) msec */
	u_int16_t	min_interval; /* (max_interval * 0.625) msec */
} __attribute__ ((packed)) ng_hci_park_mode_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_EXIT_PARK_MODE		0x0006
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_exit_park_mode_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_QOS_SETUP			0x0007
typedef struct {
	u_int16_t	con_handle;      /* connection handle */
	u_int8_t	flags;           /* reserved for future use */
	u_int8_t	service_type;    /* service type */
	u_int32_t	token_rate;      /* bytes per second */
	u_int32_t	peak_bandwidth;  /* bytes per second */
	u_int32_t	latency;         /* microseconds */
	u_int32_t	delay_variation; /* microseconds */
} __attribute__ ((packed)) ng_hci_qos_setup_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_ROLE_DISCOVERY		0x0009
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_role_discovery_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int8_t	role;       /* role for the connection handle */
} __attribute__ ((packed)) ng_hci_role_discovery_rp;

#define NG_HCI_OCF_SWITCH_ROLE			0x000b
typedef struct {
	bdaddr_t	bdaddr; /* remote address */
	u_int8_t	role;   /* new local role */
} __attribute__ ((packed)) ng_hci_switch_role_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_READ_LINK_POLICY_SETTINGS	0x000c
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_link_policy_settings_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	settings;   /* link policy settings */
} __attribute__ ((packed)) ng_hci_read_link_policy_settings_rp;

#define NG_HCI_OCF_WRITE_LINK_POLICY_SETTINGS	0x000d
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	settings;   /* link policy settings */
} __attribute__ ((packed)) ng_hci_write_link_policy_settings_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_write_link_policy_settings_rp;

#define NG_HCI_OCF_SNIFF_SUBRATING		0x0011
typedef struct {
	u_int16_t	con_handle;
	u_int16_t	max_latency;
	u_int16_t	min_remote_timeout;
	u_int16_t	min_local_timeout;
} __attribute__ ((packed)) ng_hci_sniff_subrating_cp;

typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
} __attribute__ ((packed)) ng_hci_sniff_subrating_rp;

#define NG_HCI_OCF_READ_DEFAULT_LINK_POLICY_SETTINGS	0x000e
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;   /* 0x00 - success */
	u_int16_t	settings; /* default link policy settings */
} __attribute__ ((packed)) ng_hci_read_default_link_policy_settings_rp;

#define NG_HCI_OCF_WRITE_DEFAULT_LINK_POLICY_SETTINGS	0x000f
typedef struct {
	u_int16_t	settings; /* default link policy settings */
} __attribute__ ((packed)) ng_hci_write_default_link_policy_settings_cp;

typedef ng_hci_status_rp	ng_hci_write_default_link_policy_settings_rp;

#define NG_HCI_OCF_FLOW_SPECIFICATION		0x0010

/**************************************************************************
 **************************************************************************
 **   Host controller and baseband commands and return parameters
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_HC_BASEBAND			0x03 /* OpCode Group Field */

#define NG_HCI_OCF_SET_EVENT_MASK		0x0001
typedef struct {
	u_int8_t	event_mask[NG_HCI_EVENT_MASK_SIZE]; /* event_mask */
} __attribute__ ((packed)) ng_hci_set_event_mask_cp;

typedef ng_hci_status_rp	ng_hci_set_event_mask_rp;
#define NG_HCI_EVENT_MASK_DEFAULT 0x1fffffffffff
#define NG_HCI_EVENT_MASK_LE  0x2000000000000000

#define NG_HCI_OCF_RESET			0x0003
/* No command parameter(s) */
typedef ng_hci_status_rp	ng_hci_reset_rp;

#define NG_HCI_OCF_SET_EVENT_FILTER		0x0005
typedef struct {
	u_int8_t	filter_type;           /* filter type */
	u_int8_t	filter_condition_type; /* filter condition type */
	u_int8_t	condition[0];          /* conditions - variable size */
} __attribute__ ((packed)) ng_hci_set_event_filter_cp;

typedef ng_hci_status_rp	ng_hci_set_event_filter_rp;

#define NG_HCI_OCF_FLUSH			0x0008
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_flush_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_flush_rp;

#define NG_HCI_OCF_READ_PIN_TYPE		0x0009
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;   /* 0x00 - success */
	u_int8_t	pin_type; /* PIN type */
} __attribute__ ((packed)) ng_hci_read_pin_type_rp;

#define NG_HCI_OCF_WRITE_PIN_TYPE		0x000a
typedef struct {
	u_int8_t	pin_type; /* PIN type */
} __attribute__ ((packed)) ng_hci_write_pin_type_cp;

typedef ng_hci_status_rp	ng_hci_write_pin_type_rp;

#define NG_HCI_OCF_CREATE_NEW_UNIT_KEY		0x000b
/* No command parameter(s) */
typedef ng_hci_status_rp	ng_hci_create_new_unit_key_rp;

#define NG_HCI_OCF_READ_STORED_LINK_KEY		0x000d
typedef struct {
	bdaddr_t	bdaddr;   /* address */
	u_int8_t	read_all; /* read all keys? 0x01 - yes */
} __attribute__ ((packed)) ng_hci_read_stored_link_key_cp;

typedef struct {
	u_int8_t	status;        /* 0x00 - success */
	u_int16_t	max_num_keys;  /* Max. number of keys */
	u_int16_t	num_keys_read; /* Number of stored keys */
} __attribute__ ((packed)) ng_hci_read_stored_link_key_rp;

#define NG_HCI_OCF_WRITE_STORED_LINK_KEY	0x0011
typedef struct {
	u_int8_t	num_keys_write; /* # of keys to write */
/* these are repeated "num_keys_write" times 
	bdaddr_t	bdaddr;                --- remote address(es)
	u_int8_t	key[NG_HCI_KEY_SIZE];  --- key(s) */
} __attribute__ ((packed)) ng_hci_write_stored_link_key_cp;

typedef struct {
	u_int8_t	status;           /* 0x00 - success */
	u_int8_t	num_keys_written; /* # of keys successfully written */
} __attribute__ ((packed)) ng_hci_write_stored_link_key_rp;

#define NG_HCI_OCF_DELETE_STORED_LINK_KEY	0x0012
typedef struct {
	bdaddr_t	bdaddr;     /* address */
	u_int8_t	delete_all; /* delete all keys? 0x01 - yes */
} __attribute__ ((packed)) ng_hci_delete_stored_link_key_cp;

typedef struct {
	u_int8_t	status;           /* 0x00 - success */
	u_int16_t	num_keys_deleted; /* Number of keys deleted */
} __attribute__ ((packed)) ng_hci_delete_stored_link_key_rp;

#define NG_HCI_OCF_CHANGE_LOCAL_NAME		0x0013
typedef struct {
	char		name[NG_HCI_UNIT_NAME_SIZE]; /* new unit name */
} __attribute__ ((packed)) ng_hci_change_local_name_cp;

typedef ng_hci_status_rp	ng_hci_change_local_name_rp;

#define NG_HCI_OCF_READ_LOCAL_NAME		0x0014
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;  /* 0x00 - success */
	char		name[NG_HCI_UNIT_NAME_SIZE]; /* unit name */
} __attribute__ ((packed)) ng_hci_read_local_name_rp;

#define NG_HCI_OCF_READ_CON_ACCEPT_TIMO		0x0015
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;  /* 0x00 - success */
	u_int16_t	timeout; /* (timeout * 0.625) msec */
} __attribute__ ((packed)) ng_hci_read_con_accept_timo_rp;

#define NG_HCI_OCF_WRITE_CON_ACCEPT_TIMO	0x0016
typedef struct {
	u_int16_t	timeout; /* (timeout * 0.625) msec */
} __attribute__ ((packed)) ng_hci_write_con_accept_timo_cp;

typedef ng_hci_status_rp	ng_hci_write_con_accept_timo_rp;

#define NG_HCI_OCF_READ_PAGE_TIMO		0x0017
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;  /* 0x00 - success */
	u_int16_t	timeout; /* (timeout * 0.625) msec */
} __attribute__ ((packed)) ng_hci_read_page_timo_rp;

#define NG_HCI_OCF_WRITE_PAGE_TIMO		0x0018
typedef struct {
	u_int16_t	timeout; /* (timeout * 0.625) msec */
} __attribute__ ((packed)) ng_hci_write_page_timo_cp;

typedef ng_hci_status_rp	ng_hci_write_page_timo_rp;

#define NG_HCI_OCF_READ_SCAN_ENABLE		0x0019
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;      /* 0x00 - success */
	u_int8_t	scan_enable; /* Scan enable */
} __attribute__ ((packed)) ng_hci_read_scan_enable_rp;

#define NG_HCI_OCF_WRITE_SCAN_ENABLE		0x001a
typedef struct {
	u_int8_t	scan_enable; /* Scan enable */
} __attribute__ ((packed)) ng_hci_write_scan_enable_cp;

typedef ng_hci_status_rp	ng_hci_write_scan_enable_rp;

#define NG_HCI_OCF_READ_PAGE_SCAN_ACTIVITY	0x001b
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;             /* 0x00 - success */
	u_int16_t	page_scan_interval; /* interval * 0.625 msec */
	u_int16_t	page_scan_window;   /* window * 0.625 msec */
} __attribute__ ((packed)) ng_hci_read_page_scan_activity_rp;

#define NG_HCI_OCF_WRITE_PAGE_SCAN_ACTIVITY	0x001c
typedef struct {
	u_int16_t	page_scan_interval; /* interval * 0.625 msec */
	u_int16_t	page_scan_window;   /* window * 0.625 msec */
} __attribute__ ((packed)) ng_hci_write_page_scan_activity_cp;

typedef ng_hci_status_rp	ng_hci_write_page_scan_activity_rp;

#define NG_HCI_OCF_READ_INQUIRY_SCAN_ACTIVITY	0x001d
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;                /* 0x00 - success */
	u_int16_t	inquiry_scan_interval; /* interval * 0.625 msec */
	u_int16_t	inquiry_scan_window;   /* window * 0.625 msec */
} __attribute__ ((packed)) ng_hci_read_inquiry_scan_activity_rp;

#define NG_HCI_OCF_WRITE_INQUIRY_SCAN_ACTIVITY	0x001e
typedef struct {
	u_int16_t	inquiry_scan_interval; /* interval * 0.625 msec */
	u_int16_t	inquiry_scan_window;   /* window * 0.625 msec */
} __attribute__ ((packed)) ng_hci_write_inquiry_scan_activity_cp;

typedef ng_hci_status_rp	ng_hci_write_inquiry_scan_activity_rp;

#define NG_HCI_OCF_READ_AUTH_ENABLE		0x001f
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;      /* 0x00 - success */
	u_int8_t	auth_enable; /* 0x01 - enabled */
} __attribute__ ((packed)) ng_hci_read_auth_enable_rp;

#define NG_HCI_OCF_WRITE_AUTH_ENABLE		0x0020
typedef struct {
	u_int8_t	auth_enable; /* 0x01 - enabled */
} __attribute__ ((packed)) ng_hci_write_auth_enable_cp;

typedef ng_hci_status_rp	ng_hci_write_auth_enable_rp;

#define NG_HCI_OCF_READ_ENCRYPTION_MODE		0x0021
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;          /* 0x00 - success */
	u_int8_t	encryption_mode; /* encryption mode */
} __attribute__ ((packed)) ng_hci_read_encryption_mode_rp;

#define NG_HCI_OCF_WRITE_ENCRYPTION_MODE	0x0022
typedef struct {
	u_int8_t	encryption_mode; /* encryption mode */
} __attribute__ ((packed)) ng_hci_write_encryption_mode_cp;

typedef ng_hci_status_rp	ng_hci_write_encryption_mode_rp;

#define NG_HCI_OCF_READ_UNIT_CLASS		0x0023
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;                    /* 0x00 - success */
	u_int8_t	uclass[NG_HCI_CLASS_SIZE]; /* unit class */
} __attribute__ ((packed)) ng_hci_read_unit_class_rp;

#define NG_HCI_OCF_WRITE_UNIT_CLASS		0x0024
typedef struct {
	u_int8_t	uclass[NG_HCI_CLASS_SIZE]; /* unit class */
} __attribute__ ((packed)) ng_hci_write_unit_class_cp;

typedef ng_hci_status_rp	ng_hci_write_unit_class_rp;

#define NG_HCI_OCF_READ_VOICE_SETTINGS		0x0025
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;   /* 0x00 - success */
	u_int16_t	settings; /* voice settings */
} __attribute__ ((packed)) ng_hci_read_voice_settings_rp;

#define NG_HCI_OCF_WRITE_VOICE_SETTINGS		0x0026
typedef struct {
	u_int16_t	settings; /* voice settings */
} __attribute__ ((packed)) ng_hci_write_voice_settings_cp;

typedef ng_hci_status_rp	ng_hci_write_voice_settings_rp;

#define NG_HCI_OCF_READ_AUTO_FLUSH_TIMO		0x0027
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_auto_flush_timo_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	timeout;    /* 0x00 - no flush, timeout * 0.625 msec */
} __attribute__ ((packed)) ng_hci_read_auto_flush_timo_rp;

#define NG_HCI_OCF_WRITE_AUTO_FLUSH_TIMO	0x0028
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	timeout;    /* 0x00 - no flush, timeout * 0.625 msec */
} __attribute__ ((packed)) ng_hci_write_auto_flush_timo_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_write_auto_flush_timo_rp;

#define NG_HCI_OCF_READ_NUM_BROADCAST_RETRANS	0x0029
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;  /* 0x00 - success */
	u_int8_t	counter; /* number of broadcast retransmissions */
} __attribute__ ((packed)) ng_hci_read_num_broadcast_retrans_rp;

#define NG_HCI_OCF_WRITE_NUM_BROADCAST_RETRANS	0x002a
typedef struct {
	u_int8_t	counter; /* number of broadcast retransmissions */
} __attribute__ ((packed)) ng_hci_write_num_broadcast_retrans_cp;

typedef ng_hci_status_rp	ng_hci_write_num_broadcast_retrans_rp;

#define NG_HCI_OCF_READ_HOLD_MODE_ACTIVITY	0x002b
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;             /* 0x00 - success */
	u_int8_t	hold_mode_activity; /* Hold mode activities */
} __attribute__ ((packed)) ng_hci_read_hold_mode_activity_rp;

#define NG_HCI_OCF_WRITE_HOLD_MODE_ACTIVITY	0x002c
typedef struct {
	u_int8_t	hold_mode_activity; /* Hold mode activities */
} __attribute__ ((packed)) ng_hci_write_hold_mode_activity_cp;

typedef ng_hci_status_rp	ng_hci_write_hold_mode_activity_rp;

#define NG_HCI_OCF_READ_XMIT_LEVEL		0x002d
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int8_t	type;       /* Xmit level type */
} __attribute__ ((packed)) ng_hci_read_xmit_level_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	char		level;      /* -30 <= level <= 30 dBm */
} __attribute__ ((packed)) ng_hci_read_xmit_level_rp;

#define NG_HCI_OCF_READ_SCO_FLOW_CONTROL	0x002e
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;       /* 0x00 - success */
	u_int8_t	flow_control; /* 0x00 - disabled */
} __attribute__ ((packed)) ng_hci_read_sco_flow_control_rp;

#define NG_HCI_OCF_WRITE_SCO_FLOW_CONTROL	0x002f
typedef struct {
	u_int8_t	flow_control; /* 0x00 - disabled */
} __attribute__ ((packed)) ng_hci_write_sco_flow_control_cp;

typedef ng_hci_status_rp	ng_hci_write_sco_flow_control_rp;

#define NG_HCI_OCF_H2HC_FLOW_CONTROL		0x0031
typedef struct {
	u_int8_t	h2hc_flow; /* Host to Host controller flow control */
} __attribute__ ((packed)) ng_hci_h2hc_flow_control_cp;

typedef ng_hci_status_rp	ng_hci_h2hc_flow_control_rp;

#define NG_HCI_OCF_HOST_BUFFER_SIZE		0x0033
typedef struct {
	u_int16_t	max_acl_size; /* Max. size of ACL packet (bytes) */
	u_int8_t	max_sco_size; /* Max. size of SCO packet (bytes) */
	u_int16_t	num_acl_pkt;  /* Max. number of ACL packets */
	u_int16_t	num_sco_pkt;  /* Max. number of SCO packets */
} __attribute__ ((packed)) ng_hci_host_buffer_size_cp;

typedef ng_hci_status_rp	ng_hci_host_buffer_size_rp;

#define NG_HCI_OCF_HOST_NUM_COMPL_PKTS		0x0035
typedef struct {
	u_int8_t	num_con_handles; /* # of connection handles */
/* these are repeated "num_con_handles" times
	u_int16_t	con_handle; --- connection handle(s)
	u_int16_t	compl_pkt;  --- # of completed packets */
} __attribute__ ((packed)) ng_hci_host_num_compl_pkts_cp;
/* No return parameter(s) */

#define NG_HCI_OCF_READ_LINK_SUPERVISION_TIMO	0x0036
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_link_supervision_timo_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	timeout;    /* Link supervision timeout * 0.625 msec */
} __attribute__ ((packed)) ng_hci_read_link_supervision_timo_rp;

#define NG_HCI_OCF_WRITE_LINK_SUPERVISION_TIMO	0x0037
typedef struct {
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	timeout;    /* Link supervision timeout * 0.625 msec */
} __attribute__ ((packed)) ng_hci_write_link_supervision_timo_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_write_link_supervision_timo_rp;

#define NG_HCI_OCF_READ_SUPPORTED_IAC_NUM	0x0038
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;  /* 0x00 - success */
	u_int8_t	num_iac; /* # of supported IAC during scan */
} __attribute__ ((packed)) ng_hci_read_supported_iac_num_rp;

#define NG_HCI_OCF_READ_IAC_LAP			0x0039
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;  /* 0x00 - success */
	u_int8_t	num_iac; /* # of IAC */
/* these are repeated "num_iac" times 
	u_int8_t	laps[NG_HCI_LAP_SIZE]; --- LAPs */
} __attribute__ ((packed)) ng_hci_read_iac_lap_rp;

#define NG_HCI_OCF_WRITE_IAC_LAP		0x003a
typedef struct {
	u_int8_t	num_iac; /* # of IAC */
/* these are repeated "num_iac" times 
	u_int8_t	laps[NG_HCI_LAP_SIZE]; --- LAPs */
} __attribute__ ((packed)) ng_hci_write_iac_lap_cp;

typedef ng_hci_status_rp	ng_hci_write_iac_lap_rp;

/*0x003b-0x003e commands are deprecated v2.0 or later*/
#define NG_HCI_OCF_READ_PAGE_SCAN_PERIOD	0x003b
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;                /* 0x00 - success */
	u_int8_t	page_scan_period_mode; /* Page scan period mode */
} __attribute__ ((packed)) ng_hci_read_page_scan_period_rp;

#define NG_HCI_OCF_WRITE_PAGE_SCAN_PERIOD	0x003c
typedef struct {
	u_int8_t	page_scan_period_mode; /* Page scan period mode */
} __attribute__ ((packed)) ng_hci_write_page_scan_period_cp;

typedef ng_hci_status_rp	ng_hci_write_page_scan_period_rp;

#define NG_HCI_OCF_READ_PAGE_SCAN		0x003d
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;         /* 0x00 - success */
	u_int8_t	page_scan_mode; /* Page scan mode */
} __attribute__ ((packed)) ng_hci_read_page_scan_rp;

#define NG_HCI_OCF_WRITE_PAGE_SCAN		0x003e
typedef struct {
	u_int8_t	page_scan_mode; /* Page scan mode */
} __attribute__ ((packed)) ng_hci_write_page_scan_cp;

typedef ng_hci_status_rp	ng_hci_write_page_scan_rp;

#define	NG_HCI_OCF_READ_INQUIRY_SCAN_TYPE	0x0042
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;         /* 0x00 - success */
	u_int8_t	inquiry_scan_type; /* inquiry scan type */
} __attribute__ ((packed)) ng_hci_read_inquiry_scan_type_rp;

#define	NG_HCI_OCF_WRITE_INQUIRY_SCAN_TYPE	0x0043
typedef struct {
	u_int8_t	scan_type; /* inquiry scan type */
} __attribute__ ((packed)) ng_hci_write_inquiry_scan_type_cp;

typedef ng_hci_status_rp	ng_hci_write_inquiry_scan_type_rp;

#define	NG_HCI_OCF_READ_INQUIRY_MODE		0x0044
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;       /* 0x00 - success */
	u_int8_t	inquiry_mode; /* inquiry mode */
} __attribute__ ((packed)) ng_hci_read_inquiry_mode_rp;

#define	NG_HCI_OCF_WRITE_INQUIRY_MODE		0x0045
typedef struct {
	u_int8_t	inquiry_mode; /* inquiry mode */
} __attribute__ ((packed)) ng_hci_write_inquiry_mode_cp;

typedef ng_hci_status_rp	ng_hci_write_inquiry_mode_rp;

#define	NG_HCI_OCF_READ_PAGE_SCAN_TYPE		0x0046
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;         /* 0x00 - success */
	u_int8_t	page_scan_type; /* page scan type */
} __attribute__ ((packed)) ng_hci_read_page_scan_type_rp;

#define	NG_HCI_OCF_WRITE_PAGE_SCAN_TYPE		0x0047
typedef struct {
	u_int8_t	page_scan_type; /* page scan type */
} __attribute__ ((packed)) ng_hci_write_page_scan_type_cp;

typedef ng_hci_status_rp	ng_hci_write_page_scan_type_rp;

#define	NG_HCI_OCF_READ_SIMPLE_PAIRING		0x0055
/* No command parameter(s) */
typedef struct {
	u_int8_t	status;          /* 0x00 - success */
	u_int8_t	simple_pairing;  /* simple pairing mode */
} __attribute__ ((packed)) ng_hci_read_simple_pairing_rp;

#define	NG_HCI_OCF_WRITE_SIMPLE_PAIRING		0x0056
typedef struct {
	u_int8_t simple_pairing; /* 1 -> enabled, 0 -> disabled */
} __attribute__ ((packed)) ng_hci_write_simple_pairing_cp;

typedef ng_hci_status_rp	ng_hci_write_simple_pairing_rp;

#define NG_HCI_OCF_READ_LE_HOST_SUPPORTED  0x6c
typedef struct {
	u_int8_t	status;         /* 0x00 - success */
	u_int8_t	le_supported_host ;/* LE host supported?*/
	u_int8_t	simultaneous_le_host; /* BR/LE simulateneous? */
} __attribute__ ((packed)) ng_hci_read_le_host_supported_rp;

#define NG_HCI_OCF_WRITE_LE_HOST_SUPPORTED  0x6d
typedef struct {
	u_int8_t	le_supported_host; /* LE host supported?*/
	u_int8_t	simultaneous_le_host; /* LE host supported?*/
} __attribute__ ((packed)) ng_hci_write_le_host_supported_cp;

typedef ng_hci_status_rp	ng_hci_write_le_host_supported_rp;

#define	NG_HCI_OCF_SET_AFH_HOST_CHANNEL_CLASSIFICATION	0x003f
typedef struct {
	u_int8_t	afh_host_channel_classification[10];
} __attribute__ ((packed)) ng_hci_set_afh_host_channel_classification_cp;

typedef ng_hci_status_rp ng_hci_set_afh_host_channel_classification_rp;

#define	NG_HCI_OCF_READ_SECURE_CONNECTIONS_HOST_SUPPORT	0x0079
typedef struct {
	u_int8_t	status;
	u_int8_t	support;
} __attribute__ ((packed)) ng_hci_read_secure_connections_host_support_rp;

#define	NG_HCI_OCF_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT	0x007a
typedef struct {
	u_int8_t support; /* 0 - disabled, 1 - enabled */
} __attribute__ ((packed)) ng_hci_write_secure_connections_host_support_cp;

typedef ng_hci_status_rp ng_hci_write_secure_connections_host_support_rp;

/**************************************************************************
 **************************************************************************
 **           Informational commands and return parameters 
 **     All commands in this category do not accept any parameters
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_INFO				0x04 /* OpCode Group Field */

#define NG_HCI_OCF_READ_LOCAL_VER		0x0001
typedef struct {
	u_int8_t	status;         /* 0x00 - success */
	u_int8_t	hci_version;    /* HCI version */
	u_int16_t	hci_revision;   /* HCI revision */
	u_int8_t	lmp_version;    /* LMP version */
	u_int16_t	manufacturer;   /* Hardware manufacturer name */
	u_int16_t	lmp_subversion; /* LMP sub-version */
} __attribute__ ((packed)) ng_hci_read_local_ver_rp;

#define NG_HCI_OCF_READ_LOCAL_COMMANDS		0x0002
typedef struct {
	u_int8_t	status;                         /* 0x00 - success */
	u_int8_t	features[NG_HCI_COMMANDS_SIZE]; /* command bitmsk*/
} __attribute__ ((packed)) ng_hci_read_local_commands_rp;

#define NG_HCI_OCF_READ_LOCAL_FEATURES		0x0003
typedef struct {
	u_int8_t	status;                         /* 0x00 - success */
	u_int8_t	features[NG_HCI_FEATURES_SIZE]; /* LMP features bitmsk*/
} __attribute__ ((packed)) ng_hci_read_local_features_rp;

#define NG_HCI_OCF_READ_LOCAL_EXTENDED_FEATURES	0x0004
typedef struct {
	u_int8_t	page_number; /* page of features to read */
} __attribute__ ((packed)) ng_hci_read_local_extended_features_cp;

typedef struct {
	u_int8_t	status;          /* 0x00 - success */
	u_int8_t	page_number;     /* page number */
	u_int8_t	max_page_number; /* highest page number */
	u_int8_t	features[NG_HCI_FEATURES_SIZE]; /* extended LMP features */
} __attribute__ ((packed)) ng_hci_read_local_extended_features_rp;

#define NG_HCI_OCF_READ_BUFFER_SIZE		0x0005
typedef struct {
	u_int8_t	status;       /* 0x00 - success */
	u_int16_t	max_acl_size; /* Max. size of ACL packet (bytes) */
	u_int8_t	max_sco_size; /* Max. size of SCO packet (bytes) */
	u_int16_t	num_acl_pkt;  /* Max. number of ACL packets */
	u_int16_t	num_sco_pkt;  /* Max. number of SCO packets */
} __attribute__ ((packed)) ng_hci_read_buffer_size_rp;

#define NG_HCI_OCF_READ_COUNTRY_CODE		0x0007
typedef struct {
	u_int8_t	status;       /* 0x00 - success */
	u_int8_t	country_code; /* 0x00 - NAM, EUR, JP; 0x01 - France */
} __attribute__ ((packed)) ng_hci_read_country_code_rp;

#define NG_HCI_OCF_READ_BDADDR			0x0009
typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* unit address */
} __attribute__ ((packed)) ng_hci_read_bdaddr_rp;

/**************************************************************************
 **************************************************************************
 **            Status commands and return parameters 
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_STATUS			0x05 /* OpCode Group Field */

#define NG_HCI_OCF_READ_FAILED_CONTACT_CNTR	0x0001
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_failed_contact_cntr_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	counter;    /* number of consecutive failed contacts */
} __attribute__ ((packed)) ng_hci_read_failed_contact_cntr_rp;

#define NG_HCI_OCF_RESET_FAILED_CONTACT_CNTR	0x0002
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_reset_failed_contact_cntr_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_reset_failed_contact_cntr_rp;

#define NG_HCI_OCF_GET_LINK_QUALITY		0x0003
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_get_link_quality_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int8_t	quality;    /* higher value means better quality */
} __attribute__ ((packed)) ng_hci_get_link_quality_rp;

#define NG_HCI_OCF_READ_RSSI			0x0005
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_read_rssi_cp;

typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	char		rssi;       /* -127 <= rssi <= 127 dB */
} __attribute__ ((packed)) ng_hci_read_rssi_rp;

#define NG_HCI_OCF_READ_AFH_CHANNEL_MAP		0x0006
typedef struct {
	u_int16_t	con_handle;
} __attribute__ ((packed)) ng_hci_read_afh_channel_map_cp;

typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
	u_int8_t	afh_mode;
	u_int8_t	afh_map[10];
} __attribute__ ((packed)) ng_hci_read_afh_channel_map_rp;

#define NG_HCI_OCF_READ_ENCRYPTION_KEY_SIZE	0x0008
typedef struct {
	u_int16_t	con_handle;
} __attribute__ ((packed)) ng_hci_read_encryption_key_size_cp;

typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
	u_int8_t	key_size;
} __attribute__ ((packed)) ng_hci_read_encryption_key_size_rp;

/**************************************************************************
 **************************************************************************
 **             Testing commands and return parameters
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_TESTING			0x06 /* OpCode Group Field */

#define NG_HCI_OCF_READ_LOOPBACK_MODE		0x0001
/* No command parameter(s) */
typedef struct {
	u_int8_t	status; /* 0x00 - success */
	u_int8_t	lbmode; /* loopback mode */
} __attribute__ ((packed)) ng_hci_read_loopback_mode_rp;

#define NG_HCI_OCF_WRITE_LOOPBACK_MODE		0x0002
typedef struct {
	u_int8_t	lbmode; /* loopback mode */
} __attribute__ ((packed)) ng_hci_write_loopback_mode_cp;

typedef ng_hci_status_rp	ng_hci_write_loopback_mode_rp;

#define NG_HCI_OCF_ENABLE_UNIT_UNDER_TEST	0x0003
/* No command parameter(s) */
typedef ng_hci_status_rp	ng_hci_enable_unit_under_test_rp;

/**************************************************************************
 **************************************************************************
 **                LE OpCode group field
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_LE			0x08 /* OpCode Group Field */
#define NG_HCI_OCF_LE_SET_EVENT_MASK			0x0001
typedef struct {
	u_int8_t	event_mask[NG_HCI_LE_EVENT_MASK_SIZE]; /* event_mask*/

} __attribute__ ((packed)) ng_hci_le_set_event_mask_cp;
typedef ng_hci_status_rp	ng_hci_le_set_event_mask_rp;
#define NG_HCI_LE_EVENT_MASK_ALL 0x1f

#define NG_HCI_OCF_LE_READ_BUFFER_SIZE			0x0002
/*No command parameter */
typedef struct {
	u_int8_t	status; /*status*/
	u_int16_t 	hc_le_data_packet_length;
	u_int8_t	hc_total_num_le_data_packets; 
} __attribute__ ((packed)) ng_hci_le_read_buffer_size_rp;

#define NG_HCI_OCF_LE_READ_LOCAL_SUPPORTED_FEATURES	0x0003
/*No command parameter */
typedef struct {
	u_int8_t       	status; /*status*/
	u_int64_t 	le_features;
} __attribute__ ((packed)) ng_hci_le_read_local_supported_features_rp;

#define NG_HCI_OCF_LE_SET_RANDOM_ADDRESS		0x0005
typedef struct {
	bdaddr_t 	random_address;
} __attribute__ ((packed)) ng_hci_le_set_random_address_cp_;
typedef ng_hci_status_rp	ng_hci_le_set_random_address_rp;

#define NG_HCI_OCF_LE_SET_ADVERTISING_PARAMETERS	0x0006
typedef struct {
	u_int16_t	advertising_interval_min;
	u_int16_t 	advertising_interval_max;
	u_int8_t	advertising_type;
	u_int8_t 	own_address_type;
	u_int8_t 	direct_address_type;
	bdaddr_t	direct_address;
	u_int8_t	advertising_channel_map;
	u_int8_t	advertising_filter_policy;
} __attribute__ ((packed)) ng_hci_le_set_advertising_parameters_cp;
typedef ng_hci_status_rp	ng_hci_le_set_advertising_parameters_rp;

#define NG_HCI_OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER	0x0007
/*No command parameter*/
typedef struct {
	u_int8_t status;
	u_int8_t transmit_power_level;
} __attribute__ ((packed)) ng_hci_le_read_advertising_channel_tx_power_rp;

#define NG_HCI_OCF_LE_SET_ADVERTISING_DATA		0x0008
#define NG_HCI_ADVERTISING_DATA_SIZE 31
typedef struct {
	u_int8_t advertising_data_length;
	char advertising_data[NG_HCI_ADVERTISING_DATA_SIZE];
} __attribute__ ((packed)) ng_hci_le_set_advertising_data_cp;
typedef ng_hci_status_rp	ng_hci_le_set_advertising_data_rp;

#define NG_HCI_OCF_LE_SET_SCAN_RESPONSE_DATA		0x0009

typedef struct {
	u_int8_t scan_response_data_length;
	char scan_response_data[NG_HCI_ADVERTISING_DATA_SIZE];
} __attribute__ ((packed)) ng_hci_le_set_scan_response_data_cp;
typedef ng_hci_status_rp	ng_hci_le_set_scan_response_data_rp;

#define NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE		0x000a
typedef struct {
	u_int8_t advertising_enable;
}__attribute__ ((packed)) ng_hci_le_set_advertise_enable_cp;
typedef ng_hci_status_rp	ng_hci_le_set_advertise_enable_rp;

#define NG_HCI_OCF_LE_SET_SCAN_PARAMETERS		0x000b
typedef struct {
	u_int8_t le_scan_type;
	u_int16_t le_scan_interval;
	u_int16_t le_scan_window;
	u_int8_t own_address_type;
	u_int8_t scanning_filter_policy;
}__attribute__ ((packed)) ng_hci_le_set_scan_parameters_cp;
typedef ng_hci_status_rp	ng_hci_le_set_scan_parameters_rp;

#define NG_HCI_OCF_LE_SET_SCAN_ENABLE			0x000c
typedef struct {
	u_int8_t le_scan_enable;
	u_int8_t filter_duplicates;
}__attribute__ ((packed)) ng_hci_le_set_scan_enable_cp;
typedef ng_hci_status_rp	ng_hci_le_set_scan_enable_rp;

#define NG_HCI_OCF_LE_CREATE_CONNECTION			0x000d
typedef struct {
	u_int16_t scan_interval;
	u_int16_t scan_window;
	u_int8_t filter_policy;
	u_int8_t peer_addr_type;
	bdaddr_t peer_addr;
	u_int8_t own_address_type;
	u_int16_t conn_interval_min;
	u_int16_t conn_interval_max;
	u_int16_t conn_latency;
	u_int16_t supervision_timeout;
	u_int16_t min_ce_length;
	u_int16_t max_ce_length;
}__attribute__((packed)) ng_hci_le_create_connection_cp;
/* No return parameters. */
#define NG_HCI_OCF_LE_CREATE_CONNECTION_CANCEL		0x000e
/*No command parameter*/	
typedef ng_hci_status_rp	ng_hci_le_create_connection_cancel_rp;	
#define NG_HCI_OCF_LE_READ_WHITE_LIST_SIZE		0x000f
/*No command parameter*/	
typedef struct {
	u_int8_t status;
	u_int8_t white_list_size;
} __attribute__ ((packed)) ng_hci_le_read_white_list_size_rp;

#define NG_HCI_OCF_LE_CLEAR_WHITE_LIST			0x0010
/* No command parameters. */
typedef ng_hci_status_rp	ng_hci_le_clear_white_list_rp;	
#define NG_HCI_OCF_LE_ADD_DEVICE_TO_WHITE_LIST		0x0011
typedef struct {
	u_int8_t address_type;
	bdaddr_t address;
} __attribute__ ((packed)) ng_hci_le_add_device_to_white_list_cp;
typedef ng_hci_status_rp	ng_hci_le_add_device_to_white_list_rp;	

#define NG_HCI_OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST	0x0012
typedef struct {
	u_int8_t address_type;
	bdaddr_t address;
} __attribute__ ((packed)) ng_hci_le_remove_device_from_white_list_cp;
typedef ng_hci_status_rp	ng_hci_le_remove_device_from_white_list_rp;

#define NG_HCI_OCF_LE_CONNECTION_UPDATE			0x0013
typedef struct {
	u_int16_t connection_handle;
	u_int16_t conn_interval_min;
	u_int16_t conn_interval_max;
	u_int16_t conn_latency;
	u_int16_t supervision_timeout;
	u_int16_t minimum_ce_length;
	u_int16_t maximum_ce_length;
}__attribute__ ((packed)) ng_hci_le_connection_update_cp;
/*no return parameter*/

#define NG_HCI_OCF_LE_SET_HOST_CHANNEL_CLASSIFICATION	0x0014
typedef struct{
	u_int8_t le_channel_map[5];
}__attribute__ ((packed)) ng_hci_le_set_host_channel_classification_cp;
typedef ng_hci_status_rp	ng_hci_le_set_host_channel_classification_rp;

#define NG_HCI_OCF_LE_READ_CHANNEL_MAP			0x0015
typedef struct {
	u_int16_t connection_handle;
}__attribute__ ((packed)) ng_hci_le_read_channel_map_cp;
typedef struct {
	u_int8_t status;
	u_int16_t connection_handle;
	u_int8_t le_channel_map[5];
} __attribute__ ((packed)) ng_hci_le_read_channel_map_rp;

#define NG_HCI_OCF_LE_READ_REMOTE_USED_FEATURES		0x0016
typedef struct {
	u_int16_t connection_handle;
}__attribute__ ((packed)) ng_hci_le_read_remote_used_features_cp;
/*No return parameter*/
#define NG_HCI_128BIT 16
#define NG_HCI_OCF_LE_ENCRYPT				0x0017
typedef struct {
	u_int8_t key[NG_HCI_128BIT];
	u_int8_t plaintext_data[NG_HCI_128BIT];
}__attribute__ ((packed)) ng_hci_le_encrypt_cp;	
typedef struct {
	u_int8_t status;
	u_int8_t encrypted_data[NG_HCI_128BIT];
}__attribute__ ((packed)) ng_hci_le_encrypt_rp;	

#define NG_HCI_OCF_LE_RAND				0x0018
/*No command parameter*/
typedef struct {
	u_int8_t status;
	u_int64_t random_number;
}__attribute__ ((packed)) ng_hci_le_rand_rp;	

#define NG_HCI_OCF_LE_START_ENCRYPTION			0x0019
typedef struct {
	u_int16_t connection_handle;
	u_int64_t random_number;
	u_int16_t encrypted_diversifier;
	u_int8_t long_term_key[NG_HCI_128BIT];
}__attribute__ ((packed)) ng_hci_le_start_encryption_cp;	
/*No return parameter*/
#define NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_REPLY	0x001a
typedef struct {
	u_int16_t connection_handle;
	u_int8_t long_term_key[NG_HCI_128BIT];
}__attribute__ ((packed)) ng_hci_le_long_term_key_request_reply_cp;	
typedef struct {
	u_int8_t status;
	u_int16_t connection_handle;
}__attribute__ ((packed)) ng_hci_le_long_term_key_request_reply_rp;	

#define NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY 0x001b
typedef struct{
	u_int16_t connection_handle;
}__attribute__((packed)) ng_hci_le_long_term_key_request_negative_reply_cp;
typedef struct {
	u_int8_t status;
	u_int16_t connection_handle;
}__attribute__ ((packed)) ng_hci_le_long_term_key_request_negative_reply_rp;

/* LE Remote Connection Parameter Request Reply (7.8.31) — OCF 0x0020 */
#define NG_HCI_OCF_LE_REMOTE_CONN_PARAM_REQ_REPLY	0x0020
typedef struct {
	u_int16_t	connection_handle;
	u_int16_t	interval_min;
	u_int16_t	interval_max;
	u_int16_t	max_latency;
	u_int16_t	timeout;
	u_int16_t	min_ce_length;
	u_int16_t	max_ce_length;
} __attribute__((packed)) ng_hci_le_remote_conn_param_req_reply_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_remote_conn_param_req_reply_rp;

/* LE Remote Connection Parameter Request Negative Reply (7.8.32) — OCF 0x0021 */
#define NG_HCI_OCF_LE_REMOTE_CONN_PARAM_REQ_NEG_REPLY	0x0021
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	reason;
} __attribute__((packed)) ng_hci_le_remote_conn_param_req_neg_reply_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_remote_conn_param_req_neg_reply_rp;

#define NG_HCI_OCF_LE_READ_SUGGESTED_DATA_LENGTH 	0x0023
/*No command parameter*/
typedef struct {
	u_int8_t status;
	u_int16_t suggested_max_tx_octets;
	u_int16_t suggested_max_tx_time;
}__attribute__ ((packed)) ng_hci_le_read_suggested_data_length_rp;

#define NG_HCI_OCF_LE_WRITE_SUGGESTED_DATA_LENGTH 	0x0024
typedef struct {
	u_int16_t suggested_max_tx_octets;
	u_int16_t suggested_max_tx_time;
}__attribute__ ((packed)) ng_hci_le_write_suggested_data_length_cp;
typedef ng_hci_status_rp	ng_hci_le_write_suggested_data_length_rp;

/* LE Read Local P-256 Public Key (7.8.36) — OCF 0x0025 */
#define NG_HCI_OCF_LE_READ_LOCAL_P256_PK		0x0025
/* No command parameters — generates Command_Status + LE Read Local P-256 Public Key Complete event */

/* LE Generate DHKey v1 (7.8.37) — OCF 0x0026 */
#define NG_HCI_OCF_LE_GENERATE_DHKEY			0x0026
typedef struct {
	u_int8_t	remote_p256_pk[64]; /* remote P-256 public key */
} __attribute__((packed)) ng_hci_le_generate_dhkey_cp;
/* No return params — Command_Status + LE Generate DHKey Complete event */

/* LE Set Data Length (7.8.33) — OCF 0x0022 */
#define NG_HCI_OCF_LE_SET_DATA_LENGTH		0x0022
typedef struct {
	u_int16_t	connection_handle;  /* 2 octets */
	u_int16_t	tx_octets;         /* 2 octets, range 0x001B-0x00FB */
	u_int16_t	tx_time;           /* 2 octets, range 0x0148-0x4290 */
} __attribute__((packed)) ng_hci_le_set_data_length_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_set_data_length_rp;

/* LE Read Maximum Data Length (7.8.46) — OCF 0x002F */
#define NG_HCI_OCF_LE_READ_MAX_DATA_LENGTH	0x002f
typedef struct {
	u_int8_t	status;
	u_int16_t	max_tx_octets;     /* 0x001B-0x00FB */
	u_int16_t	max_tx_time;       /* 0x0148-0x4290 */
	u_int16_t	max_rx_octets;     /* 0x001B-0x00FB */
	u_int16_t	max_rx_time;       /* 0x0148-0x4290 */
} __attribute__((packed)) ng_hci_le_read_max_data_length_rp;

/* LE Read PHY (7.8.47) — OCF 0x0030 */
#define NG_HCI_OCF_LE_READ_PHY			0x0030
typedef struct {
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_read_phy_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int8_t	tx_phy;            /* 1=1M, 2=2M, 3=Coded */
	u_int8_t	rx_phy;
} __attribute__((packed)) ng_hci_le_read_phy_rp;

/* LE Set Default PHY (7.8.48) — OCF 0x0031 */
#define NG_HCI_OCF_LE_SET_DEFAULT_PHY		0x0031
typedef struct {
	u_int8_t	all_phys;          /* bit0=no TX pref, bit1=no RX pref */
	u_int8_t	tx_phys;           /* bit0=1M, bit1=2M, bit2=Coded */
	u_int8_t	rx_phys;
} __attribute__((packed)) ng_hci_le_set_default_phy_cp;
typedef ng_hci_status_rp	ng_hci_le_set_default_phy_rp;

/* LE Set PHY (7.8.49) — OCF 0x0032, Command Status (not Complete) */
#define NG_HCI_OCF_LE_SET_PHY			0x0032
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	all_phys;
	u_int8_t	tx_phys;
	u_int8_t	rx_phys;
	u_int16_t	phy_options;       /* coded PHY S=2/S=8 preference */
} __attribute__((packed)) ng_hci_le_set_phy_cp;
/* No return params — Command_Status + LE PHY Update Complete event */

/* LE Add Device To Resolving List (7.8.38) — OCF 0x0027 */
#define NG_HCI_OCF_LE_ADD_DEV_RESOLVING_LIST		0x0027
typedef struct {
	u_int8_t	peer_identity_addr_type;
	bdaddr_t	peer_identity_addr;
	u_int8_t	peer_irk[NG_HCI_KEY_SIZE];
	u_int8_t	local_irk[NG_HCI_KEY_SIZE];
} __attribute__((packed)) ng_hci_le_add_dev_resolving_list_cp;
typedef ng_hci_status_rp	ng_hci_le_add_dev_resolving_list_rp;

/* LE Remove Device From Resolving List (7.8.39) — OCF 0x0028 */
#define NG_HCI_OCF_LE_REMOVE_DEV_RESOLVING_LIST	0x0028
typedef struct {
	u_int8_t	peer_identity_addr_type;
	bdaddr_t	peer_identity_addr;
} __attribute__((packed)) ng_hci_le_remove_dev_resolving_list_cp;
typedef ng_hci_status_rp	ng_hci_le_remove_dev_resolving_list_rp;

/* LE Clear Resolving List (7.8.40) — OCF 0x0029 */
#define NG_HCI_OCF_LE_CLEAR_RESOLVING_LIST		0x0029
typedef ng_hci_status_rp	ng_hci_le_clear_resolving_list_rp;

/* LE Read Resolving List Size (7.8.41) — OCF 0x002A */
#define NG_HCI_OCF_LE_READ_RESOLVING_LIST_SIZE		0x002a
typedef struct {
	u_int8_t	status;
	u_int8_t	resolving_list_size;
} __attribute__((packed)) ng_hci_le_read_resolving_list_size_rp;

/* LE Read Peer Resolvable Address (7.8.42) — OCF 0x002B */
#define NG_HCI_OCF_LE_READ_PEER_RESOLVABLE_ADDRESS	0x002b
typedef struct {
	u_int8_t	peer_identity_addr_type;
	bdaddr_t	peer_identity_addr;
} __attribute__((packed)) ng_hci_le_read_peer_resolvable_address_cp;

typedef struct {
	u_int8_t	status;
	bdaddr_t	peer_resolvable_addr;
} __attribute__((packed)) ng_hci_le_read_peer_resolvable_address_rp;

/* LE Read Local Resolvable Address (7.8.43) — OCF 0x002C */
#define NG_HCI_OCF_LE_READ_LOCAL_RESOLVABLE_ADDRESS	0x002c
typedef struct {
	u_int8_t	peer_identity_addr_type;
	bdaddr_t	peer_identity_addr;
} __attribute__((packed)) ng_hci_le_read_local_resolvable_address_cp;

typedef struct {
	u_int8_t	status;
	bdaddr_t	local_resolvable_addr;
} __attribute__((packed)) ng_hci_le_read_local_resolvable_address_rp;

/* LE Set Address Resolution Enable (7.8.44) — OCF 0x002D */
#define NG_HCI_OCF_LE_SET_ADDR_RESOLUTION_ENABLE	0x002d
typedef struct {
	u_int8_t	enable;
} __attribute__((packed)) ng_hci_le_set_addr_resolution_enable_cp;
typedef ng_hci_status_rp	ng_hci_le_set_addr_resolution_enable_rp;

/* LE Set Resolvable Private Address Timeout v1 (7.8.45) — OCF 0x002E */
#define NG_HCI_OCF_LE_SET_RPA_TIMEOUT			0x002e
typedef struct {
	u_int16_t	rpa_timeout;	/* seconds, range 0x0001-0x0E10 */
} __attribute__((packed)) ng_hci_le_set_rpa_timeout_cp;
typedef ng_hci_status_rp	ng_hci_le_set_rpa_timeout_rp;

/* LE Set Privacy Mode (7.8.77) — OCF 0x004E */
#define NG_HCI_OCF_LE_SET_PRIVACY_MODE			0x004e
typedef struct {
	u_int8_t	peer_identity_addr_type;
	bdaddr_t	peer_identity_addr;
	u_int8_t	privacy_mode;	/* 0=network, 1=device */
} __attribute__((packed)) ng_hci_le_set_privacy_mode_cp;
typedef ng_hci_status_rp	ng_hci_le_set_privacy_mode_rp;

/* LE Read Transmit Power Level (7.8.74) — OCF 0x004B */
#define NG_HCI_OCF_LE_READ_TRANSMIT_POWER		0x004b
/* No command parameters */
typedef struct {
	u_int8_t	status;
	int8_t		min_tx_power;	/* dBm, range -127 to +20 */
	int8_t		max_tx_power;	/* dBm, range -127 to +20 */
} __attribute__((packed)) ng_hci_le_read_transmit_power_rp;

#define NG_HCI_OCF_LE_READ_RF_PATH_COMPENSATION	0x004c
#define NG_HCI_OCF_LE_WRITE_RF_PATH_COMPENSATION	0x004d

/* LE Set Extended Advertising Parameters v1 (7.8.53) — OCF 0x0036 */
#define NG_HCI_OCF_LE_SET_EXT_ADV_PARAMS		0x0036
typedef struct {
	u_int8_t	advertising_handle;
	u_int16_t	advertising_event_properties;
	u_int8_t	primary_advertising_interval_min[3]; /* 3 octets LE */
	u_int8_t	primary_advertising_interval_max[3]; /* 3 octets LE */
	u_int8_t	primary_advertising_channel_map;
	u_int8_t	own_address_type;
	u_int8_t	peer_address_type;
	bdaddr_t	peer_address;
	u_int8_t	advertising_filter_policy;
	int8_t		advertising_tx_power;  /* -127 to +20 dBm, 0x7F=no pref */
	u_int8_t	primary_advertising_phy;
	u_int8_t	secondary_advertising_max_skip;
	u_int8_t	secondary_advertising_phy;
	u_int8_t	advertising_sid;
	u_int8_t	scan_request_notification_enable;
} __attribute__((packed)) ng_hci_le_set_ext_adv_params_cp;
typedef struct {
	u_int8_t	status;
	int8_t		selected_tx_power;
} __attribute__((packed)) ng_hci_le_set_ext_adv_params_rp;

/* LE Set Extended Advertising Data (7.8.54) — OCF 0x0037 */
#define NG_HCI_OCF_LE_SET_EXT_ADV_DATA			0x0037
#define NG_HCI_LE_EXT_ADV_DATA_MAX			251
typedef struct {
	u_int8_t	advertising_handle;
	u_int8_t	operation;       /* 0=intermediate,1=first,2=last,3=complete,4=unchanged */
	u_int8_t	fragment_preference;
	u_int8_t	advertising_data_length;
	u_int8_t	advertising_data[NG_HCI_LE_EXT_ADV_DATA_MAX];
} __attribute__((packed)) ng_hci_le_set_ext_adv_data_cp;
typedef ng_hci_status_rp	ng_hci_le_set_ext_adv_data_rp;

/* LE Set Extended Scan Response Data (7.8.55) — OCF 0x0038 */
#define NG_HCI_OCF_LE_SET_EXT_SCAN_RSP_DATA		0x0038
/* Same struct layout as Set Extended Advertising Data */
typedef ng_hci_le_set_ext_adv_data_cp	ng_hci_le_set_ext_scan_rsp_data_cp;
typedef ng_hci_status_rp		ng_hci_le_set_ext_scan_rsp_data_rp;

/* LE Set Extended Advertising Enable (7.8.56) — OCF 0x0039 */
#define NG_HCI_OCF_LE_SET_EXT_ADV_ENABLE		0x0039
/* Variable-length: enable(1) + num_sets(1) + [handle(1)+duration(2)+max_events(1)] per set */
typedef struct {
	u_int8_t	advertising_handle;
	u_int16_t	duration;        /* N * 10 ms, 0=no duration */
	u_int8_t	max_extended_advertising_events;
} __attribute__((packed)) ng_hci_le_ext_adv_set_t;

/* LE Read Maximum Advertising Data Length (7.8.57) — OCF 0x003A */
#define NG_HCI_OCF_LE_READ_MAX_ADV_DATA_LENGTH		0x003a
/* No command parameters */
typedef struct {
	u_int8_t	status;
	u_int16_t	max_adv_data_length;
} __attribute__((packed)) ng_hci_le_read_max_adv_data_length_rp;

/* LE Read Number of Supported Advertising Sets (7.8.58) — OCF 0x003B */
#define NG_HCI_OCF_LE_READ_NUM_SUPPORTED_ADV_SETS	0x003b
/* No command parameters */
typedef struct {
	u_int8_t	status;
	u_int8_t	num_supported_adv_sets;
} __attribute__((packed)) ng_hci_le_read_num_supported_adv_sets_rp;

/* LE Remove Advertising Set (7.8.59) — OCF 0x003C */
#define NG_HCI_OCF_LE_REMOVE_ADV_SET			0x003c
typedef struct {
	u_int8_t	advertising_handle;
} __attribute__((packed)) ng_hci_le_remove_adv_set_cp;
typedef ng_hci_status_rp	ng_hci_le_remove_adv_set_rp;

/* LE Clear Advertising Sets (7.8.60) — OCF 0x003D */
#define NG_HCI_OCF_LE_CLEAR_ADV_SETS			0x003d
typedef ng_hci_status_rp	ng_hci_le_clear_adv_sets_rp;

/* LE Set Extended Scan Parameters (7.8.64) — OCF 0x0041 */
#define NG_HCI_OCF_LE_SET_EXT_SCAN_PARAMS		0x0041
/* Variable-length: header + per-PHY params.  Struct for common 1-PHY case. */
typedef struct {
	u_int8_t	own_address_type;
	u_int8_t	scanning_filter_policy;
	u_int8_t	scanning_phys;		/* bitmask: bit0=1M, bit2=Coded */
	u_int8_t	scan_type;		/* per-PHY: 0=passive, 1=active */
	u_int16_t	scan_interval;		/* per-PHY */
	u_int16_t	scan_window;		/* per-PHY */
} __attribute__((packed)) ng_hci_le_set_ext_scan_params_cp;
typedef ng_hci_status_rp	ng_hci_le_set_ext_scan_params_rp;

/* LE Set Extended Scan Enable (7.8.65) — OCF 0x0042 */
#define NG_HCI_OCF_LE_SET_EXT_SCAN_ENABLE		0x0042
typedef struct {
	u_int8_t	enable;
	u_int8_t	filter_duplicates;
	u_int16_t	duration;	/* N * 10 ms, 0=until disabled */
	u_int16_t	period;		/* N * 1.28 s, 0=scan continuously */
} __attribute__((packed)) ng_hci_le_set_ext_scan_enable_cp;
typedef ng_hci_status_rp	ng_hci_le_set_ext_scan_enable_rp;

#define NG_HCI_OCF_LE_READ_BUFFER_SIZE_V2		0x0060
/*No command parameter */
typedef struct {
	u_int8_t	status;
	u_int16_t 	hc_le_data_packet_length;
	u_int8_t	hc_total_num_le_data_packets; 
	u_int16_t 	hc_iso_data_packet_length;
	u_int8_t	hc_total_num_iso_data_packets; 
} __attribute__ ((packed)) ng_hci_le_read_buffer_size_rp_v2;

#define NG_HCI_OCF_LE_READ_SUPPORTED_STATES		0x001c
/*No command parameter*/
typedef struct {
	u_int8_t status;
	u_int64_t le_states;
}__attribute__ ((packed)) ng_hci_le_read_supported_states_rp;

#define NG_HCI_OCF_LE_RECEIVER_TEST			0x001d
typedef struct{
	u_int8_t rx_frequency;
} __attribute__((packed)) ng_le_receiver_test_cp;
typedef ng_hci_status_rp	ng_hci_le_receiver_test_rp;

#define NG_HCI_OCF_LE_TRANSMITTER_TEST			0x001e
typedef struct{
	u_int8_t tx_frequency;
	u_int8_t length_of_test_data;
	u_int8_t packet_payload;
} __attribute__((packed)) ng_le_transmitter_test_cp;
typedef ng_hci_status_rp	ng_hci_le_transmitter_test_rp;

#define NG_HCI_OCF_LE_TEST_END				0x001f
/* No command parameter. */
typedef struct {
	u_int8_t status;
	u_int16_t number_of_packets;
}__attribute__ ((packed)) ng_hci_le_test_end_rp;

/* LE Set Host Feature v1 (7.8.115) — OCF 0x0074 */
#define NG_HCI_OCF_LE_SET_HOST_FEATURE			0x0074
typedef struct {
	u_int8_t	bit_number;
	u_int8_t	bit_value;
} __attribute__((packed)) ng_hci_le_set_host_feature_cp;
typedef ng_hci_status_rp	ng_hci_le_set_host_feature_rp;

/* LE Set Advertising Set Random Address (7.8.52) — OCF 0x0035 */
#define NG_HCI_OCF_LE_SET_ADV_SET_RANDOM_ADDR		0x0035
typedef struct {
	u_int8_t	advertising_handle;
	bdaddr_t	random_address;
} __attribute__((packed)) ng_hci_le_set_adv_set_random_addr_cp;
typedef ng_hci_status_rp	ng_hci_le_set_adv_set_random_addr_rp;

/* LE Extended Create Connection v1 (7.8.66) — OCF 0x0043 */
#define NG_HCI_OCF_LE_EXT_CREATE_CONNECTION		0x0043
/* Per-PHY connection parameters (16 bytes each) */
typedef struct {
	u_int16_t	scan_interval;
	u_int16_t	scan_window;
	u_int16_t	conn_interval_min;
	u_int16_t	conn_interval_max;
	u_int16_t	max_latency;
	u_int16_t	supervision_timeout;
	u_int16_t	min_ce_length;
	u_int16_t	max_ce_length;
} __attribute__((packed)) ng_hci_le_ext_create_conn_phy_t;
/* Fixed header; followed by ng_hci_le_ext_create_conn_phy_t[num_phys] */
typedef struct {
	u_int8_t	initiator_filter_policy;
	u_int8_t	own_address_type;
	u_int8_t	peer_address_type;
	bdaddr_t	peer_address;
	u_int8_t	initiating_phys;	/* bitmask: bit0=1M, bit1=2M, bit2=Coded */
	/* followed by ng_hci_le_ext_create_conn_phy_t[popcount(initiating_phys)] */
} __attribute__((packed)) ng_hci_le_ext_create_connection_cp;
/* Returns Command_Status, then LE Enhanced Connection Complete event */

/* LE Enhanced Read Transmit Power Level (7.8.117) — OCF 0x0076 */
#define NG_HCI_OCF_LE_ENH_READ_TX_POWER_LEVEL		0x0076
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	phy;			/* 1=1M, 2=2M, 3=Coded S=8, 4=Coded S=2 */
} __attribute__((packed)) ng_hci_le_enh_read_tx_power_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int8_t	phy;
	int8_t		current_tx_power_level;	/* dBm */
	int8_t		max_tx_power_level;	/* dBm */
} __attribute__((packed)) ng_hci_le_enh_read_tx_power_rp;

/* LE Read Remote Transmit Power Level (7.8.118) — OCF 0x0077 */
#define NG_HCI_OCF_LE_READ_REMOTE_TX_POWER_LEVEL	0x0077
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	phy;			/* 1=1M, 2=2M, 3=Coded S=8, 4=Coded S=2 */
} __attribute__((packed)) ng_hci_le_read_remote_tx_power_cp;
/* Returns Command_Status, then LE Transmit Power Reporting event */

/* LE Set Path Loss Reporting Parameters (7.8.119) — OCF 0x0078 */
#define NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_PARAMS	0x0078
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	high_threshold;		/* dB, 0xFF=unused */
	u_int8_t	high_hysteresis;	/* dB */
	u_int8_t	low_threshold;		/* dB */
	u_int8_t	low_hysteresis;		/* dB */
	u_int16_t	min_time_spent;		/* connection events */
} __attribute__((packed)) ng_hci_le_set_path_loss_reporting_params_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_set_path_loss_reporting_params_rp;

/* LE Set Path Loss Reporting Enable (7.8.120) — OCF 0x0079 */
#define NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE	0x0079
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	enable;			/* 0=disable, 1=enable */
} __attribute__((packed)) ng_hci_le_set_path_loss_reporting_enable_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_set_path_loss_reporting_enable_rp;

/* LE Set Transmit Power Reporting Enable (7.8.121) — OCF 0x007A */
#define NG_HCI_OCF_LE_SET_TX_POWER_REPORTING_ENABLE	0x007a
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	local_enable;		/* 0=disable, 1=enable */
	u_int8_t	remote_enable;		/* 0=disable, 1=enable */
} __attribute__((packed)) ng_hci_le_set_tx_power_reporting_enable_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_set_tx_power_reporting_enable_rp;

/**************************************************************************
 **************************************************************************
 **     Periodic Advertising commands (BT 5.0, 7.8.61-7.8.73)
 **************************************************************************
 **************************************************************************/

/* LE Set Periodic Advertising Parameters v1 (7.8.61) -- OCF 0x003E */
#define NG_HCI_OCF_LE_SET_PERIODIC_ADV_PARAMS		0x003e
typedef struct {
	u_int8_t	advertising_handle;
	u_int16_t	periodic_adv_interval_min;
	u_int16_t	periodic_adv_interval_max;
	u_int16_t	periodic_adv_properties;
} __attribute__((packed)) ng_hci_le_set_periodic_adv_params_cp;
typedef ng_hci_status_rp	ng_hci_le_set_periodic_adv_params_rp;

/* LE Set Periodic Advertising Data (7.8.62) -- OCF 0x003F */
#define NG_HCI_OCF_LE_SET_PERIODIC_ADV_DATA		0x003f
#define NG_HCI_LE_PERIODIC_ADV_DATA_MAX			252
typedef struct {
	u_int8_t	advertising_handle;
	u_int8_t	operation;	/* 0=intermediate,1=first,2=last,3=complete,4=unchanged */
	u_int8_t	advertising_data_length;
	u_int8_t	advertising_data[NG_HCI_LE_PERIODIC_ADV_DATA_MAX];
} __attribute__((packed)) ng_hci_le_set_periodic_adv_data_cp;
typedef ng_hci_status_rp	ng_hci_le_set_periodic_adv_data_rp;

/* LE Set Periodic Advertising Enable (7.8.63) -- OCF 0x0040 */
#define NG_HCI_OCF_LE_SET_PERIODIC_ADV_ENABLE		0x0040
typedef struct {
	u_int8_t	enable;
	u_int8_t	advertising_handle;
} __attribute__((packed)) ng_hci_le_set_periodic_adv_enable_cp;
typedef ng_hci_status_rp	ng_hci_le_set_periodic_adv_enable_rp;

/* LE Periodic Advertising Create Sync (7.8.67) -- OCF 0x0044 */
#define NG_HCI_OCF_LE_PERIODIC_ADV_CREATE_SYNC		0x0044
typedef struct {
	u_int8_t	options;
	u_int8_t	advertising_sid;
	u_int8_t	advertiser_address_type;
	bdaddr_t	advertiser_address;
	u_int16_t	skip;
	u_int16_t	sync_timeout;		/* N * 10 ms */
	u_int8_t	sync_cte_type;
} __attribute__((packed)) ng_hci_le_periodic_adv_create_sync_cp;
/* Returns Command_Status, then LE Periodic Advertising Sync Established event */

/* LE Periodic Advertising Create Sync Cancel (7.8.68) -- OCF 0x0045 */
#define NG_HCI_OCF_LE_PERIODIC_ADV_CREATE_SYNC_CANCEL	0x0045
/* No command parameters */
typedef ng_hci_status_rp	ng_hci_le_periodic_adv_create_sync_cancel_rp;

/* LE Periodic Advertising Terminate Sync (7.8.69) -- OCF 0x0046 */
#define NG_HCI_OCF_LE_PERIODIC_ADV_TERMINATE_SYNC	0x0046
typedef struct {
	u_int16_t	sync_handle;
} __attribute__((packed)) ng_hci_le_periodic_adv_terminate_sync_cp;
typedef ng_hci_status_rp	ng_hci_le_periodic_adv_terminate_sync_rp;

/* LE Add Device To Periodic Advertiser List (7.8.70) -- OCF 0x0047 */
#define NG_HCI_OCF_LE_ADD_DEV_PERIODIC_ADV_LIST		0x0047
typedef struct {
	u_int8_t	advertiser_address_type;
	bdaddr_t	advertiser_address;
	u_int8_t	advertising_sid;
} __attribute__((packed)) ng_hci_le_add_dev_periodic_adv_list_cp;
typedef ng_hci_status_rp	ng_hci_le_add_dev_periodic_adv_list_rp;

/* LE Remove Device From Periodic Advertiser List (7.8.71) -- OCF 0x0048 */
#define NG_HCI_OCF_LE_REMOVE_DEV_PERIODIC_ADV_LIST	0x0048
typedef struct {
	u_int8_t	advertiser_address_type;
	bdaddr_t	advertiser_address;
	u_int8_t	advertising_sid;
} __attribute__((packed)) ng_hci_le_remove_dev_periodic_adv_list_cp;
typedef ng_hci_status_rp	ng_hci_le_remove_dev_periodic_adv_list_rp;

/* LE Clear Periodic Advertiser List (7.8.72) -- OCF 0x0049 */
#define NG_HCI_OCF_LE_CLEAR_PERIODIC_ADV_LIST		0x0049
/* No command parameters */
typedef ng_hci_status_rp	ng_hci_le_clear_periodic_adv_list_rp;

/* LE Read Periodic Advertiser List Size (7.8.73) -- OCF 0x004A */
#define NG_HCI_OCF_LE_READ_PERIODIC_ADV_LIST_SIZE	0x004a
/* No command parameters */
typedef struct {
	u_int8_t	status;
	u_int8_t	periodic_advertiser_list_size;
} __attribute__((packed)) ng_hci_le_read_periodic_adv_list_size_rp;

/**************************************************************************
 **************************************************************************
 **   Periodic Advertising Sync Transfer commands (BT 5.1, 7.8.88-7.8.92)
 **************************************************************************
 **************************************************************************/

/* LE Set Periodic Advertising Receive Enable (7.8.88) -- OCF 0x0059 */
#define NG_HCI_OCF_LE_SET_PERIODIC_ADV_RCV_ENABLE	0x0059
typedef struct {
	u_int16_t	sync_handle;
	u_int8_t	enable;		/* bit0=reporting, bit1=dup filtering */
} __attribute__((packed)) ng_hci_le_set_periodic_adv_rcv_enable_cp;
typedef ng_hci_status_rp	ng_hci_le_set_periodic_adv_rcv_enable_rp;

/* LE Periodic Advertising Sync Transfer (7.8.89) -- OCF 0x005A */
#define NG_HCI_OCF_LE_PERIODIC_ADV_SYNC_TRANSFER	0x005a
typedef struct {
	u_int16_t	connection_handle;
	u_int16_t	service_data;
	u_int16_t	sync_handle;
} __attribute__((packed)) ng_hci_le_periodic_adv_sync_transfer_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_periodic_adv_sync_transfer_rp;

/* LE Periodic Advertising Set Info Transfer (7.8.90) -- OCF 0x005B */
#define NG_HCI_OCF_LE_PERIODIC_ADV_SET_INFO_TRANSFER	0x005b
typedef struct {
	u_int16_t	connection_handle;
	u_int16_t	service_data;
	u_int8_t	advertising_handle;
} __attribute__((packed)) ng_hci_le_periodic_adv_set_info_transfer_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_periodic_adv_set_info_transfer_rp;

/* LE Set Periodic Advertising Sync Transfer Parameters (7.8.91) -- OCF 0x005C */
#define NG_HCI_OCF_LE_SET_PAST_PARAMS			0x005c
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	mode;
	u_int16_t	skip;
	u_int16_t	sync_timeout;		/* N * 10 ms */
	u_int8_t	cte_type;
} __attribute__((packed)) ng_hci_le_set_past_params_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_set_past_params_rp;

/* LE Set Default Periodic Advertising Sync Transfer Parameters (7.8.92) -- OCF 0x005D */
#define NG_HCI_OCF_LE_SET_DEFAULT_PAST_PARAMS		0x005d
typedef struct {
	u_int8_t	mode;
	u_int16_t	skip;
	u_int16_t	sync_timeout;		/* N * 10 ms */
	u_int8_t	cte_type;
} __attribute__((packed)) ng_hci_le_set_default_past_params_cp;
typedef ng_hci_status_rp	ng_hci_le_set_default_past_params_rp;

#define NG_HCI_OCF_LE_SET_CONNLESS_CTE_TX_PARAMS	0x0051
#define NG_HCI_OCF_LE_SET_CONNLESS_CTE_TX_ENABLE	0x0052
#define NG_HCI_OCF_LE_SET_CONNLESS_IQ_SAMPLING_ENABLE	0x0053
#define NG_HCI_OCF_LE_SET_CONN_CTE_RX_PARAMS		0x0054
#define NG_HCI_OCF_LE_SET_CONN_CTE_TX_PARAMS		0x0055
#define NG_HCI_OCF_LE_CONN_CTE_REQ_ENABLE		0x0056
#define NG_HCI_OCF_LE_CONN_CTE_RSP_ENABLE		0x0057
#define NG_HCI_OCF_LE_READ_ANTENNA_INFORMATION		0x0058

#define NG_HCI_OCF_LE_MODIFY_SLEEP_CLOCK_ACCURACY	0x005f

/**************************************************************************
 **************************************************************************
 **          ISO Channel commands (BT 5.2, 7.8.96-7.8.116)
 **************************************************************************
 **************************************************************************/

/* LE Read ISO TX Sync (7.8.96) -- OCF 0x0061 */
#define NG_HCI_OCF_LE_READ_ISO_TX_SYNC			0x0061
typedef struct {
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_read_iso_tx_sync_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int16_t	packet_sequence_number;
	u_int32_t	tx_time_stamp;
	u_int8_t	time_offset[3];		/* 3 octets LE */
} __attribute__((packed)) ng_hci_le_read_iso_tx_sync_rp;

/* LE Set CIG Parameters (7.8.97) -- OCF 0x0062 */
#define NG_HCI_OCF_LE_SET_CIG_PARAMS			0x0062
/* Variable-length: CIG_ID(1)+SDU_Interval_C_To_P(3)+SDU_Interval_P_To_C(3)+
 * Worst_Case_SCA(1)+Packing(1)+Framing(1)+Max_Transport_Latency_C_To_P(2)+
 * Max_Transport_Latency_P_To_C(2)+CIS_Count(1)+CIS_ID[i](1)+Max_SDU_C_To_P[i](2)+
 * Max_SDU_P_To_C[i](2)+PHY_C_To_P[i](1)+PHY_P_To_C[i](1)+RTN_C_To_P[i](1)+
 * RTN_P_To_C[i](1) per CIS.  Struct deferred to ISO transport implementation. */

/* LE Set CIG Parameters Test (7.8.98) -- OCF 0x0063 */
#define NG_HCI_OCF_LE_SET_CIG_PARAMS_TEST		0x0063
/* Variable-length test variant.  Struct deferred to ISO transport implementation. */

/* LE Create CIS (7.8.99) -- OCF 0x0064 */
#define NG_HCI_OCF_LE_CREATE_CIS			0x0064
/* Variable-length: CIS_Count(1)+CIS_Connection_Handle[i](2)+ACL_Connection_Handle[i](2)
 * per CIS.  Struct deferred to ISO transport implementation. */
/* Returns Command_Status, then LE CIS Established event */

/* LE Remove CIG (7.8.100) -- OCF 0x0065 */
#define NG_HCI_OCF_LE_REMOVE_CIG			0x0065
typedef struct {
	u_int8_t	cig_id;
} __attribute__((packed)) ng_hci_le_remove_cig_cp;
typedef struct {
	u_int8_t	status;
	u_int8_t	cig_id;
} __attribute__((packed)) ng_hci_le_remove_cig_rp;

/* LE Accept CIS Request (7.8.101) -- OCF 0x0066 */
#define NG_HCI_OCF_LE_ACCEPT_CIS_REQUEST		0x0066
typedef struct {
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_accept_cis_request_cp;
/* Returns Command_Status, then LE CIS Established event */

/* LE Reject CIS Request (7.8.102) -- OCF 0x0067 */
#define NG_HCI_OCF_LE_REJECT_CIS_REQUEST		0x0067
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	reason;
} __attribute__((packed)) ng_hci_le_reject_cis_request_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_reject_cis_request_rp;

/* LE Create BIG (7.8.103) -- OCF 0x0068 */
#define NG_HCI_OCF_LE_CREATE_BIG			0x0068
/* Variable-length: BIG_Handle(1)+Advertising_Handle(1)+Num_BIS(1)+SDU_Interval(3)+
 * Max_SDU(2)+Max_Transport_Latency(2)+RTN(1)+PHY(1)+Packing(1)+Framing(1)+
 * Encryption(1)+Broadcast_Code(16).
 * Struct deferred to ISO transport implementation. */
/* Returns Command_Status, then LE Create BIG Complete event */

/* LE Create BIG Test (7.8.104) -- OCF 0x0069 */
#define NG_HCI_OCF_LE_CREATE_BIG_TEST			0x0069
/* Variable-length test variant.  Struct deferred to ISO transport implementation. */
/* Returns Command_Status */

/* LE Terminate BIG (7.8.105) -- OCF 0x006A */
#define NG_HCI_OCF_LE_TERMINATE_BIG			0x006a
typedef struct {
	u_int8_t	big_handle;
	u_int8_t	reason;
} __attribute__((packed)) ng_hci_le_terminate_big_cp;
/* Returns Command_Status, then LE Terminate BIG Complete event */

/* LE BIG Create Sync (7.8.106) -- OCF 0x006B */
#define NG_HCI_OCF_LE_BIG_CREATE_SYNC			0x006b
/* Variable-length: BIG_Handle(1)+Sync_Handle(2)+Encryption(1)+Broadcast_Code(16)+
 * MSE(1)+BIG_Sync_Timeout(2)+Num_BIS(1)+BIS[i](1) per BIS.
 * Struct deferred to ISO transport implementation. */
/* Returns Command_Status, then LE BIG Sync Established event */

/* LE BIG Terminate Sync (7.8.107) -- OCF 0x006C */
#define NG_HCI_OCF_LE_BIG_TERMINATE_SYNC		0x006c
typedef struct {
	u_int8_t	big_handle;
} __attribute__((packed)) ng_hci_le_big_terminate_sync_cp;
typedef struct {
	u_int8_t	status;
	u_int8_t	big_handle;
} __attribute__((packed)) ng_hci_le_big_terminate_sync_rp;

/* LE Request Peer SCA (7.8.108) -- OCF 0x006D */
#define NG_HCI_OCF_LE_REQUEST_PEER_SCA			0x006d
typedef struct {
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_request_peer_sca_cp;
/* Returns Command_Status, then LE Request Peer SCA Complete event */

/* LE Setup ISO Data Path (7.8.109) -- OCF 0x006E */
#define NG_HCI_OCF_LE_SETUP_ISO_DATA_PATH		0x006e
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	data_path_direction;	/* 0=input, 1=output */
	u_int8_t	data_path_id;		/* 0=HCI, 1-0xFE=vendor */
	u_int8_t	codec_id[5];		/* coding_format(1)+company_id(2)+vendor_codec_id(2) */
	u_int8_t	controller_delay[3];	/* 3 octets LE, microseconds */
	u_int8_t	codec_configuration_length;
	/* followed by codec_configuration[codec_configuration_length] */
} __attribute__((packed)) ng_hci_le_setup_iso_data_path_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_setup_iso_data_path_rp;

/* LE Remove ISO Data Path (7.8.110) -- OCF 0x006F */
#define NG_HCI_OCF_LE_REMOVE_ISO_DATA_PATH		0x006f
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	data_path_direction;	/* bit0=input, bit1=output */
} __attribute__((packed)) ng_hci_le_remove_iso_data_path_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_remove_iso_data_path_rp;

/* LE ISO Transmit Test (7.8.111) -- OCF 0x0070 */
#define NG_HCI_OCF_LE_ISO_TRANSMIT_TEST			0x0070
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	payload_type;		/* 0=zero, 1=variable, 2=max */
} __attribute__((packed)) ng_hci_le_iso_transmit_test_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_iso_transmit_test_rp;

/* LE ISO Receive Test (7.8.112) -- OCF 0x0071 */
#define NG_HCI_OCF_LE_ISO_RECEIVE_TEST			0x0071
typedef struct {
	u_int16_t	connection_handle;
	u_int8_t	payload_type;		/* 0=zero, 1=variable, 2=max */
} __attribute__((packed)) ng_hci_le_iso_receive_test_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_iso_receive_test_rp;

/* LE ISO Read Test Counters (7.8.113) -- OCF 0x0072 */
#define NG_HCI_OCF_LE_ISO_READ_TEST_COUNTERS		0x0072
typedef struct {
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_iso_read_test_counters_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int32_t	received_sdu_count;
	u_int32_t	missed_sdu_count;
	u_int32_t	failed_sdu_count;
} __attribute__((packed)) ng_hci_le_iso_read_test_counters_rp;

/* LE ISO Test End (7.8.114) -- OCF 0x0073 */
#define NG_HCI_OCF_LE_ISO_TEST_END			0x0073
typedef struct {
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_iso_test_end_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int32_t	received_sdu_count;
	u_int32_t	missed_sdu_count;
	u_int32_t	failed_sdu_count;
} __attribute__((packed)) ng_hci_le_iso_test_end_rp;

/* LE Read ISO Link Quality (7.8.116) -- OCF 0x0075 */
#define NG_HCI_OCF_LE_READ_ISO_LINK_QUALITY		0x0075
typedef struct {
	u_int16_t	connection_handle;
} __attribute__((packed)) ng_hci_le_read_iso_link_quality_cp;
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int32_t	tx_unacked_packets;
	u_int32_t	tx_flushed_packets;
	u_int32_t	tx_last_subevent_packets;
	u_int32_t	retransmitted_packets;
	u_int32_t	crc_error_packets;
	u_int32_t	rx_unreceived_packets;
	u_int32_t	duplicate_packets;
} __attribute__((packed)) ng_hci_le_read_iso_link_quality_rp;

#define NG_HCI_OCF_LE_SET_DATA_RELATED_ADDR_CHANGES	0x007c

/* LE Set Default Subrate (7.8.123) -- OCF 0x007D */
#define NG_HCI_OCF_LE_SET_DEFAULT_SUBRATE		0x007d
typedef struct {
	u_int16_t	subrate_min;
	u_int16_t	subrate_max;
	u_int16_t	max_latency;
	u_int16_t	continuation_number;
	u_int16_t	supervision_timeout;
} __attribute__((packed)) ng_hci_le_set_default_subrate_cp;
typedef ng_hci_status_rp	ng_hci_le_set_default_subrate_rp;

/* LE Subrate Request (7.8.124) -- OCF 0x007E */
#define NG_HCI_OCF_LE_SUBRATE_REQUEST			0x007e
typedef struct {
	u_int16_t	connection_handle;
	u_int16_t	subrate_min;
	u_int16_t	subrate_max;
	u_int16_t	max_latency;
	u_int16_t	continuation_number;
	u_int16_t	supervision_timeout;
} __attribute__((packed)) ng_hci_le_subrate_request_cp;
/* Returns Command_Status, then LE Subrate Change event */

/**************************************************************************
 **************************************************************************
 **                Special HCI OpCode group field values
 **************************************************************************
 **************************************************************************/

#define NG_HCI_OGF_BT_LOGO			0x3e	

#define NG_HCI_OGF_VENDOR			0x3f

/**************************************************************************
 **************************************************************************
 **                         Events and event parameters
 **************************************************************************
 **************************************************************************/

#define NG_HCI_EVENT_INQUIRY_COMPL		0x01
typedef struct {
	u_int8_t	status; /* 0x00 - success */
} __attribute__ ((packed)) ng_hci_inquiry_compl_ep;

#define NG_HCI_EVENT_INQUIRY_RESULT		0x02
typedef struct {
	u_int8_t	num_responses;      /* number of responses */
/*	ng_hci_inquiry_response[num_responses]   -- see below */
} __attribute__ ((packed)) ng_hci_inquiry_result_ep;

typedef struct {
	bdaddr_t	bdaddr;                   /* unit address */
	u_int8_t	page_scan_rep_mode;       /* page scan rep. mode */
	u_int8_t	page_scan_period_mode;    /* page scan period mode */
	u_int8_t	page_scan_mode;           /* page scan mode */
	u_int8_t	uclass[NG_HCI_CLASS_SIZE];/* unit class */
	u_int16_t	clock_offset;             /* clock offset */
} __attribute__ ((packed)) ng_hci_inquiry_response;

#define NG_HCI_EVENT_CON_COMPL			0x03
typedef struct {
	u_int8_t	status;          /* 0x00 - success */
	u_int16_t	con_handle;      /* Connection handle */
	bdaddr_t	bdaddr;          /* remote unit address */
	u_int8_t	link_type;       /* Link type */
	u_int8_t	encryption_mode; /* Encryption mode */
} __attribute__ ((packed)) ng_hci_con_compl_ep;

#define NG_HCI_EVENT_CON_REQ			0x04
typedef struct {
	bdaddr_t	bdaddr;                    /* remote unit address */
	u_int8_t	uclass[NG_HCI_CLASS_SIZE]; /* remote unit class */
	u_int8_t	link_type;                 /* link type */
} __attribute__ ((packed)) ng_hci_con_req_ep;

#define NG_HCI_EVENT_DISCON_COMPL		0x05
typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int8_t	reason;     /* reason to disconnect */
} __attribute__ ((packed)) ng_hci_discon_compl_ep;

#define NG_HCI_EVENT_AUTH_COMPL			0x06
typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_auth_compl_ep;

#define NG_HCI_EVENT_REMOTE_NAME_REQ_COMPL	0x7
typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* remote unit address */
	char		name[NG_HCI_UNIT_NAME_SIZE]; /* remote unit name */
} __attribute__ ((packed)) ng_hci_remote_name_req_compl_ep;

#define NG_HCI_EVENT_ENCRYPTION_CHANGE		0x08
typedef struct {
	u_int8_t	status;            /* 0x00 - success */
	u_int16_t	con_handle;        /* Connection handle */
	u_int8_t	encryption_enable; /* 0x00 - disable */
} __attribute__ ((packed)) ng_hci_encryption_change_ep;

#define NG_HCI_EVENT_CHANGE_CON_LINK_KEY_COMPL	0x09
typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* Connection handle */
} __attribute__ ((packed)) ng_hci_change_con_link_key_compl_ep;

#define NG_HCI_EVENT_MASTER_LINK_KEY_COMPL	0x0a
typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* Connection handle */
	u_int8_t	key_flag;   /* Key flag */
} __attribute__ ((packed)) ng_hci_master_link_key_compl_ep;

#define NG_HCI_EVENT_READ_REMOTE_FEATURES_COMPL	0x0b
typedef struct {
	u_int8_t	status;                         /* 0x00 - success */
	u_int16_t	con_handle;                     /* Connection handle */
	u_int8_t	features[NG_HCI_FEATURES_SIZE]; /* LMP features bitmsk*/
} __attribute__ ((packed)) ng_hci_read_remote_features_compl_ep;

#define NG_HCI_EVENT_READ_REMOTE_VER_INFO_COMPL	0x0c
typedef struct {
	u_int8_t	status;         /* 0x00 - success */
	u_int16_t	con_handle;     /* Connection handle */
	u_int8_t	lmp_version;    /* LMP version */
	u_int16_t	manufacturer;   /* Hardware manufacturer name */
	u_int16_t	lmp_subversion; /* LMP sub-version */
} __attribute__ ((packed)) ng_hci_read_remote_ver_info_compl_ep;

#define NG_HCI_EVENT_QOS_SETUP_COMPL		0x0d
typedef struct {
	u_int8_t	status;          /* 0x00 - success */
	u_int16_t	con_handle;      /* connection handle */
	u_int8_t	flags;           /* reserved for future use */
	u_int8_t	service_type;    /* service type */
	u_int32_t	token_rate;      /* bytes per second */
	u_int32_t	peak_bandwidth;  /* bytes per second */
	u_int32_t	latency;         /* microseconds */
	u_int32_t	delay_variation; /* microseconds */
} __attribute__ ((packed)) ng_hci_qos_setup_compl_ep;

#define NG_HCI_EVENT_COMMAND_COMPL		0x0e
typedef struct {
	u_int8_t	num_cmd_pkts; /* # of HCI command packets */
	u_int16_t	opcode;       /* command OpCode */
	/* command return parameters (if any) */
} __attribute__ ((packed)) ng_hci_command_compl_ep;

#define NG_HCI_EVENT_COMMAND_STATUS		0x0f
typedef struct {
	u_int8_t	status;       /* 0x00 - pending */
	u_int8_t	num_cmd_pkts; /* # of HCI command packets */
	u_int16_t	opcode;       /* command OpCode */
} __attribute__ ((packed)) ng_hci_command_status_ep;

#define NG_HCI_EVENT_HARDWARE_ERROR		0x10
typedef struct {
	u_int8_t	hardware_code; /* hardware error code */
} __attribute__ ((packed)) ng_hci_hardware_error_ep;

#define NG_HCI_EVENT_FLUSH_OCCUR		0x11
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_flush_occur_ep;

#define NG_HCI_EVENT_ROLE_CHANGE		0x12
typedef struct {
	u_int8_t	status; /* 0x00 - success */
	bdaddr_t	bdaddr; /* address of remote unit */
	u_int8_t	role;   /* new connection role */
} __attribute__ ((packed)) ng_hci_role_change_ep;

#define NG_HCI_EVENT_NUM_COMPL_PKTS		0x13
typedef struct {
	u_int8_t	num_con_handles; /* # of connection handles */
/* these are repeated "num_con_handles" times 
	u_int16_t	con_handle; --- connection handle(s)
	u_int16_t	compl_pkt;  --- # of completed packets */
} __attribute__ ((packed)) ng_hci_num_compl_pkts_ep;

#define NG_HCI_EVENT_MODE_CHANGE		0x14
typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int8_t	unit_mode;  /* remote unit mode */
	u_int16_t	interval;   /* interval * 0.625 msec */
} __attribute__ ((packed)) ng_hci_mode_change_ep;

#define NG_HCI_EVENT_RETURN_LINK_KEYS		0x15
typedef struct {
	u_int8_t	num_keys; /* # of keys */
/* these are repeated "num_keys" times 
	bdaddr_t	bdaddr;               --- remote address(es)
	u_int8_t	key[NG_HCI_KEY_SIZE]; --- key(s) */
} __attribute__ ((packed)) ng_hci_return_link_keys_ep;

#define NG_HCI_EVENT_PIN_CODE_REQ		0x16
typedef struct {
	bdaddr_t	bdaddr; /* remote unit address */
} __attribute__ ((packed)) ng_hci_pin_code_req_ep;

#define NG_HCI_EVENT_LINK_KEY_REQ		0x17
typedef struct {
	bdaddr_t	bdaddr; /* remote unit address */
} __attribute__ ((packed)) ng_hci_link_key_req_ep;

#define NG_HCI_EVENT_LINK_KEY_NOTIFICATION	0x18
typedef struct {
	bdaddr_t	bdaddr;               /* remote unit address */
	u_int8_t	key[NG_HCI_KEY_SIZE]; /* link key */
	u_int8_t	key_type;             /* type of the key */
} __attribute__ ((packed)) ng_hci_link_key_notification_ep;

#define NG_HCI_EVENT_LOOPBACK_COMMAND		0x19
typedef struct {
	u_int8_t	command[0]; /* Command packet */
} __attribute__ ((packed)) ng_hci_loopback_command_ep;

#define NG_HCI_EVENT_DATA_BUFFER_OVERFLOW	0x1a
typedef struct {
	u_int8_t	link_type; /* Link type */
} __attribute__ ((packed)) ng_hci_data_buffer_overflow_ep;

#define NG_HCI_EVENT_MAX_SLOT_CHANGE		0x1b
typedef struct {
	u_int16_t	con_handle;    /* connection handle */
	u_int8_t	lmp_max_slots; /* Max. # of slots allowed */
} __attribute__ ((packed)) ng_hci_max_slot_change_ep;

#define NG_HCI_EVENT_READ_CLOCK_OFFSET_COMPL	0x1c
typedef struct {
	u_int8_t	status;       /* 0x00 - success */
	u_int16_t	con_handle;   /* Connection handle */
	u_int16_t	clock_offset; /* Clock offset */
} __attribute__ ((packed)) ng_hci_read_clock_offset_compl_ep;

#define NG_HCI_EVENT_CON_PKT_TYPE_CHANGED	0x1d
typedef struct {
	u_int8_t	status;     /* 0x00 - success */
	u_int16_t	con_handle; /* connection handle */
	u_int16_t	pkt_type;   /* packet type */
} __attribute__ ((packed)) ng_hci_con_pkt_type_changed_ep;

#define NG_HCI_EVENT_QOS_VIOLATION		0x1e
typedef struct {
	u_int16_t	con_handle; /* connection handle */
} __attribute__ ((packed)) ng_hci_qos_violation_ep;

#define NG_HCI_EVENT_PAGE_SCAN_MODE_CHANGE	0x1f
typedef struct {
	bdaddr_t	bdaddr;         /* destination address */
	u_int8_t	page_scan_mode; /* page scan mode */
} __attribute__ ((packed)) ng_hci_page_scan_mode_change_ep;

#define NG_HCI_EVENT_PAGE_SCAN_REP_MODE_CHANGE	0x20
typedef struct {
	bdaddr_t	bdaddr;             /* destination address */
	u_int8_t	page_scan_rep_mode; /* page scan repetition mode */
} __attribute__ ((packed)) ng_hci_page_scan_rep_mode_change_ep;

#define NG_HCI_EVENT_FLOW_SPEC_COMPL		0x21

#define NG_HCI_EVENT_INQUIRY_RESULT_WITH_RSSI	0x22
typedef struct {
	u_int8_t	num_responses;      /* number of responses */
} __attribute__ ((packed)) ng_hci_inquiry_result_with_rssi_ep;

typedef struct {
	bdaddr_t	bdaddr;                   /* unit address */
	u_int8_t	page_scan_rep_mode;       /* page scan rep. mode */
	u_int8_t	reserved;                 /* reserved */
	u_int8_t	uclass[NG_HCI_CLASS_SIZE];/* unit class */
	u_int16_t	clock_offset;             /* clock offset */
	int8_t		rssi;                     /* RSSI in dBm */
} __attribute__ ((packed)) ng_hci_inquiry_response_with_rssi;

#define NG_HCI_EVENT_READ_REMOTE_EXT_FEATURES_COMPL	0x23

#define NG_HCI_EVENT_EXT_INQUIRY_RESULT		0x2f
typedef struct {
	u_int8_t	num_responses;      /* always 1 */
	bdaddr_t	bdaddr;                   /* unit address */
	u_int8_t	page_scan_rep_mode;       /* page scan rep. mode */
	u_int8_t	reserved;                 /* reserved */
	u_int8_t	uclass[NG_HCI_CLASS_SIZE];/* unit class */
	u_int16_t	clock_offset;             /* clock offset */
	int8_t		rssi;                     /* RSSI in dBm */
	u_int8_t	ext_inquiry_response[240];/* extended inquiry response data */
} __attribute__ ((packed)) ng_hci_ext_inquiry_result_ep;

#define NG_HCI_EVENT_SYNC_CON_COMPL		0x2c
typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
	bdaddr_t	bdaddr;
	u_int8_t	link_type;	/* 0x00=SCO, 0x02=eSCO */
	u_int8_t	tx_interval;
	u_int8_t	retransmission_window;
	u_int16_t	rx_pkt_length;
	u_int16_t	tx_pkt_length;
	u_int8_t	air_mode;
} __attribute__ ((packed)) ng_hci_sync_con_compl_ep;

#define NG_HCI_EVENT_SYNC_CON_CHANGED		0x2d
typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
	u_int8_t	tx_interval;
	u_int8_t	retransmission_window;
	u_int16_t	rx_pkt_length;
	u_int16_t	tx_pkt_length;
} __attribute__ ((packed)) ng_hci_sync_con_changed_ep;

#define NG_HCI_EVENT_SNIFF_SUBRATING		0x2e
typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
	u_int16_t	max_tx_latency;
	u_int16_t	max_rx_latency;
	u_int16_t	min_remote_timeout;
	u_int16_t	min_local_timeout;
} __attribute__ ((packed)) ng_hci_sniff_subrating_ep;

#define NG_HCI_EVENT_ENCRYPTION_KEY_REFRESH	0x30
typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
} __attribute__ ((packed)) ng_hci_encryption_key_refresh_ep;

#define	NG_HCI_EVENT_IO_CAPABILITY_REQUEST	0x31
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_io_capability_request_ep;

#define NG_HCI_EVENT_IO_CAPABILITY_RESPONSE	0x32

#define	NG_HCI_EVENT_USER_CONFIRMATION_REQUEST	0x33
typedef struct {
	bdaddr_t	bdaddr;
	u_int32_t	numeric_value;
} __attribute__ ((packed)) ng_hci_user_confirmation_request_ep;

#define NG_HCI_EVENT_USER_PASSKEY_REQUEST	0x34
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_user_passkey_request_ep;

#define	NG_HCI_EVENT_SIMPLE_PAIRING_COMPLETE	0x36
typedef struct {
	u_int8_t	status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ng_hci_simple_pairing_complete_ep;

/* Events with event mask bits but no prior defines */
#define NG_HCI_EVENT_REMOTE_OOB_DATA_REQ	0x35
#define NG_HCI_EVENT_LINK_SUPERV_TO_CHANGED	0x38
#define NG_HCI_EVENT_ENH_FLUSH_COMPL		0x39
#define NG_HCI_EVENT_USER_PASSKEY_NOTIFICATION	0x3b
#define NG_HCI_EVENT_KEYPRESS_NOTIFICATION	0x3c
#define NG_HCI_EVENT_REM_HOST_SUPP_FEAT_NOTIFI	0x3d
#define NG_HCI_EVENT_NUM_COMPL_DATA_BLOCKS	0x48

#define NG_HCI_EVENT_AUTH_PAYLOAD_TIMEOUT	0x57
typedef struct {
	u_int16_t	con_handle;
} __attribute__ ((packed)) ng_hci_auth_payload_timeout_ep;

#define NG_HCI_EVENT_ENCRYPTION_CHANGE_V2	0x59
typedef struct {
	u_int8_t	status;
	u_int16_t	con_handle;
	u_int8_t	encryption_enable;
	u_int8_t	encryption_key_size;
} __attribute__ ((packed)) ng_hci_encryption_change_v2_ep;

#define NG_HCI_EVENT_LE				0x3e
typedef struct {
	u_int8_t	subevent_code;	
}__attribute__ ((packed)) ng_hci_le_ep;

#define NG_HCI_LEEV_CON_COMPL		0x01

typedef struct {
	u_int8_t	status;
	u_int16_t	handle;
	u_int8_t 	role;
	u_int8_t 	address_type;
	bdaddr_t	address;
	u_int16_t 	interval;
	u_int16_t	latency;
	u_int16_t	supervision_timeout;
	u_int8_t	master_clock_accuracy;

} __attribute__ ((packed)) ng_hci_le_connection_complete_ep;

#define NG_HCI_LEEV_ADVREP 0x02
typedef struct {
	u_int8_t num_reports;

}__attribute__ ((packed)) ng_hci_le_advertising_report_ep;
#define NG_HCI_SCAN_RESPONSE_DATA_MAX 0x1f

typedef struct {
	u_int8_t event_type;
	u_int8_t addr_type;
	bdaddr_t bdaddr;
	u_int8_t length_data;
	/* The last octet is for RSSI */
	u_int8_t data[NG_HCI_SCAN_RESPONSE_DATA_MAX+1];
}__attribute__((packed)) ng_hci_le_advreport;

#define NG_HCI_LEEV_CON_UPDATE_COMPL 0x03
typedef struct {
	u_int8_t status;
	u_int16_t connection_handle;
	u_int16_t conn_interval;
	u_int16_t conn_latency;
	u_int16_t supervision_timeout;
}__attribute__((packed)) ng_hci_connection_update_complete_ep;

#define NG_HCI_LEEV_READ_REMOTE_FEATURES_COMPL 0x04
typedef struct {
	u_int8_t 	status;
	u_int16_t 	connection_handle;
	u_int8_t	features[NG_HCI_FEATURES_SIZE];
}__attribute__((packed)) ng_hci_le_read_remote_features_ep;

#define NG_HCI_LEEV_LONG_TERM_KEY_REQUEST 0x05
typedef struct {
	u_int16_t 	connection_handle;
	u_int64_t 	random_number;
	u_int16_t 	encrypted_diversifier;
}__attribute__((packed)) ng_hci_le_long_term_key_request_ep;

#define NG_HCI_LEEV_REMOTE_CONN_PARAM_REQUEST 0x06
typedef struct {
	u_int16_t 	connection_handle;
	u_int16_t 	interval_min;
	u_int16_t 	interval_max;
	u_int16_t 	latency;
	u_int16_t 	timeout;
}__attribute__((packed)) ng_hci_le_remote_conn_param_ep;

#define NG_HCI_LEEV_DATA_LENGTH_CHANGE 0x07
typedef struct {
	u_int16_t 	connection_handle;
	u_int16_t 	max_tx_octets;
	u_int16_t 	max_tx_time;
	u_int16_t 	max_rx_octets;
	u_int16_t 	max_rx_time;
}__attribute__((packed)) ng_hci_le_data_length_change_ep;

#define NG_HCI_LEEV_READ_LOCAL_P256_PK_COMPL 0x08
typedef struct {
	u_int8_t 	status;
	u_int8_t 	local_p256_pk[64];
}__attribute__((packed)) ng_hci_le_read_local_p256_pk_compl_ep;

#define NG_HCI_LEEV_GEN_DHKEY_COMPL 0x09
typedef struct {
	u_int8_t 	status;
	u_int8_t 	dh_key[32];
}__attribute__((packed)) ng_hci_le_gen_dhkey_compl_ep;

#define NG_HCI_LEEV_ENH_CONN_COMPL 0x0a

#define NG_HCI_LEEV_DIRECT_ADV_REP 0x0b
typedef struct {
	u_int8_t 	status;
	u_int16_t 	connection_handle;
	u_int8_t	role;
	u_int8_t 	peer_addr_type;
	bdaddr_t 	peer_addr;
	bdaddr_t 	local_res_private_addr;
	bdaddr_t 	peer_res_private_addr;
	u_int16_t 	conn_interval;
	u_int16_t 	conn_latency;
	u_int16_t 	supervision_timeout;
	u_int8_t	master_clock_accuracy;
}__attribute__((packed)) ng_hci_le_enh_conn_compl_ep;

#define NG_HCI_LEEV_PHY_UPDATE_COMPLETE 0x0c
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int8_t	tx_phy;
	u_int8_t	rx_phy;
}__attribute__((packed)) ng_hci_le_phy_update_compl_ep;

#define NG_HCI_LEEV_EXT_ADVREP			0x0d
/* LE Extended Advertising Report — variable-length, one or more reports.
 * Each report: event_type(2) + addr_type(1) + addr(6) + primary_phy(1) +
 * secondary_phy(1) + advertising_sid(1) + tx_power(1) + rssi(1) +
 * periodic_adv_interval(2) + direct_addr_type(1) + direct_addr(6) +
 * data_length(1) + data[data_length].
 * Parsed manually in hci_le_ext_scan(). */

/* BT 5.0 LE subevents */
#define NG_HCI_LEEV_PER_ADV_SYNC_EST		0x0e
#define NG_HCI_LEEV_PER_ADV_REPORT		0x0f
#define NG_HCI_LEEV_PER_ADV_SYNC_LOST		0x10
#define NG_HCI_LEEV_SCAN_TIMEOUT		0x11
#define NG_HCI_LEEV_ADV_SET_TERMINATED		0x12
#define NG_HCI_LEEV_SCAN_REQ_RECEIVED		0x13
#define NG_HCI_LEEV_CHAN_SEL_ALGO		0x14

/* BT 5.1 LE subevents */
#define NG_HCI_LEEV_CONNECTIONLESS_IQ_REPORT	0x15
#define NG_HCI_LEEV_CONNECTION_IQ_REPORT	0x16
#define NG_HCI_LEEV_CTE_REQUEST_FAILED		0x17
#define NG_HCI_LEEV_PER_ADV_SYNC_XFER_RCVD	0x18

/* BT 5.2 LE subevents (ISO) */
#define NG_HCI_LEEV_CIS_ESTABLISHED		0x19
#define NG_HCI_LEEV_CIS_REQUEST			0x1a
#define NG_HCI_LEEV_CREATE_BIG_COMPL		0x1b
#define NG_HCI_LEEV_TERMINATE_BIG_COMPL		0x1c
#define NG_HCI_LEEV_BIG_SYNC_EST		0x1d
#define NG_HCI_LEEV_BIG_SYNC_LOST		0x1e
#define NG_HCI_LEEV_REQ_PEER_SCA_COMPL		0x1f

/* BT 5.2+ LE subevents (power control, BIGInfo, subrate) */
#define NG_HCI_LEEV_PATH_LOSS_THRESHOLD		0x20
#define NG_HCI_LEEV_TX_POWER_REPORTING		0x21
#define NG_HCI_LEEV_BIGINFO_ADV_REPORT		0x22
#define NG_HCI_LEEV_SUBRATE_CHANGE		0x23

/* LE CIS Established event (7.7.65.25) */
typedef struct {
	u_int8_t	status;
	u_int16_t	connection_handle;
	u_int8_t	cig_sync_delay[3];	/* 3-octet field */
	u_int8_t	cis_sync_delay[3];	/* 3-octet field */
	u_int8_t	transport_latency_c_to_p[3];
	u_int8_t	transport_latency_p_to_c[3];
	u_int8_t	phy_c_to_p;
	u_int8_t	phy_p_to_c;
	u_int8_t	nse;
	u_int8_t	bn_c_to_p;
	u_int8_t	bn_p_to_c;
	u_int8_t	ft_c_to_p;
	u_int8_t	ft_p_to_c;
	u_int16_t	max_pdu_c_to_p;
	u_int16_t	max_pdu_p_to_c;
	u_int16_t	iso_interval;
} __attribute__ ((packed)) ng_hci_le_cis_established_ep;

/* LE CIS Request event (7.7.65.26) */
typedef struct {
	u_int16_t	acl_connection_handle;
	u_int16_t	cis_connection_handle;
	u_int8_t	cig_id;
	u_int8_t	cis_id;
} __attribute__ ((packed)) ng_hci_le_cis_request_ep;

/* LE Create BIG Complete event (7.7.65.27) -- fixed header only */
typedef struct {
	u_int8_t	status;
	u_int8_t	big_handle;
	u_int8_t	big_sync_delay[3];
	u_int8_t	transport_latency_big[3];
	u_int8_t	phy;
	u_int8_t	nse;
	u_int8_t	bn;
	u_int8_t	pto;
	u_int8_t	irc;
	u_int16_t	max_pdu;
	u_int16_t	iso_interval;
	u_int8_t	num_bis;
	/* followed by num_bis * u_int16_t connection_handle[] */
} __attribute__ ((packed)) ng_hci_le_create_big_compl_ep;

/* LE Terminate BIG Complete event (7.7.65.28) */
typedef struct {
	u_int8_t	big_handle;
	u_int8_t	reason;
} __attribute__ ((packed)) ng_hci_le_terminate_big_compl_ep;

/* LE BIG Sync Established event (7.7.65.29) -- fixed header only */
typedef struct {
	u_int8_t	status;
	u_int8_t	big_handle;
	u_int8_t	transport_latency_big[3];
	u_int8_t	nse;
	u_int8_t	bn;
	u_int8_t	pto;
	u_int8_t	irc;
	u_int16_t	max_pdu;
	u_int16_t	iso_interval;
	u_int8_t	num_bis;
	/* followed by num_bis * u_int16_t connection_handle[] */
} __attribute__ ((packed)) ng_hci_le_big_sync_est_ep;

/* LE BIG Sync Lost event (7.7.65.30) */
typedef struct {
	u_int8_t	big_handle;
	u_int8_t	reason;
} __attribute__ ((packed)) ng_hci_le_big_sync_lost_ep;

#define NG_HCI_EVENT_BT_LOGO			0xfe

#define NG_HCI_EVENT_VENDOR			0xff

#endif /* ndef _NETGRAPH_HCI_H_ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh access layer + Configuration /
 * Health model message parsers (lib/libmesh/mesh_access.c,
 * mesh_cfg_model.c, mesh_health_model.c).
 *
 * An Access PDU is fully attacker-controlled: it is the plaintext the upper
 * transport hands up after a successful AES-CCM decrypt, so its opcode and
 * parameters are arbitrary bytes chosen by whoever encrypted the message
 * under a key the node holds.  A malformed opcode length, a truncated
 * parameter block, an out-of-range key index or a bogus model-identifier
 * length must all be handled without an out-of-bounds access.
 *
 * This harness treats the fuzz input AS one received Access PDU and drives:
 *
 *   mesh_access_pdu_parse()   -- the opcode/parameter codec (1/2/3-octet
 *                                opcode detection, truncation, the reserved
 *                                0x7F case).
 *   mesh_access_dispatch()    -- the registry lookup + handler invocation,
 *                                against a tiny two-element node.
 *   the Configuration model parsers -- AppKey Add, AppKey List (two-per-3
 *                                key-index unpacking), Composition Data
 *                                Status, Model App Bind, Model Publication
 *                                Set, Model Subscription, NetKey List.
 *   the Health model parsers  -- Fault Status (FaultArray), Fault Get,
 *                                Fault Test, Period, Attention.
 *
 * Every parser copies out of the input into fixed-size structures, so
 * AddressSanitizer / UndefinedBehaviorSanitizer catch any read past the
 * exact input length or any integer UB in the length arithmetic.  A crash
 * here is a real bug in our code.
 *
 * Reference: MshPRT_v1.1 Section 3.7 (Access layer); MshMDL_v1.1 Section 4
 * (Configuration model) and Section 7 (Health model).
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_cfg_model.h"
#include "mesh_health_model.h"

static int
noop_handler(const struct mesh_access_rx *rx)
{

	/* Touch the parsed fields so the compiler cannot elide the parse. */
	return (rx->pdu->params_len > 0 ? (int)rx->pdu->params[0] : 0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const struct mesh_opcode_entry ops[] = {
		{ MESH_CFG_OP_APPKEY_ADD, noop_handler },
		{ MESH_CFG_OP_APPKEY_STATUS, noop_handler },
		{ MESH_CFG_OP_MODEL_APP_BIND, noop_handler },
		{ MESH_HLT_OP_CURRENT_STATUS, noop_handler },
		/* Vendor opcode 0x0A, Company Identifier 0x1234 (canonical
		 * form octet0<<16 | CID); see mesh_access_vendor_opcode(). */
		{ 0xca1234u, noop_handler },
	};
	static const struct mesh_model models[] = {
		{ 0x0000, MESH_COMPANY_SIG, ops, 5, NULL, NULL },
	};
	static const struct mesh_element elems[] = {
		{ 0x0001, models, 1 },
		{ 0x0002, models, 1 },
	};

	struct mesh_access_pdu ap;
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_comp_status cs;
	struct mesh_cfg_comp_page0 cp;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_pub mp;
	struct mesh_cfg_model_sub ms;
	struct mesh_cfg_relay rel;
	struct mesh_hlt_fault_status fs;
	uint8_t *copy;
	uint32_t op;
	uint8_t status, tid, val;
	uint16_t a, b, cid, idxs[MESH_CFG_MAX_KEY_INDEXES];
	size_t n;

	/* An Access PDU is at most 380 octets; keep slack for oversize paths. */
	if (size > 512)
		size = 512;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	/* Core access-layer codec. */
	(void)mesh_access_pdu_parse(copy, size, &ap);

	/* Dispatch: registry lookup + handler on a tiny node (unicast dst). */
	(void)mesh_access_dispatch(elems, 2, 0x1201, 0x0001, copy, size, NULL);
	(void)mesh_access_dispatch(elems, 2, 0x1201, 0x0002, copy, size, NULL);

	/* Configuration model parsers. */
	(void)mesh_cfg_appkey_add_parse(copy, size, &op, &ak);
	(void)mesh_cfg_appkey_delete_parse(copy, size, &a, &b);
	(void)mesh_cfg_appkey_status_parse(copy, size, &status, &a, &b);
	(void)mesh_cfg_appkey_list_parse(copy, size, &status, &a, idxs,
	    MESH_CFG_MAX_KEY_INDEXES, &n);
	(void)mesh_cfg_netkey_list_parse(copy, size, idxs,
	    MESH_CFG_MAX_KEY_INDEXES, &n);
	(void)mesh_cfg_comp_status_parse(copy, size, &cs);
	(void)mesh_cfg_comp_page0_decode(copy, size, &cp);
	(void)mesh_cfg_model_app_parse(copy, size, &op, &ma);
	(void)mesh_cfg_model_app_status_parse(copy, size, &status, &ma);
	(void)mesh_cfg_model_pub_set_parse(copy, size, &mp);
	(void)mesh_cfg_model_pub_status_parse(copy, size, &status, &mp);
	(void)mesh_cfg_model_sub_parse(copy, size, &op, &ms);
	(void)mesh_cfg_model_sub_status_parse(copy, size, &status, &ms);
	(void)mesh_cfg_u8_state_parse(copy, size, &op, &val);
	(void)mesh_cfg_relay_set_parse(copy, size, &op, &rel);

	/* Health model parsers. */
	(void)mesh_hlt_fault_status_parse(copy, size, &op, &fs);
	(void)mesh_hlt_fault_get_parse(copy, size, &cid);
	(void)mesh_hlt_fault_clear_parse(copy, size, &op, &cid);
	(void)mesh_hlt_fault_test_parse(copy, size, &op, &tid, &cid);
	(void)mesh_hlt_period_parse(copy, size, &op, &val);
	(void)mesh_hlt_attention_parse(copy, size, &op, &val);

	free(copy);
	return (0);
}

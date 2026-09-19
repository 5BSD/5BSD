/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh Configuration model
 * (mesh_cfg_model.[ch], MshMDL_v1.1 Section 4.4.1).
 *
 * The headline vector is the Config AppKey Add message whose Access payload
 * is the plaintext of MshPRT_v1.1 Section 8.3.6 (Message #6):
 *
 *   Access message = 0056341263964771734fbd76e3b40519d1d94a48
 *
 * Decoded per MshMDL Section 4.3.1.1 the "563412" NetKeyIndexAndAppKeyIndex
 * field is NetKeyIndex 0x456 and AppKeyIndex 0x123, followed by the 16-octet
 * AppKey 63964771734fbd76e3b40519d1d94a48.  This byte string is asserted for
 * both build and parse, and the 12-bit two-index packing is verified in
 * isolation against a hand computation (0x456,0x123 -> 56 34 12).
 *
 * The remaining messages (Composition Data, Model App Bind, Publication,
 * Subscription, the Status opcodes, key management, Node Reset and the
 * node-wide states) are asserted against byte strings hand-derived from the
 * field-layout and little-endian rules of the cited MshMDL sections; the
 * field VALUES are illustrative but every octet's POSITION and ENDIANNESS
 * comes from the specification, and each is checked for both build and parse.
 *
 * All Configuration-model fields are little-endian on the wire.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_cfg_model.h"
#include "spec_oracles.h"

static void
hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%02x", &b);
		out[i] = (uint8_t)b;
	}
}

#define	HEX(var, hexstr, len) \
	uint8_t var[len]; hex_to_bytes(var, hexstr, len)

/* ================================================================
 * Key-index 12-bit packing (MshMDL Section 4.3.1.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(keyidx_packing);
ATF_TC_BODY(keyidx_packing, tc)
{
	uint8_t two[3], one[2];
	uint16_t a, b;

	/* Two indexes: NetKeyIndex 0x456 (idx0), AppKeyIndex 0x123 (idx1). */
	mesh_cfg_keyidx_pack2(two, 0x456, 0x123);
	ATF_CHECK_EQ_MSG(0x56, two[0], "octet0 = idx0[7:0]");
	ATF_CHECK_EQ_MSG(0x34, two[1], "octet1 = idx1[3:0]<<4 | idx0[11:8]");
	ATF_CHECK_EQ_MSG(0x12, two[2], "octet2 = idx1[11:4]");
	mesh_cfg_keyidx_unpack2(two, &a, &b);
	ATF_CHECK_EQ(0x456, a);
	ATF_CHECK_EQ(0x123, b);

	/* Single index: 12-bit little-endian, 4 RFU bits zero. */
	mesh_cfg_keyidx_pack1(one, 0x456);
	ATF_CHECK_EQ(0x56, one[0]);
	ATF_CHECK_EQ(0x04, one[1]);
	ATF_CHECK_EQ(0x456, mesh_cfg_keyidx_unpack1(one));

	mesh_cfg_keyidx_pack1(one, 0x123);
	ATF_CHECK_EQ(0x23, one[0]);
	ATF_CHECK_EQ(0x01, one[1]);
}

/* ================================================================
 * AppKey Add: MshPRT Section 8.3.6 access payload.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(appkey_add_msg6);
ATF_TC_BODY(appkey_add_msg6, tc)
{
	struct mesh_cfg_appkey in, out;
	HEX(exp, "0056341263964771734fbd76e3b40519d1d94a48", 20);
	uint8_t buf[20];
	size_t outlen;
	uint32_t op;

	memset(&in, 0, sizeof(in));
	in.net_idx = 0x456;
	in.app_idx = 0x123;
	memcpy(in.key, exp + 4, 16);

	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &in,
	    buf, &outlen));
	ATF_CHECK_EQ_MSG(20, (int)outlen, "AppKey Add access PDU is 20 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp, 20),
	    "AppKey Add access PDU must equal the Section 8.3.6 bytes");

	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_parse(exp, 20, &op, &out));
	ATF_CHECK_EQ(MESH_CFG_OP_APPKEY_ADD, op);
	ATF_CHECK_EQ_MSG(0x456, out.net_idx, "recovered NetKeyIndex 0x456");
	ATF_CHECK_EQ_MSG(0x123, out.app_idx, "recovered AppKeyIndex 0x123");
	ATF_CHECK_EQ(0, memcmp(out.key, exp + 4, 16));

	/* Same struct with the Update opcode 0x01. */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &in, buf, &outlen));
	ATF_CHECK_EQ(0x01, buf[0]);
}

/* ================================================================
 * Composition Data Page 0 + Status (MshMDL Section 4.4.1.2.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(composition_data);
ATF_TC_BODY(composition_data, tc)
{
	struct mesh_cfg_comp_page0 in, out;
	struct mesh_cfg_comp_status st, stout;
	HEX(exp_page,
	    "f10502000300640003000001020100000200f1053412000001000010", 28);
	HEX(exp_status,
	    "0200f10502000300640003000001020100000200f1053412000001000010", 30);
	uint8_t buf[64];
	size_t outlen;

	memset(&in, 0, sizeof(in));
	in.cid = 0x05f1;
	in.pid = 0x0002;
	in.vid = 0x0003;
	in.crpl = 0x0064;
	in.features = MESH_CFG_FEATURE_RELAY | MESH_CFG_FEATURE_PROXY; /* 0x03 */
	in.n_elements = 2;
	in.elements[0].loc = 0x0100;
	in.elements[0].n_sig = 2;
	in.elements[0].sig_models[0] = 0x0000;	/* Config Server */
	in.elements[0].sig_models[1] = 0x0002;	/* Health Server */
	in.elements[0].n_vnd = 1;
	in.elements[0].vnd_models[0].company_id = 0x05f1;
	in.elements[0].vnd_models[0].model_id = 0x1234;
	in.elements[1].loc = 0x0000;
	in.elements[1].n_sig = 1;
	in.elements[1].sig_models[0] = 0x1000;

	ATF_REQUIRE_EQ(0, mesh_cfg_comp_page0_encode(&in, buf, &outlen));
	ATF_CHECK_EQ_MSG(28, (int)outlen, "page-0 blob length");
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_page, 28),
	    "Composition Data Page 0 byte layout (4.4.1.2.1)");

	ATF_REQUIRE_EQ(0, mesh_cfg_comp_page0_decode(exp_page, 28, &out));
	ATF_CHECK_EQ(0x05f1, out.cid);
	ATF_CHECK_EQ(0x0064, out.crpl);
	ATF_CHECK_EQ(0x0003, out.features);
	ATF_CHECK_EQ_MSG(2, (int)out.n_elements, "two elements decoded");
	ATF_CHECK_EQ(2, (int)out.elements[0].n_sig);
	ATF_CHECK_EQ(1, (int)out.elements[0].n_vnd);
	ATF_CHECK_EQ(0x0002, out.elements[0].sig_models[1]);
	ATF_CHECK_EQ(0x05f1, out.elements[0].vnd_models[0].company_id);
	ATF_CHECK_EQ(0x1234, out.elements[0].vnd_models[0].model_id);
	ATF_CHECK_EQ(0x1000, out.elements[1].sig_models[0]);

	/* Composition Data Status: opcode 0x02 + Page + page data. */
	memset(&st, 0, sizeof(st));
	st.page = 0x00;
	memcpy(st.data, exp_page, 28);
	st.data_len = 28;
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_status_build(&st, buf, &outlen));
	ATF_CHECK_EQ(30, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_status, 30),
	    "Composition Data Status access PDU (opcode 0x02)");
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_status_parse(exp_status, 30, &stout));
	ATF_CHECK_EQ(0x00, stout.page);
	ATF_CHECK_EQ(28, (int)stout.data_len);
	ATF_CHECK_EQ(0, memcmp(stout.data, exp_page, 28));

	/* Composition Data Get: opcode 0x8008 + Page 0xff. */
	{
		HEX(exp_get, "8008ff", 3);
		uint8_t page;
		ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0xff, buf, &outlen));
		ATF_CHECK_EQ(3, (int)outlen);
		ATF_CHECK_EQ(0, memcmp(buf, exp_get, 3));
		ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_parse(exp_get, 3, &page));
		ATF_CHECK_EQ(0xff, page);
	}
}

/* ================================================================
 * Model App Bind + Status (MshMDL Section 4.4.1.2 / 4.3.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_app_bind);
ATF_TC_BODY(model_app_bind, tc)
{
	struct mesh_cfg_model_app in, out;
	HEX(exp_sig, "803d020006000010", 8);
	HEX(exp_vnd, "803d02000600f1053412", 10);
	HEX(exp_status, "803e00020006000010", 9);
	uint8_t buf[16];
	size_t outlen;
	uint32_t op;
	uint8_t status;

	/* SIG model bind: opcode 0x803D, elem 0x0002, appkey 0x006, model 0x1000. */
	memset(&in, 0, sizeof(in));
	in.elem_addr = 0x0002;
	in.app_idx = 0x0006;
	in.model.vendor = 0;
	in.model.model_id = 0x1000;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &in, buf, &outlen));
	ATF_CHECK_EQ(8, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_sig, 8),
	    "Model App Bind (SIG) access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_parse(exp_sig, 8, &op, &out));
	ATF_CHECK_EQ(MESH_CFG_OP_MODEL_APP_BIND, op);
	ATF_CHECK_EQ(0x0002, out.elem_addr);
	ATF_CHECK_EQ(0x0006, out.app_idx);
	ATF_CHECK_EQ(0, out.model.vendor);
	ATF_CHECK_EQ(0x1000, out.model.model_id);

	/* Vendor model bind: 4-octet model identifier CID 0x05F1 + MID 0x1234. */
	in.model.vendor = 1;
	in.model.company_id = 0x05f1;
	in.model.model_id = 0x1234;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &in, buf, &outlen));
	ATF_CHECK_EQ(10, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_vnd, 10),
	    "Model App Bind (vendor) access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_parse(exp_vnd, 10, &op, &out));
	ATF_CHECK_EQ(1, out.model.vendor);
	ATF_CHECK_EQ(0x05f1, out.model.company_id);
	ATF_CHECK_EQ(0x1234, out.model.model_id);

	/* Model App Status: opcode 0x803E + Status + fields. */
	memset(&in, 0, sizeof(in));
	in.elem_addr = 0x0002;
	in.app_idx = 0x0006;
	in.model.model_id = 0x1000;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_status_build(MESH_CFG_SUCCESS, &in,
	    buf, &outlen));
	ATF_CHECK_EQ(9, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_status, 9),
	    "Model App Status access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_status_parse(exp_status, 9,
	    &status, &out));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0x0002, out.elem_addr);
	ATF_CHECK_EQ(0x1000, out.model.model_id);
}

/* ================================================================
 * Model Publication set/status/get (MshMDL Section 4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_publication);
ATF_TC_BODY(model_publication, tc)
{
	struct mesh_cfg_model_pub in, out;
	HEX(exp_set, "03020000c006000700000010", 12);
	uint8_t buf[20];
	size_t outlen;
	uint8_t status;

	memset(&in, 0, sizeof(in));
	in.elem_addr = 0x0002;
	in.pub_addr = 0xc000;
	in.app_idx = 0x0006;
	in.cred_flag = 0;
	in.ttl = 0x07;
	in.period = 0x00;
	in.retransmit = 0x00;
	in.model.model_id = 0x1000;

	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&in, buf, &outlen));
	ATF_CHECK_EQ(12, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_set, 12),
	    "Model Publication Set access PDU (opcode 0x03)");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_parse(exp_set, 12, &out));
	ATF_CHECK_EQ(0x0002, out.elem_addr);
	ATF_CHECK_EQ(0xc000, out.pub_addr);
	ATF_CHECK_EQ(0x0006, out.app_idx);
	ATF_CHECK_EQ(0, out.cred_flag);
	ATF_CHECK_EQ(0x07, out.ttl);
	ATF_CHECK_EQ(0x1000, out.model.model_id);

	/* CredentialFlag in bit 12 of the AppKeyIndex word. */
	in.cred_flag = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&in, buf, &outlen));
	ATF_CHECK_EQ_MSG(0x06, buf[5], "AppKeyIndex low octet unchanged");
	ATF_CHECK_EQ_MSG(0x10, buf[6], "CredentialFlag sets bit 12 -> high octet 0x10");
	memset(&out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_parse(buf, outlen, &out));
	ATF_CHECK_EQ(1, out.cred_flag);
	ATF_CHECK_EQ(0x0006, out.app_idx);

	/* Publication Status round trip (opcode 0x8019). */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_build(MESH_CFG_SUCCESS, &in,
	    buf, &outlen));
	ATF_CHECK_EQ_MSG(0x80, buf[0], "Pub Status opcode high octet");
	ATF_CHECK_EQ(0x19, buf[1]);
	ATF_CHECK_EQ_MSG(MESH_CFG_SUCCESS, buf[2], "status octet follows opcode");
	memset(&out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(buf, outlen, &status,
	    &out));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0xc000, out.pub_addr);
}

/* ================================================================
 * Model Subscription add/delete-all/status (MshMDL Section 4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_subscription);
ATF_TC_BODY(model_subscription, tc)
{
	struct mesh_cfg_model_sub in, out;
	struct mesh_cfg_model_id mid;
	HEX(exp_add, "801b020000c00010", 8);
	HEX(exp_delall, "801d02000010", 6);
	HEX(exp_status, "801f00020000c00010", 9);
	uint8_t buf[16];
	size_t outlen;
	uint32_t op;
	uint8_t status;
	uint16_t elem;

	/* Subscription Add: opcode 0x801B, elem 0x0002, address 0xC000. */
	memset(&in, 0, sizeof(in));
	in.elem_addr = 0x0002;
	in.address = 0xc000;
	in.model.model_id = 0x1000;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &in, buf, &outlen));
	ATF_CHECK_EQ(8, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_add, 8),
	    "Model Subscription Add access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_parse(exp_add, 8, &op, &out));
	ATF_CHECK_EQ(MESH_CFG_OP_MODEL_SUB_ADD, op);
	ATF_CHECK_EQ(0xc000, out.address);
	ATF_CHECK_EQ(0x1000, out.model.model_id);

	/* Delete (same struct, opcode 0x801C) differs only in the opcode. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_DELETE,
	    &in, buf, &outlen));
	ATF_CHECK_EQ(0x1c, buf[1]);

	/* Delete All: opcode 0x801D, no Address field. */
	memset(&mid, 0, sizeof(mid));
	mid.model_id = 0x1000;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_del_all_build(0x0002, &mid, buf,
	    &outlen));
	ATF_CHECK_EQ(6, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_delall, 6),
	    "Model Subscription Delete All access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_del_all_parse(exp_delall, 6, &elem,
	    &mid));
	ATF_CHECK_EQ(0x0002, elem);
	ATF_CHECK_EQ(0x1000, mid.model_id);

	/* Subscription Status: opcode 0x801F + Status. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_build(MESH_CFG_SUCCESS, &in,
	    buf, &outlen));
	ATF_CHECK_EQ(9, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_status, 9),
	    "Model Subscription Status access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_parse(exp_status, 9, &status,
	    &out));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0xc000, out.address);
}

/* ================================================================
 * Key management: AppKey/NetKey Delete/Get/List/Status.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_management);
ATF_TC_BODY(key_management, tc)
{
	HEX(exp_appstatus, "800300563412", 6);
	HEX(exp_applist, "80020056042361458907", 10);
	HEX(exp_netadd, "804023017dd7364cd842ad18c17c2b820c84c3d6", 20);
	HEX(exp_netstatus, "8044002301", 5);
	HEX(exp_netlist, "8043236145", 5);
	uint8_t buf[24];
	size_t outlen, n;
	uint8_t status;
	uint16_t net_idx, app_idx, idxs[8];
	struct mesh_cfg_netkey nk, nkout;
	uint32_t op;

	/* AppKey Status (0x8003): NetKeyIndex 0x456, AppKeyIndex 0x123. */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_build(MESH_CFG_SUCCESS, 0x456,
	    0x123, buf, &outlen));
	ATF_CHECK_EQ(6, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_appstatus, 6),
	    "AppKey Status access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(exp_appstatus, 6, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0x456, net_idx);
	ATF_CHECK_EQ(0x123, app_idx);

	/* AppKey List (0x8002): NetKeyIndex 0x456, AppKeys {0x123,0x456,0x789}. */
	{
		uint16_t apps[3] = { 0x123, 0x456, 0x789 };
		ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_build(MESH_CFG_SUCCESS,
		    0x456, apps, 3, buf, &outlen));
		ATF_CHECK_EQ(10, (int)outlen);
		ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_applist, 10),
		    "AppKey List access PDU (two-per-3-octets packing)");
	}
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_parse(exp_applist, 10, &status,
	    &net_idx, idxs, 8, &n));
	ATF_CHECK_EQ(0x456, net_idx);
	ATF_CHECK_EQ_MSG(3, (int)n, "three AppKey indexes unpacked");
	ATF_CHECK_EQ(0x123, idxs[0]);
	ATF_CHECK_EQ(0x456, idxs[1]);
	ATF_CHECK_EQ(0x789, idxs[2]);

	/* NetKey Add (0x8040): NetKeyIndex 0x123 + NetKey. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x123;
	hex_to_bytes(nk.key, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    buf, &outlen));
	ATF_CHECK_EQ(20, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_netadd, 20), "NetKey Add access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_parse(exp_netadd, 20, &op, &nkout));
	ATF_CHECK_EQ(MESH_CFG_OP_NETKEY_ADD, op);
	ATF_CHECK_EQ(0x123, nkout.net_idx);
	ATF_CHECK_EQ(0, memcmp(nkout.key, nk.key, 16));

	/* NetKey Status (0x8044). */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_build(MESH_CFG_SUCCESS, 0x123,
	    buf, &outlen));
	ATF_CHECK_EQ(0, memcmp(buf, exp_netstatus, 5));

	/* NetKey List (0x8043): {0x123, 0x456}. */
	{
		uint16_t nets[2] = { 0x123, 0x456 };
		ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_build(nets, 2, buf,
		    &outlen));
		ATF_CHECK_EQ(5, (int)outlen);
		ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_netlist, 5),
		    "NetKey List access PDU");
	}
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_parse(exp_netlist, 5, idxs, 8, &n));
	ATF_CHECK_EQ(2, (int)n);
	ATF_CHECK_EQ(0x123, idxs[0]);
	ATF_CHECK_EQ(0x456, idxs[1]);
}

/* ================================================================
 * Node-wide states + Node Reset.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_states);
ATF_TC_BODY(node_states, tc)
{
	HEX(exp_beacon, "800a01", 3);
	HEX(exp_ttl, "800d07", 3);
	HEX(exp_relay, "8027012a", 4);
	HEX(exp_reset, "8049", 2);
	HEX(exp_reset_status, "804a", 2);
	uint8_t buf[8];
	size_t outlen;
	uint32_t op;
	uint8_t val;
	struct mesh_cfg_relay relay, rout;

	/* Beacon Set (0x800A) = on. */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_BEACON_SET, 0x01,
	    buf, &outlen));
	ATF_CHECK_EQ(0, memcmp(buf, exp_beacon, 3));
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_parse(exp_beacon, 3, &op, &val));
	ATF_CHECK_EQ(MESH_CFG_OP_BEACON_SET, op);
	ATF_CHECK_EQ(0x01, val);

	/* Default TTL Set (0x800D) = 7. */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_DEFAULT_TTL_SET,
	    0x07, buf, &outlen));
	ATF_CHECK_EQ(0, memcmp(buf, exp_ttl, 3));
	ATF_CHECK_EQ_MSG(1, mesh_cfg_default_ttl_valid(0x07), "TTL 7 is valid");
	ATF_CHECK_EQ_MSG(0, mesh_cfg_default_ttl_valid(0x01),
	    "TTL 1 is prohibited");
	ATF_CHECK_EQ_MSG(0, mesh_cfg_default_ttl_valid(200),
	    "TTL > 127 is prohibited");

	/* Relay Set (0x8027): relay on, retransmit (5<<3)|2 = 0x2A. */
	memset(&relay, 0, sizeof(relay));
	relay.relay = 0x01;
	relay.retransmit = 0x2a;
	ATF_REQUIRE_EQ(0, mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_SET, &relay,
	    buf, &outlen));
	ATF_CHECK_EQ(4, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_relay, 4), "Relay Set access PDU");
	ATF_REQUIRE_EQ(0, mesh_cfg_relay_set_parse(exp_relay, 4, &op, &rout));
	ATF_CHECK_EQ(MESH_CFG_OP_RELAY_SET, op);
	ATF_CHECK_EQ(0x01, rout.relay);
	ATF_CHECK_EQ(0x2a, rout.retransmit);
	buf[0] = 0x80; buf[1] = 0x27; buf[2] = 0x02; buf[3] = 0x2a;
	ATF_CHECK_EQ(-1, mesh_cfg_relay_set_parse(buf, 4, &op, &rout));

	/* Node Reset (0x8049) and Node Reset Status (0x804A): no parameters. */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_build(buf, &outlen));
	ATF_CHECK_EQ(2, (int)outlen);
	ATF_CHECK_EQ(0, memcmp(buf, exp_reset, 2));
	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_status_build(buf, &outlen));
	ATF_CHECK_EQ(0, memcmp(buf, exp_reset_status, 2));
}

/* ================================================================
 * Malformed-message rejection (MshPRT 1.1 §3.7.3.1; MshMDL 1.1.1
 * §§4.3.1.1, 4.3.2 and 4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cfg_negatives);
ATF_TC_BODY(cfg_negatives, tc)
{
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	HEX(good_bind, "803d020006000010", 8);
	uint8_t buf[24];
	size_t outlen;
	uint32_t op;

	/* Wrong opcode fed to a parser. */
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_add_parse(good_bind, 8, &op, &ak),
	    "AppKey Add parser rejects a Model App Bind PDU");

	/* Truncated Model App Bind (missing the model identifier). */
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_app_parse(good_bind, 5, &op, &ma),
	    "truncated Model App Bind is rejected");

	/* Model identifier that is neither 2 nor 4 octets. */
	{
		HEX(bad, "803d0200060000", 7);	/* 3-octet trailing id */
		ATF_CHECK_EQ(-1, mesh_cfg_model_app_parse(bad, 7, &op, &ma));
	}

	/* Key index out of the 12-bit range on build. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x1000;	/* > 0x0FFF */
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, buf, &outlen), "NetKeyIndex > 0x0FFF is rejected");
}

/*
 * Small shared oracles used by the negative cases below.  A malformed access
 * PDU is the reserved one-octet opcode 0x7F (Section 3.7.3.1); a well-formed
 * but unexpected opcode is the two-octet 0x8100 (valid form, no cfg meaning).
 */
static const uint8_t rfu_pdu[1] = {
	BT_MSHPRT11_ACCESS_OPCODE_ONE_RFU
};
static const uint8_t wrong_pdu[2] = { 0x81, 0x00 };

/* ================================================================
 * Model identifier codec guards (Section 4.3.2): NULL arguments and a
 * length that is neither the 2-octet SIG nor the 4-octet vendor form.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_id_codec_negatives);
ATF_TC_BODY(model_id_codec_negatives, tc)
{
	struct mesh_cfg_model_id m, out;
	uint8_t buf[4];
	size_t len;

	memset(&m, 0, sizeof(m));
	m.model_id = 0x1000;

	/* encode: NULL model / out / outlen. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_id_encode(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_id_encode(&m, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_id_encode(&m, buf, NULL));

	/* decode: NULL in / out. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_id_decode(NULL, 2, &out));
	ATF_CHECK_EQ(-1, mesh_cfg_model_id_decode(buf, 2, NULL));

	/* decode: a 3-octet identifier is neither SIG (2) nor vendor (4). */
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_id_decode(buf, 3, &out),
	    "a ModelIdentifier must be exactly 2 or 4 octets");
}

/* ================================================================
 * Composition Data Page 0 encode/decode guards (Section 4.4.1.2.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(composition_negatives);
ATF_TC_BODY(composition_negatives, tc)
{
	struct mesh_cfg_comp_page0 p, out;
	uint8_t buf[600];
	size_t len, e;

	memset(&p, 0, sizeof(p));

	/* encode: NULL in / out / outlen. */
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_encode(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_encode(&p, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_encode(&p, buf, NULL));

	/* encode: too many elements. */
	p.n_elements = MESH_CFG_COMP_MAX_ELEMENTS + 1;
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_encode(&p, buf, &len));

	/* encode: an element with too many SIG models. */
	memset(&p, 0, sizeof(p));
	p.n_elements = 1;
	p.elements[0].n_sig = MESH_CFG_COMP_MAX_MODELS + 1;
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_encode(&p, buf, &len));

	/* encode: an element with too many vendor models. */
	p.elements[0].n_sig = 0;
	p.elements[0].n_vnd = MESH_CFG_COMP_MAX_MODELS + 1;
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_encode(&p, buf, &len));

	/* encode: aggregate size beyond MESH_ACCESS_PARAMS_MAX.  Four full
	 * elements (16 SIG + 16 vendor each) are 4*(4+32+64)=400 > 379. */
	memset(&p, 0, sizeof(p));
	p.n_elements = 4;
	for (e = 0; e < 4; e++) {
		p.elements[e].n_sig = MESH_CFG_COMP_MAX_MODELS;
		p.elements[e].n_vnd = MESH_CFG_COMP_MAX_MODELS;
	}
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_comp_page0_encode(&p, buf, &len),
	    "a page-0 blob beyond the access-payload maximum is rejected");

	/* decode: NULL in / out. */
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_decode(NULL, 10, &out));
	ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_decode(buf, 10, NULL));

	/* decode: fewer than the 10-octet fixed header. */
	{
		uint8_t hdr9[9] = { 0 };
		ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_decode(hdr9, 9, &out));
	}

	/* decode: more elements than MESH_CFG_COMP_MAX_ELEMENTS (nine empty
	 * elements: 10-octet header + 9 * (loc,NumS,NumV) = 46 octets). */
	{
		uint8_t nine[46] = { 0 };
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_comp_page0_decode(nine, 46, &out),
		    "more than MESH_CFG_COMP_MAX_ELEMENTS elements is rejected");
	}

	/* decode: an element header that runs past the end (off + 4 > inlen). */
	{
		uint8_t part[12] = { 0 };	/* header + 2 stray octets */
		ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_decode(part, 12, &out));
	}

	/* decode: an element that claims more SIG models than the maximum. */
	{
		uint8_t badns[14] = { 0 };
		badns[12] = MESH_CFG_COMP_MAX_MODELS + 1;	/* NumS */
		ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_decode(badns, 14, &out));
	}

	/* decode: an element whose model list runs past the end. */
	{
		uint8_t shortlist[15] = { 0 };
		shortlist[12] = 2;		/* NumS = 2 -> needs 4 octets */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_comp_page0_decode(shortlist, 15,
		    &out), "a model list that overruns the PDU is rejected");
	}
}

/* ================================================================
 * Composition Data Get / Status guards (Sections 4.4.1.2.x).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(comp_get_status_negatives);
ATF_TC_BODY(comp_get_status_negatives, tc)
{
	struct mesh_cfg_comp_status st, stout;
	uint8_t buf[8];
	uint8_t page;
	size_t len;

	/* Get parse: NULL page out-param is accepted. */
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0x00, buf, &len));
	ATF_CHECK_EQ(0, mesh_cfg_comp_get_parse(buf, len, NULL));
	/* Get parse: malformed, wrong opcode, wrong param length. */
	ATF_CHECK_EQ(-1, mesh_cfg_comp_get_parse(rfu_pdu, 1, &page));
	ATF_CHECK_EQ(-1, mesh_cfg_comp_get_parse(wrong_pdu, 2, &page));
	{
		uint8_t noparam[2] = { 0x80, 0x08 };	/* 0x8008, 0 params */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_comp_get_parse(noparam, 2, &page),
		    "Composition Data Get carries exactly one Page octet");
	}

	/* Status build: NULL in / over-long data. */
	ATF_CHECK_EQ(-1, mesh_cfg_comp_status_build(NULL, buf, &len));
	memset(&st, 0, sizeof(st));
	st.data_len = MESH_CFG_COMP_DATA_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_cfg_comp_status_build(&st, buf, &len));

	/* Status build: an empty page-data blob (page octet only). */
	memset(&st, 0, sizeof(st));
	st.page = 0x00;
	st.data_len = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_status_build(&st, buf, &len));
	ATF_CHECK_EQ_MSG(2, (int)len, "opcode 0x02 + page octet, no data");

	/* Status parse: NULL out; malformed; wrong opcode; a body with no
	 * page octet (params_len < 1); and an empty-data round trip. */
	ATF_CHECK_EQ(-1, mesh_cfg_comp_status_parse(buf, len, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_comp_status_parse(rfu_pdu, 1, &stout));
	ATF_CHECK_EQ(-1, mesh_cfg_comp_status_parse(wrong_pdu, 2, &stout));
	{
		uint8_t empty[1] = { 0x02 };	/* opcode 0x02, 0 params */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_comp_status_parse(empty, 1,
		    &stout), "Composition Data Status needs at least a Page octet");
	}
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_status_parse(buf, len, &stout));
	ATF_CHECK_EQ_MSG(0, (int)stout.data_len, "empty page-data decodes");
}

/* ================================================================
 * AppKey management guards (MshMDL 1.1.1 §§4.3.1.1 and 4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(appkey_negatives);
ATF_TC_BODY(appkey_negatives, tc)
{
	struct mesh_cfg_appkey ak, akout;
	uint8_t buf[24];
	uint8_t status;
	uint16_t net_idx, app_idx, idxs[8];
	size_t len, n;
	uint32_t op;

	memset(&ak, 0, sizeof(ak));

	/* AppKey Add build: wrong opcode; AppKeyIndex out of the 12-bit range
	 * (NetKeyIndex valid). */
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_add_build(0x1234, &ak, buf, &len),
	    "AppKey Add build rejects a non-Add/Update opcode");
	ak.net_idx = 0x001;
	ak.app_idx = 0x1000;		/* > 0x0FFF */
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    buf, &len));

	/* AppKey Add parse: NULL out; malformed; a valid Update opcode (the
	 * second accepted opcode); wrong parameter length. */
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_add_parse(buf, 20, &op, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_add_parse(rfu_pdu, 1, &op, &akout));
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x456;
	ak.app_idx = 0x123;
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_parse(buf, len, &op, &akout));
	ATF_CHECK_EQ(MESH_CFG_OP_APPKEY_UPDATE, op);
	{
		uint8_t shortadd[19] = { 0 };	/* opcode 0x00 + 18 params */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_add_parse(shortadd, 19,
		    &op, &akout), "AppKey Add needs 3 + 16 parameter octets");
	}

	/* AppKey Delete round trip + guards. */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_delete_build(0x456, 0x123, buf, &len));
	ATF_CHECK_EQ_MSG(0x80, buf[0], "AppKey Delete opcode 0x8000");
	ATF_CHECK_EQ(0x00, buf[1]);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_delete_parse(buf, len, &net_idx,
	    &app_idx));
	ATF_CHECK_EQ(0x456, net_idx);
	ATF_CHECK_EQ(0x123, app_idx);
	/* NULL out-params are accepted. */
	ATF_CHECK_EQ(0, mesh_cfg_appkey_delete_parse(buf, len, NULL, NULL));
	/* build: index out of range (each operand). */
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_delete_build(0x1000, 0x001, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_delete_build(0x001, 0x1000, buf, &len));
	/* parse: malformed, wrong opcode, wrong length. */
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_delete_parse(rfu_pdu, 1, &net_idx,
	    &app_idx));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_delete_parse(wrong_pdu, 2, &net_idx,
	    &app_idx));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_delete_parse(buf, len - 1, &net_idx,
	    &app_idx), "AppKey Delete needs exactly 3 parameter octets");

	/* AppKey Get round trip + guards. */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_get_build(0x456, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_get_parse(buf, len, &net_idx));
	ATF_CHECK_EQ(0x456, net_idx);
	ATF_CHECK_EQ(0, mesh_cfg_appkey_get_parse(buf, len, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_get_build(0x1000, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_get_parse(rfu_pdu, 1, &net_idx));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_get_parse(wrong_pdu, 2, &net_idx));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_get_parse(buf, len - 1, &net_idx),
	    "AppKey Get needs exactly 2 parameter octets");

	/* AppKey Status build: index out of range (each operand). */
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_status_build(0, 0x1000, 0x001, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_status_build(0, 0x001, 0x1000, buf,
	    &len));
	/* AppKey Status parse: NULL out-params accepted; malformed; wrong
	 * opcode; wrong length. */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_build(MESH_CFG_SUCCESS, 0x456,
	    0x123, buf, &len));
	ATF_CHECK_EQ(0, mesh_cfg_appkey_status_parse(buf, len, NULL, NULL,
	    NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_status_parse(rfu_pdu, 1, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_status_parse(wrong_pdu, 2, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_status_parse(buf, len - 1, &status,
	    &net_idx, &app_idx));

	/* AppKey List build guards: NetKeyIndex out of range; too many
	 * indexes; a non-zero count with a NULL index array; an AppKeyIndex
	 * out of range (keyidx_list_pack failure). */
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_list_build(0, 0x1000, idxs, 0, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_list_build(0, 0x001, idxs,
	    MESH_CFG_MAX_KEY_INDEXES + 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_list_build(0, 0x001, NULL, 1, buf,
	    &len));
	{
		uint16_t bad[1] = { 0x1000 };	/* > 0x0FFF */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_list_build(0, 0x001, bad, 1,
		    buf, &len), "an AppKeyIndex beyond 0x0FFF is rejected");
	}
	/* AppKey List parse: NULL app_idx array; malformed; wrong opcode; a
	 * body shorter than Status + NetKeyIndex; and NULL status/net/n. */
	{
		uint16_t apps[2] = { 0x123, 0x456 };
		ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_build(MESH_CFG_SUCCESS,
		    0x456, apps, 2, buf, &len));
	}
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_list_parse(buf, len, &status, &net_idx,
	    NULL, 8, &n));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_list_parse(rfu_pdu, 1, &status,
	    &net_idx, idxs, 8, &n));
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_list_parse(wrong_pdu, 2, &status,
	    &net_idx, idxs, 8, &n));
	{
		uint8_t shortlist[4] = { 0x80, 0x02, 0x00 }; /* opcode + 1 param */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_appkey_list_parse(shortlist, 3,
		    &status, &net_idx, idxs, 8, &n),
		    "AppKey List needs at least Status + NetKeyIndex");
	}
	ATF_CHECK_EQ(0, mesh_cfg_appkey_list_parse(buf, len, NULL, NULL, idxs, 8,
	    NULL));
}

/* ================================================================
 * NetKey management guards (MshMDL 1.1.1 §§4.3.1.1 and 4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(netkey_negatives);
ATF_TC_BODY(netkey_negatives, tc)
{
	struct mesh_cfg_netkey nk, nkout;
	uint8_t buf[24];
	uint8_t status;
	uint16_t net_idx, idxs[8];
	size_t len, n;
	uint32_t op;

	memset(&nk, 0, sizeof(nk));

	/* NetKey Add build: NULL in; wrong opcode; NetKeyIndex out of range. */
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, NULL,
	    buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_add_build(0x1234, &nk, buf, &len));
	nk.net_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    buf, &len));

	/* NetKey Add parse: NULL out; malformed; a valid Update opcode; wrong
	 * length. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x123;
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_add_parse(buf, 20, &op, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_add_parse(rfu_pdu, 1, &op, &nkout));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_parse(buf, len, &op, &nkout));
	ATF_CHECK_EQ(MESH_CFG_OP_NETKEY_UPDATE, op);
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_netkey_add_parse(buf, len - 1, &op,
	    &nkout), "NetKey Add needs 2 + 16 parameter octets");

	/* NetKey Delete round trip + guards. */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_delete_build(0x123, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_delete_parse(buf, len, &net_idx));
	ATF_CHECK_EQ(0x123, net_idx);
	ATF_CHECK_EQ(0, mesh_cfg_netkey_delete_parse(buf, len, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_delete_build(0x1000, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_delete_parse(rfu_pdu, 1, &net_idx));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_delete_parse(wrong_pdu, 2, &net_idx));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_netkey_delete_parse(buf, len - 1,
	    &net_idx), "NetKey Delete needs exactly 2 parameter octets");

	/* NetKey Status round trip + guards. */
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_status_build(0, 0x1000, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_build(MESH_CFG_SUCCESS, 0x123,
	    buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(buf, len, &status,
	    &net_idx));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0x123, net_idx);
	ATF_CHECK_EQ(0, mesh_cfg_netkey_status_parse(buf, len, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_status_parse(rfu_pdu, 1, &status,
	    &net_idx));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_status_parse(wrong_pdu, 2, &status,
	    &net_idx));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_netkey_status_parse(buf, len - 1, &status,
	    &net_idx), "NetKey Status needs exactly 3 parameter octets");

	/* NetKey List build guards: too many indexes; non-zero count with a
	 * NULL array; an index out of range. */
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_list_build(idxs,
	    MESH_CFG_MAX_KEY_INDEXES + 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_list_build(NULL, 1, buf, &len));
	{
		uint16_t bad[1] = { 0x1000 };
		ATF_CHECK_EQ(-1, mesh_cfg_netkey_list_build(bad, 1, buf, &len));
	}
	/* NetKey List parse: NULL net_idx array; malformed; wrong opcode; NULL
	 * count out-param accepted; a one-octet remainder is malformed. */
	{
		uint16_t nets[2] = { 0x123, 0x456 };
		ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_build(nets, 2, buf, &len));
	}
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_list_parse(buf, len, NULL, 8, &n));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_list_parse(rfu_pdu, 1, idxs, 8, &n));
	ATF_CHECK_EQ(-1, mesh_cfg_netkey_list_parse(wrong_pdu, 2, idxs, 8, &n));
	ATF_CHECK_EQ(0, mesh_cfg_netkey_list_parse(buf, len, idxs, 8, NULL));
	{
		uint8_t oneoct[3] = { 0x80, 0x43, 0x00 };  /* opcode + 1 octet */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_netkey_list_parse(oneoct, 3, idxs,
		    8, &n), "a one-octet key-index remainder is malformed");
	}
}

/* ================================================================
 * Key-index list packing/unpacking edge cases (Section 4.3.1.1), exercised
 * through the AppKey/NetKey List codecs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(keyidx_list_edges);
ATF_TC_BODY(keyidx_list_edges, tc)
{
	uint8_t buf[24];
	uint16_t idxs[4];
	size_t len, n;
	uint8_t status;
	uint16_t net_idx;

	/* pack: the second index of a pair is out of range. */
	{
		uint16_t pair[2] = { 0x001, 0x1000 };
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_netkey_list_build(pair, 2, buf,
		    &len), "the second index of a pair must be <= 0x0FFF");
	}

	/* unpack: a trailing odd index needs room (cnt >= max). */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_build((uint16_t[]){ 0x123 }, 1,
	    buf, &len));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_netkey_list_parse(buf, len, idxs, 0, &n),
	    "unpacking a single index needs at least one output slot");

	/* unpack: a full 3-octet pair overflows a one-slot output (cnt+2>max). */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_build((uint16_t[]){ 0x123,
	    0x456 }, 2, buf, &len));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_netkey_list_parse(buf, len, idxs, 1, &n),
	    "unpacking a pair needs two output slots");

	/* A trailing odd AppKeyIndex packs into 2 octets (pack1 path) and
	 * round-trips. */
	{
		uint16_t apps[3] = { 0x111, 0x222, 0x333 };
		ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_build(MESH_CFG_SUCCESS,
		    0x001, apps, 3, buf, &len));
		ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_parse(buf, len, &status,
		    &net_idx, idxs, 4, &n));
		ATF_CHECK_EQ_MSG(3, (int)n, "odd-length AppKey list round-trips");
		ATF_CHECK_EQ(0x333, idxs[2]);
	}
}

/* ================================================================
 * Model App Bind / Unbind / Status guards (Sections 4.4.1.2 / 4.3.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_app_negatives);
ATF_TC_BODY(model_app_negatives, tc)
{
	struct mesh_cfg_model_app ma, out;
	uint8_t buf[16];
	uint8_t status;
	size_t len;
	uint32_t op;

	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = 0x0002;
	ma.model.model_id = 0x1000;

	/* Bind build: NULL in; wrong opcode; AppKeyIndex out of range. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_build(0x1234, &ma, buf, &len));
	ma.app_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, buf, &len));

	/* Unbind (0x803F) is the second accepted opcode; round-trip it and
	 * parse with a NULL opcode out-param. */
	ma.app_idx = 0x0006;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_UNBIND,
	    &ma, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_parse(buf, len, &op, &out));
	ATF_CHECK_EQ(MESH_CFG_OP_MODEL_APP_UNBIND, op);
	ATF_CHECK_EQ(0, mesh_cfg_model_app_parse(buf, len, NULL, &out));

	/* Bind parse: NULL out; malformed; wrong opcode. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_parse(buf, len, &op, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_parse(rfu_pdu, 1, &op, &out));
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_parse(wrong_pdu, 2, &op, &out));

	/* Status build: NULL in; AppKeyIndex out of range. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_status_build(0, NULL, buf, &len));
	ma.app_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_status_build(0, &ma, buf, &len));
	ma.app_idx = 0x0006;

	/* Status parse: NULL out; NULL status accepted; malformed; wrong
	 * opcode; wrong length. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_status_build(MESH_CFG_SUCCESS, &ma,
	    buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_status_parse(buf, len, &status,
	    NULL));
	ATF_CHECK_EQ(0, mesh_cfg_model_app_status_parse(buf, len, NULL, &out));
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_status_parse(rfu_pdu, 1, &status,
	    &out));
	ATF_CHECK_EQ(-1, mesh_cfg_model_app_status_parse(wrong_pdu, 2, &status,
	    &out));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_app_status_parse(buf, len - 1,
	    &status, &out), "Model App Status length must be 7 or 9");
}

/* ================================================================
 * Model Publication set / status / get guards (Section 4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_pub_negatives);
ATF_TC_BODY(model_pub_negatives, tc)
{
	struct mesh_cfg_model_pub pub, pout;
	struct mesh_cfg_model_id mid, midout;
	uint8_t buf[20];
	uint8_t status;
	uint16_t elem;
	size_t len;

	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = 0x0002;
	pub.pub_addr = 0xc000;
	pub.model.model_id = 0x1000;

	/* Set build: NULL in; AppKeyIndex out of range. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_set_build(NULL, buf, &len));
	pub.app_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_set_build(&pub, buf, &len));
	pub.app_idx = 0x0006;

	/* Set parse: NULL out; malformed; wrong opcode; wrong length. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_set_parse(buf, len, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_set_parse(rfu_pdu, 1, &pout));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_set_parse(wrong_pdu, 2, &pout));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_pub_set_parse(buf, len - 1, &pout),
	    "Model Publication Set length must be 11 or 13");

	/* Status build: NULL in; AppKeyIndex out of range. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_status_build(0, NULL, buf, &len));
	pub.app_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_status_build(0, &pub, buf, &len));
	pub.app_idx = 0x0006;

	/* Status parse: NULL out; NULL status accepted; malformed; wrong
	 * opcode; wrong length. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_build(MESH_CFG_SUCCESS, &pub,
	    buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_status_parse(buf, len, &status,
	    NULL));
	ATF_CHECK_EQ(0, mesh_cfg_model_pub_status_parse(buf, len, NULL, &pout));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_status_parse(rfu_pdu, 1, &status,
	    &pout));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_status_parse(wrong_pdu, 2, &status,
	    &pout));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_pub_status_parse(buf, len - 1,
	    &status, &pout), "Model Publication Status length must be 12 or 14");

	/* Get round trip + guards: NULL model; NULL out-params accepted;
	 * malformed; wrong opcode; wrong length. */
	memset(&mid, 0, sizeof(mid));
	mid.model_id = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_get_build(0x0002, NULL, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_build(0x0002, &mid, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_parse(buf, len, &elem,
	    &midout));
	ATF_CHECK_EQ(0x0002, elem);
	ATF_CHECK_EQ(0x1000, midout.model_id);
	/* NULL elem_addr is accepted; a NULL model is rejected by the decoder. */
	ATF_CHECK_EQ(0, mesh_cfg_model_pub_get_parse(buf, len, NULL, &midout));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_get_parse(buf, len, &elem, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_get_parse(rfu_pdu, 1, &elem,
	    &midout));
	ATF_CHECK_EQ(-1, mesh_cfg_model_pub_get_parse(wrong_pdu, 2, &elem,
	    &midout));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_pub_get_parse(buf, len - 1, &elem,
	    &midout), "Model Publication Get length must be 4 or 6");
}

/* ================================================================
 * Model Subscription add / delete-all / status guards (Section 4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_sub_negatives);
ATF_TC_BODY(model_sub_negatives, tc)
{
	struct mesh_cfg_model_sub sub, out;
	struct mesh_cfg_model_id mid, midout;
	uint8_t buf[16];
	uint8_t status;
	uint16_t elem;
	size_t len;
	uint32_t op;

	memset(&sub, 0, sizeof(sub));
	sub.elem_addr = 0x0002;
	sub.address = 0xc000;
	sub.model.model_id = 0x1000;

	/* build: NULL in; wrong opcode; Overwrite (0x801E) is accepted. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_build(0x1234, &sub, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_OVERWRITE,
	    &sub, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_parse(buf, len, &op, &out));
	ATF_CHECK_EQ(MESH_CFG_OP_MODEL_SUB_OVERWRITE, op);
	/* Delete opcode also parses (covers the middle opcode arm). */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_DELETE,
	    &sub, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_parse(buf, len, NULL, &out));

	/* parse: NULL out; malformed; wrong opcode; wrong length. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_parse(buf, len, &op, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_parse(rfu_pdu, 1, &op, &out));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_parse(wrong_pdu, 2, &op, &out));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_sub_parse(buf, len - 1, &op, &out),
	    "Model Subscription length must be 6 or 8");

	/* Delete All: NULL model on build; NULL out-params accepted on parse;
	 * malformed; wrong opcode; wrong length. */
	memset(&mid, 0, sizeof(mid));
	mid.model_id = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_del_all_build(0x0002, NULL, buf,
	    &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_del_all_build(0x0002, &mid, buf,
	    &len));
	/* NULL elem_addr is accepted; a NULL model is rejected by the decoder. */
	ATF_CHECK_EQ(0, mesh_cfg_model_sub_del_all_parse(buf, len, NULL,
	    &midout));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_del_all_parse(buf, len, &elem, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_del_all_parse(rfu_pdu, 1, &elem,
	    &midout));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_del_all_parse(wrong_pdu, 2, &elem,
	    &midout));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_sub_del_all_parse(buf, len - 1,
	    &elem, &midout), "Delete All length must be 4 or 6");

	/* Status build: NULL in.  Status parse: NULL out; NULL status accepted;
	 * malformed; wrong opcode; wrong length. */
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_status_build(0, NULL, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_build(MESH_CFG_SUCCESS, &sub,
	    buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_status_parse(buf, len, &status,
	    NULL));
	ATF_CHECK_EQ(0, mesh_cfg_model_sub_status_parse(buf, len, NULL, &out));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_status_parse(rfu_pdu, 1, &status,
	    &out));
	ATF_CHECK_EQ(-1, mesh_cfg_model_sub_status_parse(wrong_pdu, 2, &status,
	    &out));
	ATF_CHECK_EQ_MSG(-1, mesh_cfg_model_sub_status_parse(buf, len - 1,
	    &status, &out), "Model Subscription Status length must be 7 or 9");
}

/* ================================================================
 * Node-wide single-octet state, Relay, empty messages and server state
 * (MshMDL 1.1.1 §§4.2.10-4.2.13 and 4.4.1.1-4.4.1.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_state_negatives);
ATF_TC_BODY(node_state_negatives, tc)
{
	struct mesh_cfg_relay relay, rout;
	struct mesh_cfg_server_state s;
	uint8_t buf[8];
	uint8_t val;
	size_t len;
	uint32_t op;
	size_t i;
	static const uint32_t u8_ops[] = {
		MESH_CFG_OP_BEACON_SET, MESH_CFG_OP_BEACON_STATUS,
		MESH_CFG_OP_DEFAULT_TTL_SET, MESH_CFG_OP_DEFAULT_TTL_STATUS,
		MESH_CFG_OP_GATT_PROXY_SET, MESH_CFG_OP_GATT_PROXY_STATUS,
		MESH_CFG_OP_FRIEND_SET, MESH_CFG_OP_FRIEND_STATUS,
	};

	/* u8-state build+parse for every accepted opcode of the switch. */
	for (i = 0; i < sizeof(u8_ops) / sizeof(u8_ops[0]); i++) {
		ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(u8_ops[i], 0x01, buf,
		    &len));
		ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_parse(buf, len, &op, &val));
		ATF_CHECK_EQ(u8_ops[i], op);
		ATF_CHECK_EQ(0x01, val);
	}
	/* u8-state build/parse reject a non-state opcode. */
	ATF_CHECK_EQ(-1, mesh_cfg_u8_state_build(0x1234, 0x01, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_u8_state_parse(wrong_pdu, 2, &op, &val));
	ATF_CHECK_EQ(-1, mesh_cfg_u8_state_parse(rfu_pdu, 1, &op, &val));
	/* u8-state parse: NULL out-params accepted; a state opcode with the
	 * wrong parameter length is rejected. */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_BEACON_SET, 0x01,
	    buf, &len));
	ATF_CHECK_EQ(0, mesh_cfg_u8_state_parse(buf, len, NULL, NULL));
	{
		uint8_t bad[4] = { 0x80, 0x0a, 0x01, 0x02 };	/* 2 params */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_u8_state_parse(bad, 4, &op, &val),
		    "a single-octet state carries exactly one parameter");
	}

	/* Empty message build (any Get / Node Reset). */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(MESH_CFG_OP_BEACON_GET, buf,
	    &len));
	ATF_CHECK_EQ_MSG(2, (int)len, "an empty message is opcode-only");
	/* NetKey Get is opcode-only too. */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_get_build(buf, &len));
	ATF_CHECK_EQ(2, (int)len);

	/* Relay Set build: NULL in; wrong opcode; Relay Status is accepted. */
	memset(&relay, 0, sizeof(relay));
	relay.relay = 0x01;
	relay.retransmit = 0x2a;
	ATF_CHECK_EQ(-1, mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_SET, NULL,
	    buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_relay_set_build(0x1234, &relay, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_STATUS,
	    &relay, buf, &len));
	ATF_CHECK_EQ(0x28, buf[1]);
	/* Relay parse: NULL out; NULL opcode accepted; malformed; wrong
	 * opcode; wrong length. */
	ATF_CHECK_EQ(-1, mesh_cfg_relay_set_parse(buf, len, &op, NULL));
	ATF_CHECK_EQ(0, mesh_cfg_relay_set_parse(buf, len, NULL, &rout));
	ATF_CHECK_EQ(-1, mesh_cfg_relay_set_parse(rfu_pdu, 1, &op, &rout));
	ATF_CHECK_EQ(-1, mesh_cfg_relay_set_parse(wrong_pdu, 2, &op, &rout));
	{
		uint8_t bad[3] = { 0x80, 0x27, 0x01 };	/* 1 param, need 2 */
		ATF_CHECK_EQ_MSG(-1, mesh_cfg_relay_set_parse(bad, 3, &op,
		    &rout), "Relay Set/Status carries exactly two parameters");
	}

	/* Server init is NULL-safe. */
	mesh_cfg_server_init(NULL);
	mesh_cfg_server_init(&s);
	ATF_CHECK_EQ(0, s.default_ttl);
}

/* ================================================================
 * Remaining reachable arms: NULL-opcode parses, empty key lists, a
 * wrong-opcode NetKey Add, a NumV-overflow Composition decode, a NULL
 * struct on AppKey Add build, and vendor (4-octet ModelIdentifier)
 * variants of the Status/Publication/Subscription codecs (the longer of
 * each message's two accepted parameter lengths, Section 4.3.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cfg_reachable_remainder);
ATF_TC_BODY(cfg_reachable_remainder, tc)
{
	uint8_t buf[24];
	size_t len, n;
	uint32_t op;
	uint8_t status;
	uint16_t net_idx, idxs[8];

	/* AppKey Add build rejects a NULL struct. */
	ATF_CHECK_EQ(-1, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, NULL,
	    buf, &len));

	/* AppKey/NetKey Add parse with a NULL opcode out-param. */
	{
		struct mesh_cfg_appkey ak, akout;
		struct mesh_cfg_netkey nk, nkout;

		memset(&ak, 0, sizeof(ak));
		ak.net_idx = 0x456;
		ak.app_idx = 0x123;
		ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(
		    MESH_CFG_OP_APPKEY_ADD, &ak, buf, &len));
		ATF_CHECK_EQ(0, mesh_cfg_appkey_add_parse(buf, len, NULL,
		    &akout));

		memset(&nk, 0, sizeof(nk));
		nk.net_idx = 0x123;
		ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(
		    MESH_CFG_OP_NETKEY_ADD, &nk, buf, &len));
		ATF_CHECK_EQ(0, mesh_cfg_netkey_add_parse(buf, len, NULL,
		    &nkout));
		/* NetKey Add parse rejects a valid but unrelated opcode. */
		ATF_CHECK_EQ(-1, mesh_cfg_netkey_add_parse(wrong_pdu, 2, &op,
		    &nkout));
	}

	/* Empty AppKey / NetKey lists (n == 0). */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_build(MESH_CFG_SUCCESS, 0x001,
	    NULL, 0, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_parse(buf, len, &status, &net_idx,
	    idxs, 8, &n));
	ATF_CHECK_EQ_MSG(0, (int)n, "an empty AppKey list decodes to zero indexes");
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_build(NULL, 0, buf, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_parse(buf, len, idxs, 8, &n));
	ATF_CHECK_EQ(0, (int)n);

	/* Composition Data decode rejects an element with too many vendor
	 * models (NumV > max, with NumS in range). */
	{
		uint8_t badnv[14] = { 0 };
		struct mesh_cfg_comp_page0 cout;

		badnv[12] = 0;				/* NumS */
		badnv[13] = MESH_CFG_COMP_MAX_MODELS + 1; /* NumV */
		ATF_CHECK_EQ(-1, mesh_cfg_comp_page0_decode(badnv, 14, &cout));
	}

	/* Vendor Model App Status (params_len 9). */
	{
		struct mesh_cfg_model_app ma, out;

		memset(&ma, 0, sizeof(ma));
		ma.elem_addr = 0x0002;
		ma.app_idx = 0x0006;
		ma.model.vendor = 1;
		ma.model.company_id = 0x05f1;
		ma.model.model_id = 0x1234;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_app_status_build(
		    MESH_CFG_SUCCESS, &ma, buf, &len));
		ATF_CHECK_EQ_MSG(11, (int)len, "vendor Model App Status is 11 octets");
		ATF_REQUIRE_EQ(0, mesh_cfg_model_app_status_parse(buf, len,
		    &status, &out));
		ATF_CHECK_EQ(1, out.model.vendor);
		ATF_CHECK_EQ(0x1234, out.model.model_id);
	}

	/* Vendor Model Publication Set (13), Status (14) and Get (6). */
	{
		struct mesh_cfg_model_pub pub, pout;
		struct mesh_cfg_model_id mid, midout;
		uint16_t elem;

		memset(&pub, 0, sizeof(pub));
		pub.elem_addr = 0x0002;
		pub.pub_addr = 0xc000;
		pub.app_idx = 0x0006;
		pub.model.vendor = 1;
		pub.model.company_id = 0x05f1;
		pub.model.model_id = 0x1234;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, buf, &len));
		ATF_CHECK_EQ_MSG(14, (int)len, "vendor Pub Set is 14 octets");
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_parse(buf, len, &pout));
		ATF_CHECK_EQ(0x1234, pout.model.model_id);
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_build(
		    MESH_CFG_SUCCESS, &pub, buf, &len));
		ATF_CHECK_EQ_MSG(16, (int)len, "vendor Pub Status is 16 octets");
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(buf, len,
		    &status, &pout));
		ATF_CHECK_EQ(1, pout.model.vendor);

		memset(&mid, 0, sizeof(mid));
		mid.vendor = 1;
		mid.company_id = 0x05f1;
		mid.model_id = 0x1234;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_build(0x0002, &mid, buf,
		    &len));
		ATF_CHECK_EQ_MSG(8, (int)len, "vendor Pub Get is 8 octets");
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_parse(buf, len, &elem,
		    &midout));
		ATF_CHECK_EQ(1, midout.vendor);
	}

	/* Vendor Model Subscription Add (8), Delete All (6) and Status (9). */
	{
		struct mesh_cfg_model_sub sub, out;
		struct mesh_cfg_model_id mid, midout;
		uint16_t elem;

		memset(&sub, 0, sizeof(sub));
		sub.elem_addr = 0x0002;
		sub.address = 0xc000;
		sub.model.vendor = 1;
		sub.model.company_id = 0x05f1;
		sub.model.model_id = 0x1234;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(
		    MESH_CFG_OP_MODEL_SUB_ADD, &sub, buf, &len));
		ATF_CHECK_EQ_MSG(10, (int)len, "vendor Sub Add is 10 octets");
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_parse(buf, len, &op, &out));
		ATF_CHECK_EQ(1, out.model.vendor);

		memset(&mid, 0, sizeof(mid));
		mid.vendor = 1;
		mid.company_id = 0x05f1;
		mid.model_id = 0x1234;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_del_all_build(0x0002, &mid,
		    buf, &len));
		ATF_CHECK_EQ_MSG(8, (int)len, "vendor Delete All is 8 octets");
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_del_all_parse(buf, len,
		    &elem, &midout));
		ATF_CHECK_EQ(1, midout.vendor);

		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_build(
		    MESH_CFG_SUCCESS, &sub, buf, &len));
		ATF_CHECK_EQ_MSG(11, (int)len, "vendor Sub Status is 11 octets");
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_parse(buf, len,
		    &status, &out));
		ATF_CHECK_EQ(1, out.model.vendor);
	}

	/* Opcode-family and 12-bit-index gates that sit above the shared codecs. */
	{
		struct mesh_cfg_model_id sig, vendor;
		uint16_t values[1] = { 1 };

		memset(&sig, 0, sizeof(sig));
		sig.model_id = 0x1000;
		vendor = sig;
		vendor.vendor = 1;
		vendor.company_id = 0x1234;
		ATF_CHECK_EQ(-1, mesh_cfg_model_sub_get_build(0, 1, &sig, buf,
		    &len));
		ATF_CHECK_EQ(-1, mesh_cfg_model_app_get_build(0, 1, &sig, buf,
		    &len));
		ATF_CHECK_EQ(-1, mesh_cfg_model_sub_list_build(0, 0, 1, &sig,
		    NULL, 0, buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_model_sub_list_build(
		    MESH_CFG_OP_VND_MODEL_SUB_LIST, 0, 1, &sig, NULL, 0, buf,
		    &len));
		ATF_CHECK_EQ(-1, mesh_cfg_model_sub_list_build(
		    MESH_CFG_OP_SIG_MODEL_SUB_LIST, 0, 1, &sig, NULL,
		    MESH_CFG_MAX_ADDRESSES + 1, buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_model_app_list_build(0, 0, 1, &sig,
		    NULL, 0, buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_model_app_list_build(
		    MESH_CFG_OP_SIG_MODEL_APP_LIST, 0, 1, &vendor, NULL, 0,
		    buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_model_app_list_build(
		    MESH_CFG_OP_SIG_MODEL_APP_LIST, 0, 1, &sig, values,
		    MESH_CFG_MAX_KEY_INDEXES + 1, buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_kr_phase_get_build(0x1000, buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_kr_phase_set_build(0x1000,
		    MESH_CFG_KR_TRANSITION_2, buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_kr_phase_status_build(0, 0x1000, 0,
		    buf, &len));
		ATF_CHECK_EQ(-1, mesh_cfg_node_identity_get_build(0x1000, buf,
		    &len));
		ATF_CHECK_EQ(-1, mesh_cfg_node_identity_set_build(0x1000, 0, buf,
		    &len));
		ATF_CHECK_EQ(-1, mesh_cfg_node_identity_status_build(0, 0x1000,
		    0, buf, &len));
	}
}

/* ================================================================
 * P8: additional mandatory Configuration Server messages
 * (MshMDL_v1.1 Section 4.4.1).  Field POSITION/ENDIANNESS is spec-derived;
 * all Configuration-model fields are little-endian.
 * ================================================================ */

/* The §8.3.22 Label UUID, reused for the virtual-address messages. */
static const uint8_t p8_label[BT_MSHPRT11_LABEL_UUID_SIZE] =
    BT_MSHPRT11_SAMPLE_LABEL_UUID_BYTES;

ATF_TC_WITHOUT_HEAD(net_transmit);
ATF_TC_BODY(net_transmit, tc)
{
	struct mesh_cfg_net_transmit nt, out;
	uint8_t buf[8];
	size_t len;
	uint32_t opcode;
	/* Count 2 (bits0..2), IntervalSteps 5 (bits3..7): 2|(5<<3)=0x2A. */
	const uint8_t exp_set[3] = { 0x80, 0x24, 0x2a };

	ATF_REQUIRE_EQ(0, mesh_cfg_net_transmit_get_build(buf, &len));
	ATF_CHECK_EQ(2, (int)len);
	ATF_CHECK_EQ(0x80, buf[0]);
	ATF_CHECK_EQ(0x23, buf[1]);

	memset(&nt, 0, sizeof(nt));
	nt.count = 2;
	nt.interval_steps = 5;
	ATF_REQUIRE_EQ(0, mesh_cfg_net_transmit_set_build(
	    MESH_CFG_OP_NET_TRANSMIT_SET, &nt, buf, &len));
	ATF_CHECK_EQ_MSG(3, (int)len, "Net Transmit Set is 3 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_set, 3), "Net Transmit Set wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_net_transmit_set_parse(buf, len, &opcode,
	    &out));
	ATF_CHECK_EQ(MESH_CFG_OP_NET_TRANSMIT_SET, opcode);
	ATF_CHECK_EQ(2, out.count);
	ATF_CHECK_EQ(5, out.interval_steps);

	/* Status shares the format under opcode 0x8025. */
	ATF_REQUIRE_EQ(0, mesh_cfg_net_transmit_set_build(
	    MESH_CFG_OP_NET_TRANSMIT_STATUS, &nt, buf, &len));
	ATF_CHECK_EQ(0x25, buf[1]);
	/* Out-of-range subfields rejected. */
	nt.count = 8;
	ATF_CHECK_EQ(-1, mesh_cfg_net_transmit_set_build(
	    MESH_CFG_OP_NET_TRANSMIT_SET, &nt, buf, &len));
}

ATF_TC_WITHOUT_HEAD(key_refresh_phase);
ATF_TC_BODY(key_refresh_phase, tc)
{
	uint8_t buf[8];
	size_t len;
	uint16_t net_idx;
	uint8_t status, phase, transition;
	/* NetKeyIndex 0x456 -> pack1 56 04. */
	const uint8_t exp_get[4] = { 0x80, 0x15, 0x56, 0x04 };
	const uint8_t exp_set[5] = { 0x80, 0x16, 0x56, 0x04, 0x02 };
	const uint8_t exp_status[6] = { 0x80, 0x17, 0x00, 0x56, 0x04, 0x02 };

	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_get_build(0x456, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_get, 4), "KR Phase Get wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_get_parse(buf, len, &net_idx));
	ATF_CHECK_EQ(0x456, net_idx);

	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x456,
	    MESH_CFG_KR_TRANSITION_2, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_set, 5), "KR Phase Set wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_parse(buf, len, &net_idx,
	    &transition));
	ATF_CHECK_EQ(0x456, net_idx);
	ATF_CHECK_EQ(MESH_CFG_KR_TRANSITION_2, transition);
	/* Only transitions 0x02/0x03 are valid. */
	ATF_CHECK_EQ(-1, mesh_cfg_kr_phase_set_build(0x456, 0x01, buf, &len));
	buf[4] = 0x01;
	ATF_CHECK_EQ(-1, mesh_cfg_kr_phase_set_parse(buf, 5, &net_idx,
	    &transition));

	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_build(MESH_CFG_SUCCESS,
	    0x456, MESH_CFG_KR_PHASE_2, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_status, 6), "KR Phase Status wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(buf, len, &status,
	    &net_idx, &phase));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0x456, net_idx);
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_2, phase);
}

ATF_TC_WITHOUT_HEAD(node_identity);
ATF_TC_BODY(node_identity, tc)
{
	uint8_t buf[8];
	size_t len;
	uint16_t net_idx;
	uint8_t status, identity;
	const uint8_t exp_get[4] = { 0x80, 0x46, 0x56, 0x04 };
	const uint8_t exp_set[5] = { 0x80, 0x47, 0x56, 0x04, 0x01 };
	const uint8_t exp_status[6] = { 0x80, 0x48, 0x00, 0x56, 0x04, 0x01 };

	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_get_build(0x456, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_get, 4), "Node Identity Get wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_get_parse(buf, len, &net_idx));
	ATF_CHECK_EQ(0x456, net_idx);

	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_set_build(0x456,
	    MESH_CFG_NODE_IDENTITY_RUNNING, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_set, 5), "Node Identity Set wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_set_parse(buf, len, &net_idx,
	    &identity));
	ATF_CHECK_EQ(MESH_CFG_NODE_IDENTITY_RUNNING, identity);
	buf[4] = 0x02;
	ATF_CHECK_EQ(-1, mesh_cfg_node_identity_set_parse(buf, len, &net_idx,
	    &identity));
	ATF_CHECK_EQ(-1, mesh_cfg_node_identity_set_build(0x456, 0x02, buf,
	    &len));

	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_build(MESH_CFG_SUCCESS,
	    0x456, MESH_CFG_NODE_IDENTITY_RUNNING, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_status, 6),
	    "Node Identity Status wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(buf, len, &status,
	    &net_idx, &identity));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(MESH_CFG_NODE_IDENTITY_RUNNING, identity);
}

ATF_TC_WITHOUT_HEAD(lpn_polltimeout);
ATF_TC_BODY(lpn_polltimeout, tc)
{
	uint8_t buf[8];
	size_t len;
	uint16_t lpn_addr;
	uint32_t poll_timeout;
	/* LPNAddress 0x0102 (LE 02 01); PollTimeout 0x0F4240 (LE 40 42 0F). */
	const uint8_t exp_get[4] = { 0x80, 0x2d, 0x02, 0x01 };
	const uint8_t exp_status[7] = {
		0x80, 0x2e, 0x02, 0x01, 0x40, 0x42, 0x0f
	};

	ATF_REQUIRE_EQ(0, mesh_cfg_lpn_polltimeout_get_build(0x0102, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_get, 4), "LPN PollTimeout Get wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_lpn_polltimeout_get_parse(buf, len,
	    &lpn_addr));
	ATF_CHECK_EQ(0x0102, lpn_addr);

	ATF_REQUIRE_EQ(0, mesh_cfg_lpn_polltimeout_status_build(0x0102, 0x0f4240,
	    buf, &len));
	ATF_CHECK_EQ_MSG(7, (int)len, "LPN PollTimeout Status is 7 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_status, 7),
	    "LPN PollTimeout Status wire (24-bit LE PollTimeout)");
	ATF_REQUIRE_EQ(0, mesh_cfg_lpn_polltimeout_status_parse(buf, len,
	    &lpn_addr, &poll_timeout));
	ATF_CHECK_EQ(0x0102, lpn_addr);
	ATF_CHECK_EQ_MSG(0x0f4240u, poll_timeout, "PollTimeout round-trips");
	/* PollTimeout is a 24-bit field. */
	ATF_CHECK_EQ(-1, mesh_cfg_lpn_polltimeout_status_build(0x0102, 0x1000000,
	    buf, &len));
}

ATF_TC_WITHOUT_HEAD(model_sub_get_list);
ATF_TC_BODY(model_sub_get_list, tc)
{
	struct mesh_cfg_model_id sig = { .model_id = 0x1000, .vendor = 0 };
	struct mesh_cfg_model_id vnd = {
		.company_id = 0x05f1, .model_id = 0x1234, .vendor = 1
	};
	struct mesh_cfg_model_id gotm;
	uint16_t addrs[4], elem_addr;
	uint8_t buf[32];
	size_t len, n;
	uint32_t opcode;
	uint8_t status;
	/* SIG Get: elem 0x0003, model 0x1000 -> 80 29 03 00 00 10. */
	const uint8_t exp_sig_get[6] = { 0x80, 0x29, 0x03, 0x00, 0x00, 0x10 };
	/*
	 * SIG List: status 0, elem 0x0003, model 0x1000, addrs 0xC001,0xC105
	 * -> 80 2A 00 03 00 00 10 01 C0 05 C1.
	 */
	const uint8_t exp_sig_list[11] = {
		0x80, 0x2a, 0x00, 0x03, 0x00, 0x00, 0x10, 0x01, 0xc0, 0x05,
		0xc1
	};
	/* Vendor Get: elem 0x0003, company 0x05F1, model 0x1234. */
	const uint8_t exp_vnd_get[8] = {
		0x80, 0x2b, 0x03, 0x00, 0xf1, 0x05, 0x34, 0x12
	};

	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_get_build(
	    MESH_CFG_OP_SIG_MODEL_SUB_GET, 0x0003, &sig, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_sig_get, 6), "SIG Sub Get wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_get_parse(buf, len, &opcode,
	    &elem_addr, &gotm));
	ATF_CHECK_EQ(MESH_CFG_OP_SIG_MODEL_SUB_GET, opcode);
	ATF_CHECK_EQ(0x0003, elem_addr);
	ATF_CHECK_EQ(0x1000, gotm.model_id);
	ATF_CHECK_EQ(0, gotm.vendor);

	addrs[0] = 0xc001;
	addrs[1] = 0xc105;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_list_build(
	    MESH_CFG_OP_SIG_MODEL_SUB_LIST, MESH_CFG_SUCCESS, 0x0003, &sig,
	    addrs, 2, buf, &len));
	ATF_CHECK_EQ_MSG(11, (int)len, "SIG Sub List is 11 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_sig_list, 11), "SIG Sub List wire");
	memset(addrs, 0, sizeof(addrs));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_list_parse(buf, len, &opcode,
	    &status, &elem_addr, &gotm, addrs, 4, &n));
	ATF_CHECK_EQ(MESH_CFG_OP_SIG_MODEL_SUB_LIST, opcode);
	ATF_CHECK_EQ(0x0003, elem_addr);
	ATF_CHECK_EQ_MSG(2, (int)n, "two subscribed addresses");
	ATF_CHECK_EQ(0xc001, addrs[0]);
	ATF_CHECK_EQ(0xc105, addrs[1]);

	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_get_build(
	    MESH_CFG_OP_VND_MODEL_SUB_GET, 0x0003, &vnd, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_vnd_get, 8), "Vendor Sub Get wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_get_parse(buf, len, &opcode,
	    &elem_addr, &gotm));
	ATF_CHECK_EQ(1, gotm.vendor);
	ATF_CHECK_EQ(0x05f1, gotm.company_id);
	ATF_CHECK_EQ(0x1234, gotm.model_id);
}

ATF_TC_WITHOUT_HEAD(model_app_get_list);
ATF_TC_BODY(model_app_get_list, tc)
{
	struct mesh_cfg_model_id sig = { .model_id = 0x1000, .vendor = 0 };
	struct mesh_cfg_model_id gotm;
	uint16_t app_idx[4], elem_addr;
	uint8_t buf[32];
	size_t len, n;
	uint32_t opcode;
	uint8_t status;
	/* SIG App Get: elem 0x0003, model 0x1000 -> 80 4B 03 00 00 10. */
	const uint8_t exp_sig_get[6] = { 0x80, 0x4b, 0x03, 0x00, 0x00, 0x10 };
	/*
	 * SIG App List: status 0, elem 0x0003, model 0x1000, app 0x001,0x002.
	 * keyidx pack2(0x001,0x002)=01 20 00 -> 80 4C 00 03 00 00 10 01 20 00.
	 */
	const uint8_t exp_sig_list[10] = {
		0x80, 0x4c, 0x00, 0x03, 0x00, 0x00, 0x10, 0x01, 0x20, 0x00
	};

	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_get_build(
	    MESH_CFG_OP_SIG_MODEL_APP_GET, 0x0003, &sig, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_sig_get, 6), "SIG App Get wire");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_get_parse(buf, len, &opcode,
	    &elem_addr, &gotm));
	ATF_CHECK_EQ(MESH_CFG_OP_SIG_MODEL_APP_GET, opcode);
	ATF_CHECK_EQ(0x1000, gotm.model_id);

	app_idx[0] = 0x001;
	app_idx[1] = 0x002;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_list_build(
	    MESH_CFG_OP_SIG_MODEL_APP_LIST, MESH_CFG_SUCCESS, 0x0003, &sig,
	    app_idx, 2, buf, &len));
	ATF_CHECK_EQ_MSG(10, (int)len, "SIG App List is 10 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_sig_list, 10), "SIG App List wire");
	memset(app_idx, 0, sizeof(app_idx));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_list_parse(buf, len, &opcode,
	    &status, &elem_addr, &gotm, app_idx, 4, &n));
	ATF_CHECK_EQ(0x0003, elem_addr);
	ATF_CHECK_EQ_MSG(2, (int)n, "two bound AppKey indexes");
	ATF_CHECK_EQ(0x001, app_idx[0]);
	ATF_CHECK_EQ(0x002, app_idx[1]);
}

ATF_TC_WITHOUT_HEAD(virtual_pub_sub);
ATF_TC_BODY(virtual_pub_sub, tc)
{
	struct mesh_cfg_model_pub_va pub, gotpub;
	struct mesh_cfg_model_sub_va sub, gotsub;
	uint8_t buf[40];
	size_t len;
	uint32_t opcode;

	/* Model Publication Virtual Address Set (0x801A). */
	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = 0x0003;
	memcpy(pub.label, p8_label, 16);
	pub.app_idx = 0x123;
	pub.cred_flag = 0;
	pub.ttl = 0x05;
	pub.period = 0x00;
	pub.retransmit = 0x00;
	pub.model.model_id = 0x1000;
	pub.model.vendor = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_va_set_build(&pub, buf, &len));
	/* 2 opcode + 2 elem + 16 label + 2 word + 1 ttl + 1 period + 1 rtx +
	 * 2 model = 27. */
	ATF_CHECK_EQ_MSG(27, (int)len, "Pub VA Set (SIG) is 27 octets");
	ATF_CHECK_EQ_MSG(0x80, buf[0], "opcode 0x801A high");
	ATF_CHECK_EQ_MSG(0x1a, buf[1], "opcode 0x801A low");
	ATF_CHECK_EQ_MSG(0x03, buf[2], "elem addr LE low");
	ATF_CHECK_EQ_MSG(0, memcmp(buf + 4, p8_label, 16), "Label UUID inline");
	/* AppKeyIndex/CredentialFlag word 0x0123 -> LE 23 01. */
	ATF_CHECK_EQ(0x23, buf[20]);
	ATF_CHECK_EQ(0x01, buf[21]);
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_va_set_parse(buf, len, &gotpub));
	ATF_CHECK_EQ(0x0003, gotpub.elem_addr);
	ATF_CHECK_EQ_MSG(0, memcmp(gotpub.label, p8_label, 16),
	    "Label UUID round-trips");
	ATF_CHECK_EQ(0x123, gotpub.app_idx);
	ATF_CHECK_EQ(0x1000, gotpub.model.model_id);

	/* Model Subscription Virtual Address Add (0x8020). */
	memset(&sub, 0, sizeof(sub));
	sub.elem_addr = 0x0003;
	memcpy(sub.label, p8_label, 16);
	sub.model.model_id = 0x1000;
	sub.model.vendor = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_va_build(
	    MESH_CFG_OP_MODEL_SUB_VA_ADD, &sub, buf, &len));
	/* 2 opcode + 2 elem + 16 label + 2 model = 22. */
	ATF_CHECK_EQ_MSG(22, (int)len, "Sub VA Add (SIG) is 22 octets");
	ATF_CHECK_EQ(0x80, buf[0]);
	ATF_CHECK_EQ(0x20, buf[1]);
	ATF_CHECK_EQ_MSG(0, memcmp(buf + 4, p8_label, 16), "Label UUID inline");
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_va_parse(buf, len, &opcode,
	    &gotsub));
	ATF_CHECK_EQ(MESH_CFG_OP_MODEL_SUB_VA_ADD, opcode);
	ATF_CHECK_EQ_MSG(0, memcmp(gotsub.label, p8_label, 16),
	    "Label UUID round-trips");

	/* Delete (0x8021) and Overwrite (0x8022) share the codec. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_va_build(
	    MESH_CFG_OP_MODEL_SUB_VA_DELETE, &sub, buf, &len));
	ATF_CHECK_EQ(0x21, buf[1]);
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_va_build(
	    MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE, &sub, buf, &len));
	ATF_CHECK_EQ(0x22, buf[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, keyidx_packing);
	ATF_TP_ADD_TC(tp, appkey_add_msg6);
	ATF_TP_ADD_TC(tp, composition_data);
	ATF_TP_ADD_TC(tp, model_app_bind);
	ATF_TP_ADD_TC(tp, model_publication);
	ATF_TP_ADD_TC(tp, model_subscription);
	ATF_TP_ADD_TC(tp, key_management);
	ATF_TP_ADD_TC(tp, node_states);
	ATF_TP_ADD_TC(tp, cfg_negatives);
	ATF_TP_ADD_TC(tp, model_id_codec_negatives);
	ATF_TP_ADD_TC(tp, composition_negatives);
	ATF_TP_ADD_TC(tp, comp_get_status_negatives);
	ATF_TP_ADD_TC(tp, appkey_negatives);
	ATF_TP_ADD_TC(tp, netkey_negatives);
	ATF_TP_ADD_TC(tp, keyidx_list_edges);
	ATF_TP_ADD_TC(tp, model_app_negatives);
	ATF_TP_ADD_TC(tp, model_pub_negatives);
	ATF_TP_ADD_TC(tp, model_sub_negatives);
	ATF_TP_ADD_TC(tp, node_state_negatives);
	ATF_TP_ADD_TC(tp, cfg_reachable_remainder);
	ATF_TP_ADD_TC(tp, net_transmit);
	ATF_TP_ADD_TC(tp, key_refresh_phase);
	ATF_TP_ADD_TC(tp, node_identity);
	ATF_TP_ADD_TC(tp, lpn_polltimeout);
	ATF_TP_ADD_TC(tp, model_sub_get_list);
	ATF_TP_ADD_TC(tp, model_app_get_list);
	ATF_TP_ADD_TC(tp, virtual_pub_sub);

	return (atf_no_error());
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Bluetooth Mesh network manager / provisioner application
 * (lib/libmesh/mesh_manager.c) and its meshd Provisioner-role wiring.
 *
 * The manager is the layer that CREATES and owns a mesh network: it mints the
 * primary NetKey / AppKey (MPROV1), allocates unicast addresses (MPROV2), keeps
 * a provisioned-node roster and DevKey store (MPROV3) and drives a just-
 * provisioned node as a Config Client (MPROV4).  These tests assert behaviour
 * and on-the-wire spec bytes (MshPRT 1.1 §§3.4, 3.7, and 4.2-4.4),
 * and run one create-network + provision-two-devices + configure end-to-end
 * scenario over the real provisioning protocol and Configuration Server.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "mesh_transport.h"
#include "mesh_generic.h"
#include "spec_mesh_cfg_v11_oracles.h"
#include "spec_mesh_heartbeat_oracles.h"
#include "spec_mesh_manager_oracles.h"

/* Two-octet Mesh Access opcodes are encoded most-significant octet first. */
#define CHECK_OPCODE2(buf, expected) do {                              \
	ATF_CHECK_EQ(BT_MMGR_OPCODE_HI(expected), (buf)[0]);             \
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(expected), (buf)[1]);             \
} while (0)

/* ================================================================
 * MPROV1 - create-network.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(create_network);
ATF_TC_BODY(create_network, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	uint8_t nk[16], ak[16], zero[16];

	memset(zero, 0, sizeof(zero));
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, nk, ak));

	/* IV Index and both key indexes fixed at 0 (MshPRT Section 4). */
	ATF_CHECK_EQ(0u, mgr->iv_index);
	ATF_CHECK_EQ(0u, mgr->netkey_index);
	ATF_CHECK_EQ(0u, mgr->appkey_index);
	/* Provisioner's own node at unicast 0x0001, one element. */
	ATF_CHECK_EQ(BT_MMGR_UNICAST_MIN, mgr->self_addr);
	ATF_CHECK_EQ(1, mgr->self_elements);
	/* Allocator starts just past the Provisioner's element block. */
	ATF_CHECK_EQ(0x0002, mgr->next_unicast);
	/* Empty roster, no pending reservation. */
	ATF_CHECK_EQ(0u, mesh_mgr_node_count(mgr));
	ATF_CHECK_EQ(0, mgr->pending.active);

	/* Keys were minted (non-zero) and distinct from each other. */
	ATF_CHECK(memcmp(nk, zero, 16) != 0);
	ATF_CHECK(memcmp(ak, zero, 16) != 0);
	ATF_CHECK(memcmp(nk, ak, 16) != 0);
	ATF_CHECK_EQ(0, memcmp(nk, mgr->netkey, 16));
	ATF_CHECK_EQ(0, memcmp(ak, mgr->appkey, 16));
	/* The Provisioner has its own DevKey, distinct from the network keys. */
	ATF_CHECK(memcmp(mgr->self_devkey, zero, 16) != 0);
	ATF_CHECK(memcmp(mgr->self_devkey, nk, 16) != 0);

	/* NULL out arguments are accepted. */
	ATF_CHECK_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_mgr_create_network(NULL, NULL, NULL));
}

/* ================================================================
 * MPROV2 - unicast allocator: sequential, element spacing, exhaustion.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(alloc_unicast);
ATF_TC_BODY(alloc_unicast, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	uint16_t a;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));

	/* Sequential single-element allocations start at 0x0002. */
	ATF_REQUIRE_EQ(0, mesh_mgr_alloc_unicast(mgr, 1, &a));
	ATF_CHECK_EQ(0x0002, a);
	ATF_REQUIRE_EQ(0, mesh_mgr_alloc_unicast(mgr, 1, &a));
	ATF_CHECK_EQ(0x0003, a);

	/* A 2-element device consumes two consecutive addresses (0x0004,0x0005). */
	ATF_REQUIRE_EQ(0, mesh_mgr_alloc_unicast(mgr, 2, &a));
	ATF_CHECK_EQ(0x0004, a);
	ATF_REQUIRE_EQ(0, mesh_mgr_alloc_unicast(mgr, 1, &a));
	ATF_CHECK_EQ(0x0006, a);

	/* Zero elements is rejected. */
	ATF_CHECK_EQ(-1, mesh_mgr_alloc_unicast(mgr, 0, &a));

	/* Exhaustion at the top of the unicast range (0x7FFF). */
	mgr->next_unicast = BT_MMGR_UNICAST_MAX;
	ATF_CHECK_EQ(-1, mesh_mgr_alloc_unicast(mgr, 2, &a)); /* would hit 0x8000 */
	ATF_REQUIRE_EQ(0, mesh_mgr_alloc_unicast(mgr, 1, &a));
	ATF_CHECK_EQ(BT_MMGR_UNICAST_MAX, a);
	ATF_CHECK_EQ(-1, mesh_mgr_alloc_unicast(mgr, 1, &a)); /* nothing left */
}

/* ================================================================
 * MPROV3 - roster add / lookup / remove and collision safety.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(roster_ops);
ATF_TC_BODY(roster_ops, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	struct mesh_mgr_node *n;
	uint8_t uuidA[16], uuidB[16], dkA[16], dkB[16];

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	memset(uuidA, 0xA1, sizeof(uuidA));
	memset(uuidB, 0xB2, sizeof(uuidB));
	memset(dkA, 0x11, sizeof(dkA));
	memset(dkB, 0x22, sizeof(dkB));

	/* A: one element at 0x0002; B: two elements at 0x0003. */
	n = mesh_mgr_add_node(mgr, uuidA, 0x0002, 1, dkA, 100);
	ATF_REQUIRE(n != NULL);
	n = mesh_mgr_add_node(mgr, uuidB, 0x0003, 2, dkB, 200);
	ATF_REQUIRE(n != NULL);
	ATF_CHECK_EQ(2u, mesh_mgr_node_count(mgr));

	/* Overlap with the Provisioner (0x0001) and with a node are rejected. */
	ATF_CHECK(mesh_mgr_add_node(mgr, uuidA, BT_MMGR_UNICAST_MIN, 1, dkA,
	    0) == NULL);
	ATF_CHECK(mesh_mgr_add_node(mgr, uuidA, 0x0002, 1, dkA, 0) == NULL);
	ATF_CHECK(mesh_mgr_add_node(mgr, uuidA, 0x0004, 1, dkA, 0) == NULL);
	ATF_CHECK(mesh_mgr_add_node(mgr, uuidA, BT_MMGR_UNASSIGNED, 1, dkA,
	    0) == NULL);

	/* Lookup by address, including an interior element of a multi-element node. */
	ATF_CHECK(mesh_mgr_find_by_addr(mgr, 0x0002)->addr == 0x0002);
	ATF_CHECK(mesh_mgr_find_by_addr(mgr, 0x0004)->addr == 0x0003);
	ATF_CHECK(mesh_mgr_find_by_addr(mgr, 0x0006) == NULL);
	/* Lookup by UUID, and the stored DevKey. */
	n = mesh_mgr_find_by_uuid(mgr, uuidB);
	ATF_REQUIRE(n != NULL);
	ATF_CHECK_EQ(0x0003, n->addr);
	ATF_CHECK_EQ(0, memcmp(n->devkey, dkB, 16));

	/* Remove by primary address only. */
	ATF_CHECK_EQ(-1, mesh_mgr_remove_node(mgr, 0x0004)); /* interior, not primary */
	ATF_CHECK_EQ(0, mesh_mgr_remove_node(mgr, 0x0003));
	ATF_CHECK_EQ(1u, mesh_mgr_node_count(mgr));
	ATF_CHECK(mesh_mgr_find_by_uuid(mgr, uuidB) == NULL);
	ATF_CHECK(mesh_mgr_find_by_uuid(mgr, uuidA) != NULL);
}

/* ================================================================
 * MPROV3 - persistence round-trip and CRC gating.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(roster_persist);
ATF_TC_BODY(roster_persist, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct mesh_mgr, loaded);
	uint8_t uuidA[16], uuidB[16], dkA[16], dkB[16];
	const char *path = "mesh_mgr_persist.tmp";
	FILE *f;
	long sz;
	uint8_t byte;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	memset(uuidA, 0xA1, sizeof(uuidA));
	memset(uuidB, 0xB2, sizeof(uuidB));
	memset(dkA, 0x11, sizeof(dkA));
	memset(dkB, 0x22, sizeof(dkB));
	ATF_REQUIRE(mesh_mgr_add_node(mgr, uuidA, 0x0002, 1, dkA, 111) != NULL);
	ATF_REQUIRE(mesh_mgr_add_node(mgr, uuidB, 0x0003, 2, dkB, 222) != NULL);

	ATF_REQUIRE_EQ(0, mesh_mgr_save(mgr, path));

	/* A clean load reproduces the network keys, self node and roster. */
	ATF_REQUIRE_EQ(0, mesh_mgr_load(loaded, path));
	ATF_CHECK_EQ(0, memcmp(loaded->netkey, mgr->netkey, 16));
	ATF_CHECK_EQ(0, memcmp(loaded->appkey, mgr->appkey, 16));
	ATF_CHECK_EQ(0, memcmp(loaded->self_devkey, mgr->self_devkey, 16));
	ATF_CHECK_EQ(mgr->self_addr, loaded->self_addr);
	ATF_CHECK_EQ(mgr->next_unicast, loaded->next_unicast);
	ATF_CHECK_EQ(2u, mesh_mgr_node_count(loaded));
	ATF_CHECK_EQ(0, memcmp(mesh_mgr_node_at(loaded, 1)->devkey, dkB, 16));
	ATF_CHECK_EQ(0x0003, mesh_mgr_node_at(loaded, 1)->addr);
	ATF_CHECK_EQ(2, mesh_mgr_node_at(loaded, 1)->num_elements);

	/* Corrupting a payload byte must fail the CRC and reject the load. */
	f = fopen(path, "r+b");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(0, fseek(f, 0, SEEK_END));
	sz = ftell(f);
	ATF_REQUIRE(sz > 40);
	ATF_REQUIRE_EQ(0, fseek(f, 40, SEEK_SET));
	ATF_REQUIRE_EQ(1, fread(&byte, 1, 1, f));
	byte ^= 0xFF;
	ATF_REQUIRE_EQ(0, fseek(f, 40, SEEK_SET));
	ATF_REQUIRE_EQ(1, fwrite(&byte, 1, 1, f));
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_CHECK_EQ(-1, mesh_mgr_load(loaded, path));

	/* A missing file is rejected too. */
	ATF_REQUIRE_EQ(0, unlink(path));
	ATF_CHECK_EQ(-1, mesh_mgr_load(loaded, path));
}

/* ================================================================
 * MPROV4 - Config Client PDU spec bytes.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cfg_client_bytes);
ATF_TC_BODY(cfg_client_bytes, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	struct mesh_cfg_model_id model;
	uint8_t pdu[64];
	size_t len;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));

	/* AppKey Add: opcode 0x00, NetKeyIdx/AppKeyIdx packing {00 00 00}, AppKey. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, pdu, &len));
	ATF_CHECK_EQ(1u + 3u + 16u, len);
	ATF_CHECK_EQ(BT_MMGR_OP_APPKEY_ADD, pdu[0]);
	ATF_CHECK_EQ(0x00, pdu[1]);
	ATF_CHECK_EQ(0x00, pdu[2]);
	ATF_CHECK_EQ(0x00, pdu[3]);
	ATF_CHECK_EQ(0, memcmp(pdu + 4, mgr->appkey, 16));

	/* Model App Bind: opcode 0x803D, ElemAddr LE, AppKeyIdx LE, ModelId LE. */
	memset(&model, 0, sizeof(model));
	model.model_id = BT_MMGR_MODEL_GEN_ONOFF_SRV;	/* 0x1000 */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr, 0x0002, &model,
	    pdu, &len));
	ATF_CHECK_EQ(2u + 2u + 2u + 2u, len);
	CHECK_OPCODE2(pdu, BT_MMGR_OP_MODEL_APP_BIND);
	ATF_CHECK_EQ(0x02, pdu[2]);	/* elem addr 0x0002 LE */
	ATF_CHECK_EQ(0x00, pdu[3]);
	ATF_CHECK_EQ(0x00, pdu[4]);	/* app idx 0 */
	ATF_CHECK_EQ(0x00, pdu[5]);
	ATF_CHECK_EQ(0x00, pdu[6]);	/* model id 0x1000 LE */
	ATF_CHECK_EQ(0x10, pdu[7]);
}

/* ================================================================
 * DevKey seal/open round-trip (MshPRT_v1.1 Section 3.6.5.1 device nonce).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(devkey_roundtrip);
ATF_TC_BODY(devkey_roundtrip, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	struct mesh_mgr_node *node;
	uint8_t uuid[16], devkey[16];
	uint8_t access[20], upper[64], recovered[64];
	size_t alen = sizeof(access), ulen, rlen;
	uint32_t seq0, seq1;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	memset(uuid, 0xC3, sizeof(uuid));
	memset(devkey, 0x5A, sizeof(devkey));
	node = mesh_mgr_add_node(mgr, uuid, 0x0002, 1, devkey, 0);
	ATF_REQUIRE(node != NULL);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, access, &alen));

	/* seal consumes a sequence number; two seals use consecutive seqs. */
	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_seal(mgr, node, access, alen, &seq0,
	    upper, &ulen));
	ATF_CHECK_EQ(0u, seq0);
	ATF_CHECK_EQ(alen + BT_MMGR_TRANS_MIC32_SIZE, ulen);
	{
		uint8_t u2[64];
		size_t u2len;

		ATF_REQUIRE_EQ(0, mesh_mgr_devkey_seal(mgr, node, access, alen,
		    &seq1, u2, &u2len));
		ATF_CHECK_EQ(1u, seq1);
	}

	/* Open with the matching (seq, src=self, dst=node) recovers the plaintext. */
	rlen = sizeof(recovered);
	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_open(mgr, node, seq0, mgr->self_addr,
	    node->addr, upper, ulen, recovered, &rlen));
	ATF_CHECK_EQ(alen, rlen);
	ATF_CHECK_EQ(0, memcmp(recovered, access, alen));

	/* A wrong sequence number in the nonce fails the MIC. */
	rlen = sizeof(recovered);
	ATF_CHECK_EQ(-1, mesh_mgr_devkey_open(mgr, node, seq0 + 7, mgr->self_addr,
	    node->addr, upper, ulen, recovered, &rlen));
}

/* ================================================================
 * End-to-end: create a network, provision TWO devices over the real
 * provisioning protocol with the manager auto-filling the data and recording
 * the roster, then configure device A as a Config Client.
 * ================================================================ */

static void
base_config(struct meshd_config *cfg, const uint8_t netkey[16], uint16_t addr)
{

	meshd_config_defaults(cfg);
	memcpy(cfg->netkey, netkey, 16);
	memset(cfg->appkey, 0x77, 16);		/* unused by the config server DB */
	cfg->have_netkey = 1;
	cfg->have_appkey = 1;
	cfg->netkey_index = 0;
	cfg->appkey_index = 0;
	cfg->unicast_addr = addr;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
}

/*
 * Provision one device end-to-end through the meshd Provisioner and a
 * simulated device session, driven from the manager.  Records the node and
 * returns its address and DevKey.
 */
static void
provision_device(struct meshd_node *nd, struct mesh_mgr *mgr,
    const uint8_t uuid[16], uint8_t nelem, uint32_t link_id,
    uint16_t *out_addr, uint8_t out_devkey[16])
{
	struct mesh_prov_link dl;
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_mgr_node *node;
	uint8_t pkt[MESH_PBADV_PKT_MAX], dev_ack[MESH_PBADV_PKT_MAX];
	uint8_t rpdu[MESH_PROV_PDU_MAX];
	size_t len, rlen, dev_ack_len;
	int have_pdu, have_ack, dev_ack_pending, i;
	uint64_t now = 0;

	memset(&caps, 0, sizeof(caps));
	caps.num_elements = nelem;
	caps.algorithms = BT_MMGR_PROV_ALGO_P256_CMAC;
	mesh_prov_link_init_device(&dl, uuid, 100000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&ds, NULL, NULL, &caps));
	dev_ack_pending = 0;

	/* begin_mgr allocates the address and fills the provisioning data. */
	ATF_REQUIRE_EQ(0, meshd_provisioner_begin_mgr(nd, mgr, uuid, nelem,
	    link_id, NULL, NULL, 0x00, 100000, 3, now, pkt, &len));
	have_ack = have_pdu = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, len, now, rpdu, &rlen,
	    &have_pdu, dev_ack, &dev_ack_len, &have_ack));
	if (have_ack)
		dev_ack_pending = 1;

	for (i = 0; i < 400; i++) {
		if (meshd_provisioner_poll(nd, now, pkt, &len) == 1) {
			have_ack = have_pdu = 0;
			ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, len, now,
			    rpdu, &rlen, &have_pdu, dev_ack, &dev_ack_len,
			    &have_ack));
			if (have_ack)
				dev_ack_pending = 1;
			if (have_pdu)
				(void)mesh_prov_session_recv(&ds, rpdu, rlen);
			continue;
		}
		if (dev_ack_pending) {
			ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, dev_ack,
			    dev_ack_len, now));
			dev_ack_pending = 0;
			continue;
		}
		{
			int rc = mesh_prov_link_poll(&dl, now, pkt, &len);

			if (rc == 1) {
				ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, pkt,
				    len, now));
				continue;
			}
			if (mesh_prov_link_idle(&dl)) {
				uint8_t spdu[MESH_PROV_PDU_MAX];
				size_t slen;

				if (mesh_prov_session_poll(&ds, spdu, &slen) == 1) {
					ATF_REQUIRE_EQ(0, mesh_prov_link_send(&dl,
					    spdu, slen, now));
					continue;
				}
			}
		}
		if (meshd_provisioner_done(nd) && mesh_prov_session_done(&ds))
			break;
	}
	ATF_REQUIRE(meshd_provisioner_done(nd));
	ATF_REQUIRE(mesh_prov_session_done(&ds));

	/* commit_mgr records the node + DevKey; both sides derived the same key. */
	node = meshd_provisioner_commit_mgr(nd, mgr, 0x1234);
	ATF_REQUIRE(node != NULL);
	ATF_CHECK_EQ(0, memcmp(node->devkey, mesh_prov_session_devkey(&ds), 16));
	if (out_addr != NULL)
		*out_addr = node->addr;
	if (out_devkey != NULL)
		memcpy(out_devkey, node->devkey, 16);

	mesh_prov_session_free(&ds);
	mesh_prov_session_free(&nd->prov_sess);
}

/*
 * Run one DevKey-encrypted Config request against a Config Server node and
 * return the parsed Status.  The manager seals the request; the node decrypts,
 * processes it and encrypts the reply; the manager opens and reports it.
 */
static uint8_t
cfg_exchange(struct mesh_mgr *mgr, const struct mesh_mgr_node *node,
    struct meshd_node *dev, const uint8_t *req, size_t req_len,
    uint8_t *reply_access, size_t *reply_len)
{
	uint8_t upper[MESH_UPPER_MAX], plain[MESH_ACCESS_MAX];
	uint8_t reply[MESH_ACCESS_MAX], rupper[MESH_UPPER_MAX];
	size_t ulen, plen, rlen, rulen;
	uint32_t seq;

	/* Manager -> node: seal, then the node decrypts under its DevKey. */
	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_seal(mgr, node, req, req_len, &seq,
	    upper, &ulen));
	plen = sizeof(plain);
	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_open(mgr, node, seq, mgr->self_addr,
	    node->addr, upper, ulen, plain, &plen));
	ATF_REQUIRE_EQ(req_len, plen);
	ATF_REQUIRE_EQ(0, memcmp(plain, req, req_len));

	/* Node processes the Configuration message and emits a reply. */
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(dev, plain, plen, reply,
	    sizeof(reply), &rlen));

	/* Node -> manager: the node seals the reply, the manager opens it. */
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(node->devkey, 0, 0, 0, node->addr,
	    mgr->self_addr, mgr->iv_index, NULL, reply, rlen, rupper, &rulen));
	*reply_len = MESH_ACCESS_MAX;
	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_open(mgr, node, 0, node->addr,
	    mgr->self_addr, rupper, rulen, reply_access, reply_len));
	return (0);
}

/*
 * Stand up a Config Server node at addr on the manager's subnet and record a
 * matching roster entry (arbitrary but shared DevKey).  The manager and node
 * exchange plaintext Access PDUs via cfg_exchange (the DevKey used throughout
 * is the roster node's), so no provisioning handshake is needed to drive the
 * Config Client end to end.
 */
static struct mesh_mgr_node *
standup_server(struct mesh_mgr *mgr, struct meshd_node *dev,
    struct meshd_config *dcfg, uint16_t addr, uint8_t nelem, uint8_t seed)
{
	struct mesh_mgr_node *n;
	uint8_t uuid[16], dk[16];

	memset(uuid, 0xD0 ^ seed, sizeof(uuid));
	memset(dk, 0x50 ^ seed, sizeof(dk));
	n = mesh_mgr_add_node(mgr, uuid, addr, nelem, dk, 0);
	ATF_REQUIRE(n != NULL);
	base_config(dcfg, mgr->netkey, addr);
	ATF_REQUIRE_EQ(0, meshd_node_init(dev, dcfg));
	return (n);
}

/*
 * The Config Server half of a transaction: open the manager's sealed request
 * (seq, self->node), let the node process it, and seal the Status reply back
 * under the node's DevKey (node->self, node seq 0) for the manager to open.
 */
static void
node_reply(struct mesh_mgr *mgr, const struct mesh_mgr_node *node,
    struct meshd_node *dev, uint32_t req_seq, const uint8_t *req_upper,
    size_t req_ulen, uint8_t *rupper, size_t *rulen)
{
	uint8_t plain[MESH_ACCESS_MAX], reply[MESH_ACCESS_MAX];
	size_t plen = sizeof(plain), rlen;

	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_open(mgr, node, req_seq, mgr->self_addr,
	    node->addr, req_upper, req_ulen, plain, &plen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(dev, plain, plen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(node->devkey, 0, 0, 0, node->addr,
	    mgr->self_addr, mgr->iv_index, NULL, reply, rlen, rupper, rulen));
}

/* ================================================================
 * MPROV4 - Composition Data Get -> Status populates the roster node's
 * discovered model layout, and configuration can then target it.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(comp_data_discovery);
ATF_TC_BODY(comp_data_discovery, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	struct mesh_cfg_model_id model;
	static const uint16_t expected_sig_models[] = {
		0x0000,
		0x0002,
		BT_MMGR_MODEL_GEN_ONOFF_SRV,
		BT_MMGR_MODEL_GEN_LEVEL_SRV,
		BT_MMGR_MODEL_LIGHT_LIGHTNESS_SRV,
		BT_MMGR_MODEL_LIGHT_LIGHTNESS_SETUP_SRV,
		BT_MMGR_MODEL_LIGHT_CTL_SRV,
		BT_MMGR_MODEL_LIGHT_CTL_SETUP_SRV,
		BT_MMGR_MODEL_LIGHT_HSL_SRV,
		BT_MMGR_MODEL_LIGHT_HSL_SETUP_SRV,
		BT_MMGR_MODEL_LIGHT_XYL_SRV,
		BT_MMGR_MODEL_LIGHT_XYL_SETUP_SRV,
		BT_MMGR_MODEL_LIGHT_LC_SRV,
		BT_MMGR_MODEL_LIGHT_LC_SETUP_SRV,
		BT_MMGR_MODEL_GEN_DTT_SRV,
		BT_MMGR_MODEL_GEN_POWER_ONOFF_SRV,
		BT_MMGR_MODEL_GEN_POWER_ONOFF_SETUP_SRV,
		BT_MMGR_MODEL_GEN_POWER_LEVEL_SRV,
		BT_MMGR_MODEL_GEN_POWER_LEVEL_SETUP_SRV,
		BT_MMGR_MODEL_GEN_BATTERY_SRV,
		BT_MMGR_MODEL_GEN_LOCATION_SRV,
		BT_MMGR_MODEL_GEN_LOCATION_SETUP_SRV,
		BT_MMGR_MODEL_SENSOR_SRV,
		BT_MMGR_MODEL_SENSOR_SETUP_SRV,
		BT_MMGR_MODEL_TIME_SRV,
		BT_MMGR_MODEL_TIME_SETUP_SRV,
		BT_MMGR_MODEL_SCENE_SRV,
		BT_MMGR_MODEL_SCENE_SETUP_SRV,
		BT_MMGR_MODEL_SCHEDULER_SRV,
		BT_MMGR_MODEL_SCHEDULER_SETUP_SRV,
	};
	uint8_t req[64], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint8_t status;
	size_t i;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 1);

	/* Composition Data Get, page 0: opcode 0x8008 (0x80 0x08) + Page. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_comp_get_pdu(mgr, 0, req, &req_len));
	ATF_CHECK_EQ(3u, req_len);
	CHECK_OPCODE2(req, BT_MMGR_OP_COMP_DATA_GET);
	ATF_CHECK_EQ(0x00, req[2]);

	/* Before discovery the roster node has no layout. */
	ATF_CHECK_EQ(0, nA->have_comp);

	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_comp_status_apply(nA, reply, reply_len));

	/* The discovered layout matches the sim node's element/model table. */
	ATF_CHECK_EQ(1, nA->have_comp);
	ATF_REQUIRE_EQ(4u, nA->comp.n_elements);
	ATF_REQUIRE_EQ(nitems(expected_sig_models),
	    nA->comp.elements[0].n_sig);
	ATF_CHECK_EQ(0u, nA->comp.elements[0].n_vnd);
	for (i = 0; i < nitems(expected_sig_models); i++)
		ATF_CHECK_EQ(expected_sig_models[i],
		    nA->comp.elements[0].sig_models[i]);
	ATF_REQUIRE_EQ(2u, nA->comp.elements[1].n_sig);
	ATF_CHECK_EQ(BT_MMGR_MODEL_GEN_LEVEL_SRV,
	    nA->comp.elements[1].sig_models[0]);
	ATF_CHECK_EQ(BT_MMGR_MODEL_LIGHT_CTL_TEMP_SRV,
	    nA->comp.elements[1].sig_models[1]);
	ATF_CHECK_EQ(BT_MMGR_MODEL_LIGHT_HSL_HUE_SRV,
	    nA->comp.elements[2].sig_models[1]);
	ATF_CHECK_EQ(BT_MMGR_MODEL_LIGHT_HSL_SAT_SRV,
	    nA->comp.elements[3].sig_models[1]);

	/*
	 * Drive a bind against a DISCOVERED model id: AppKey Add first, then
	 * Model App Bind targeting elements[0].sig_models[2] resolved from the
	 * Composition Data.  The node accepts both.
	 */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_status_parse(reply, reply_len,
	    &status, NULL, NULL));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	memset(&model, 0, sizeof(model));
	model.model_id = nA->comp.elements[0].sig_models[2];
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	{
		struct mesh_cfg_model_app mout;

		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_status_parse(reply,
		    reply_len, &status, &mout));
		ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
		ATF_CHECK_EQ(BT_MMGR_MODEL_GEN_ONOFF_SRV, mout.model.model_id);
	}
}

/* ================================================================
 * MPROV4 - key management: NetKey Add, AppKey Get/Update/Delete round-trips
 * through a real Config Server.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_management);
ATF_TC_BODY(key_management, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	uint8_t req[64], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len, n;
	uint8_t status, nk2[16];
	uint16_t rni, list[8];

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 2);

	/* NetKey Add (0x8040) a second subnet index 1: opcode + idx + key. */
	memset(nk2, 0xAB, sizeof(nk2));
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_netkey_add_pdu(mgr, 1, nk2, req, &req_len));
	ATF_CHECK_EQ(2u + 2u + 16u, req_len);
	CHECK_OPCODE2(req, BT_MMGR_OP_NETKEY_ADD);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_netkey_status_parse(reply, reply_len,
	    &status, &rni));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(1, rni);

	/* AppKey Add the primary AppKey, then AppKey Get lists index 0. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_status_parse(reply, reply_len,
	    &status, NULL, NULL));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_get_pdu(mgr, 0, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_list_parse(reply, reply_len,
	    &status, &rni, list, 8, &n));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0, rni);
	ATF_REQUIRE_EQ(1u, n);
	ATF_CHECK_EQ(0, list[0]);

	/* AppKey Update (0x01): the node reports SUCCESS for the known index. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_update_pdu(mgr, req, &req_len));
	ATF_CHECK_EQ(BT_MMGR_OP_APPKEY_UPDATE, req[0]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_status_parse(reply, reply_len,
	    &status, NULL, NULL));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	/* AppKey Delete (0x8000): SUCCESS, and a subsequent Get lists nothing. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_delete_pdu(mgr, req, &req_len));
	CHECK_OPCODE2(req, 0x8000u); /* AppKey Delete, MshPRT §4.3.2.3. */
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_status_parse(reply, reply_len,
	    &status, NULL, NULL));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_get_pdu(mgr, 0, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_list_parse(reply, reply_len,
	    &status, &rni, list, 8, &n));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0u, n);
}

/* ================================================================
 * MPROV4 - Key Refresh via the Config Client: NetKey Update (0x8045) then KR
 * Phase Set (0x8016) transitions drive a real Config Server node through the
 * refresh, revoking the old key at the finish (MshPRT_v1.1 Section 3.11.4).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_config_client);
ATF_TC_BODY(key_refresh_config_client, tc)
{
	static const uint8_t newkey[16] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0
	};
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	uint8_t req[64], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint8_t status, phase;
	uint16_t rni;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 7);

	/* NetKey Update (0x8045) on the primary subnet: opcode + idx + key. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_netkey_update_pdu(mgr, 0, newkey, req,
	    &req_len));
	ATF_CHECK_EQ(2u + 2u + 16u, req_len);
	CHECK_OPCODE2(req, BT_MMGR_OP_NETKEY_UPDATE);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_netkey_status_parse(reply, reply_len,
	    &status, &rni));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(BT_MMGR_KR_PHASE_1, meshd_kr_phase(dev));

	/* KR Phase Get (0x8015) reports Phase 1. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_kr_phase_get_pdu(mgr, 0, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_KR_PHASE_GET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_kr_phase_status_parse(reply, reply_len,
	    &status, &rni, &phase));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(BT_MMGR_KR_PHASE_1, phase);

	/* KR Phase Set Transition 2 (0x8016) -> Phase 2. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_kr_phase_set_pdu(mgr, 0,
	    BT_MMGR_KR_TRANSITION_2, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_KR_PHASE_SET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_kr_phase_status_parse(reply, reply_len,
	    &status, &rni, &phase));
	ATF_CHECK_EQ(BT_MMGR_KR_PHASE_2, phase);

	/* Transition 3 -> finish: old key revoked, new key promoted, Phase 0. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_kr_phase_set_pdu(mgr, 0,
	    BT_MMGR_KR_TRANSITION_3, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_kr_phase_status_parse(reply, reply_len,
	    &status, &rni, &phase));
	ATF_CHECK_EQ(BT_MMGR_KR_PHASE_NORMAL, phase);
	ATF_CHECK_EQ(0, dev->self->have_new_key);
	ATF_CHECK_EQ_MSG(0, memcmp(dev->self->netkey, newkey, 16),
	    "the Config Server node promoted the new key as sole current key");

	/* NetKey Delete (0x8041) builder shape. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_netkey_delete_pdu(mgr, 1, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_NETKEY_DELETE);
}

/* ================================================================
 * MPROV4 - network-wide Key Refresh per-node acknowledgement: a node that never
 * acknowledges the new key stays pending, which is how the operator sees the
 * node that would be partitioned (evicted) once the phase advances.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_network_ack);
ATF_TC_BODY(key_refresh_network_ack, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	uint8_t uuid[16], dk[16];

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	memset(dk, 0x33, sizeof(dk));
	memset(uuid, 0x01, sizeof(uuid));
	ATF_REQUIRE(mesh_mgr_add_node(mgr, uuid, 0x0002, 1, dk, 0) != NULL);
	memset(uuid, 0x02, sizeof(uuid));
	ATF_REQUIRE(mesh_mgr_add_node(mgr, uuid, 0x0003, 1, dk, 0) != NULL);
	memset(uuid, 0x03, sizeof(uuid));
	ATF_REQUIRE(mesh_mgr_add_node(mgr, uuid, 0x0004, 1, dk, 0) != NULL);

	/* Begin: every node awaits the new key. */
	mesh_mgr_kr_begin(mgr);
	ATF_CHECK_EQ(3u, mesh_mgr_kr_pending(mgr));

	/* Two nodes acknowledge; the third is the missed node. */
	ATF_CHECK_EQ(0, mesh_mgr_kr_ack(mgr, 0x0002));
	ATF_CHECK_EQ(0, mesh_mgr_kr_ack(mgr, 0x0003));
	ATF_CHECK_EQ(1u, mesh_mgr_kr_pending(mgr));

	/* An ack for an interior element address resolves to its node. */
	ATF_CHECK_EQ(0, mesh_mgr_kr_ack(mgr, 0x0004));
	ATF_CHECK_EQ(0u, mesh_mgr_kr_pending(mgr));

	/* An unknown address is reported, not silently accepted. */
	ATF_CHECK_EQ(-1, mesh_mgr_kr_ack(mgr, 0x7000));
}

/* ================================================================
 * MPROV4 - node-wide state Set -> Get round-trips (relay, proxy, friend,
 * beacon, default TTL, network transmit) through a real Config Server.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_state);
ATF_TC_BODY(node_state, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	uint8_t req[64], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint8_t v, v2, relay, rtx;
	uint32_t op;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 3);

	/* Beacon Set On (0x800A), then Beacon Get (0x8009) reads it back. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_set_pdu(mgr,
	    BT_MMGR_OP_BEACON_SET, 1, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_BEACON_SET);
	ATF_CHECK_EQ(0x01, req[2]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_status_parse(reply, reply_len,
	    &op, &v));
	ATF_CHECK_EQ(BT_MMGR_OP_BEACON_STATUS, op);
	ATF_CHECK_EQ(1, v);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_get_pdu(mgr,
	    BT_MMGR_OP_BEACON_GET, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_status_parse(reply, reply_len,
	    &op, &v2));
	ATF_CHECK_EQ(1, v2);

	/* Default TTL Set (0x800D) to 5, then Get (0x800C). */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_set_pdu(mgr,
	    BT_MMGR_OP_DEFAULT_TTL_SET, 5, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_status_parse(reply, reply_len,
	    &op, &v));
	ATF_CHECK_EQ(BT_MMGR_OP_DEFAULT_TTL_STATUS, op);
	ATF_CHECK_EQ(5, v);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_get_pdu(mgr,
	    BT_MMGR_OP_DEFAULT_TTL_GET, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_status_parse(reply, reply_len,
	    &op, &v2));
	ATF_CHECK_EQ(5, v2);

	/* GATT Proxy Set (0x8013) On and Friend Set (0x8010) On: both SUCCESS. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_set_pdu(mgr,
	    BT_MMGR_OP_GATT_PROXY_SET, 1, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_status_parse(reply, reply_len,
	    &op, &v));
	ATF_CHECK_EQ(BT_MMGR_OP_GATT_PROXY_STATUS, op);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_set_pdu(mgr,
	    BT_MMGR_OP_FRIEND_SET, 1, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_status_parse(reply, reply_len,
	    &op, &v));
	ATF_CHECK_EQ(BT_MMGR_OP_FRIEND_STATUS, op);

	/* Relay Set (0x8027) enabled + retransmit, then Relay Get (0x8026). */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_relay_set_pdu(mgr, 1, 0x12, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_RELAY_SET);
	ATF_CHECK_EQ(0x01, req[2]);
	ATF_CHECK_EQ(0x12, req[3]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_relay_status_parse(reply, reply_len,
	    &relay, &rtx));
	ATF_CHECK_EQ(1, relay);
	ATF_CHECK_EQ(0x12, rtx);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_relay_get_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_relay_status_parse(reply, reply_len,
	    &relay, &rtx));
	ATF_CHECK_EQ(1, relay);
	ATF_CHECK_EQ(0x12, rtx);

	/* Network Transmit Set (0x8024) count/interval, then Get (0x8023). */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_net_transmit_set_pdu(mgr, 3, 5, req,
	    &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_net_transmit_status_parse(reply, reply_len,
	    &v, &v2));
	ATF_CHECK_EQ(3, v);
	ATF_CHECK_EQ(5, v2);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_net_transmit_get_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_net_transmit_status_parse(reply, reply_len,
	    &v, &v2));
	ATF_CHECK_EQ(3, v);
	ATF_CHECK_EQ(5, v2);
}

/* ================================================================
 * MPROV4 - binding / subscription removal + Node Reset.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(unbind_unsub_reset);
ATF_TC_BODY(unbind_unsub_reset, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	struct mesh_cfg_model_id model;
	struct mesh_cfg_model_app mapp;
	struct mesh_cfg_model_sub msub;
	uint8_t req[64], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint8_t status;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 4);
	memset(&model, 0, sizeof(model));
	model.model_id = BT_MMGR_MODEL_GEN_ONOFF_SRV;

	/* AppKey Add + Bind so there is a binding to remove. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);

	/* Model App Unbind (0x803F): SUCCESS. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_unbind_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_MODEL_APP_UNBIND);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_status_parse(reply, reply_len,
	    &status, &mapp));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	/* Subscription Add then Delete (0x801C): both SUCCESS, addr echoed. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_add_pdu(mgr, nA->addr, 0xC001,
	    &model, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_status_parse(reply, reply_len,
	    &status, &msub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_delete_pdu(mgr, nA->addr, 0xC001,
	    &model, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_MODEL_SUB_DELETE);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_status_parse(reply, reply_len,
	    &status, &msub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	/* Overwrite then Delete All: exercise both remaining subscription verbs. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_overwrite_pdu(mgr, nA->addr,
	    0xC002, &model, req, &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MMGR_OP_MODEL_SUB_OVERWRITE), req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_status_parse(reply, reply_len,
	    &status, &msub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_delete_all_pdu(mgr, nA->addr,
	    &model, req, &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MMGR_OP_MODEL_SUB_DELETE_ALL), req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_status_parse(reply, reply_len,
	    &status, &msub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	/* Node Reset (0x8049) -> Node Reset Status (0x804A), no parameters. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_reset_pdu(mgr, req, &req_len));
	ATF_CHECK_EQ(2u, req_len);	/* 2-octet opcode, no parameters */
	CHECK_OPCODE2(req, BT_MMGR_OP_NODE_RESET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_reset_status_parse(reply, reply_len));
	/* A truncated / wrong-opcode Status is rejected without over-reading. */
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_node_reset_status_parse(reply, 0));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_node_reset_status_parse(req, req_len));
}

/* ================================================================
 * MPROV4 - Config Client transaction: Status correlation, retry-on-timeout
 * with a mock clock, and bounded-budget exhaustion.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(txn_retry_sm);
ATF_TC_BODY(txn_retry_sm, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	struct mesh_mgr_txn t;
	uint8_t req[64], upper[MESH_UPPER_MAX], rupper[MESH_UPPER_MAX];
	size_t req_len, ulen, rulen;
	uint32_t seq;
	uint8_t status;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 5);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, req, &req_len));

	/*
	 * Budget exhaustion: 3 attempts, 100-unit interval.  begin sends attempt
	 * 1 (seq 0); ticks at the deadline retransmit until the budget is spent,
	 * then TIMEOUT.  No Status is ever fed.
	 */
	ATF_REQUIRE_EQ(0, mesh_mgr_txn_begin(mgr, &t, nA, req, req_len,
	    BT_MMGR_OP_APPKEY_STATUS, 0, 100, 3, upper, &ulen, &seq));
	ATF_CHECK_EQ(MESH_MGR_TXN_WAITING, t.state);
	ATF_CHECK_EQ(1u, t.attempts);
	ATF_CHECK_EQ(0u, seq);

	/* Not due yet. */
	ATF_CHECK_EQ(0, mesh_mgr_txn_tick(mgr, &t, nA, 50, upper, &ulen, &seq));
	ATF_CHECK_EQ(MESH_MGR_TXN_WAITING, t.state);

	/* Deadline: retransmit (attempt 2, fresh seq 1). */
	ATF_CHECK_EQ(1, mesh_mgr_txn_tick(mgr, &t, nA, 100, upper, &ulen, &seq));
	ATF_CHECK_EQ(2u, t.attempts);
	ATF_CHECK_EQ(1u, seq);
	/* Retransmit (attempt 3, seq 2). */
	ATF_CHECK_EQ(1, mesh_mgr_txn_tick(mgr, &t, nA, 200, upper, &ulen, &seq));
	ATF_CHECK_EQ(3u, t.attempts);
	ATF_CHECK_EQ(2u, seq);
	/* Budget spent: TIMEOUT, no emission, and cannot loop further. */
	ATF_CHECK_EQ(0, mesh_mgr_txn_tick(mgr, &t, nA, 300, upper, &ulen, &seq));
	ATF_CHECK_EQ(MESH_MGR_TXN_TIMEOUT, t.state);
	ATF_CHECK_EQ(3u, t.attempts);
	ATF_CHECK_EQ(0, mesh_mgr_txn_tick(mgr, &t, nA, 400, upper, &ulen, &seq));
	ATF_CHECK_EQ(MESH_MGR_TXN_TIMEOUT, t.state);

	/*
	 * Success path with one lost transmission: begin (attempt 1), a wrong-
	 * opcode reply is ignored (still WAITING), a tick retransmits, and the
	 * real Status completes the transaction.
	 */
	ATF_REQUIRE_EQ(0, mesh_mgr_txn_begin(mgr, &t, nA, req, req_len,
	    BT_MMGR_OP_APPKEY_STATUS, 0, 100, 3, upper, &ulen, &seq));

	/* Feed a NetKey Status (wrong opcode) reply: correlation rejects it. */
	{
		uint8_t nreq[64], nupper[MESH_UPPER_MAX];
		size_t nlen, nulen;
		uint32_t nseq;

		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_netkey_add_pdu(mgr, 1,
		    mgr->netkey, nreq, &nlen));
		ATF_REQUIRE_EQ(0, mesh_mgr_devkey_seal(mgr, nA, nreq, nlen,
		    &nseq, nupper, &nulen));
		node_reply(mgr, nA, dev, nseq, nupper, nulen, rupper, &rulen);
		ATF_CHECK_EQ(0, mesh_mgr_txn_rx(&t, mgr, nA, 0, nA->addr,
		    mgr->self_addr, rupper, rulen));
		ATF_CHECK_EQ(MESH_MGR_TXN_WAITING, t.state);
	}

	/* Retransmit the AppKey Add and let the node answer AppKey Status. */
	ATF_CHECK_EQ(1, mesh_mgr_txn_tick(mgr, &t, nA, 100, upper, &ulen, &seq));
	node_reply(mgr, nA, dev, seq, upper, ulen, rupper, &rulen);
	ATF_CHECK_EQ(1, mesh_mgr_txn_rx(&t, mgr, nA, 0, nA->addr, mgr->self_addr,
	    rupper, rulen));
	ATF_CHECK_EQ(MESH_MGR_TXN_COMPLETE, t.state);

	/* The recovered Status parses as AppKey Status = SUCCESS. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_status_parse(t.status, t.status_len,
	    &status, NULL, NULL));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);

	/* No double-apply: a further Status and further ticks are inert. */
	ATF_CHECK_EQ(0, mesh_mgr_txn_rx(&t, mgr, nA, 0, nA->addr, mgr->self_addr,
	    rupper, rulen));
	ATF_CHECK_EQ(MESH_MGR_TXN_COMPLETE, t.state);
	ATF_CHECK_EQ(0, mesh_mgr_txn_tick(mgr, &t, nA, 500, upper, &ulen, &seq));
	ATF_CHECK_EQ(MESH_MGR_TXN_COMPLETE, t.state);
}

ATF_TC_WITHOUT_HEAD(e2e_create_provision_configure);
ATF_TC_BODY(e2e_create_provision_configure, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, prov);		/* the Provisioner */
	MESH_HEAP(struct meshd_node, dev);		/* stand-in Config Server = device A */
	struct meshd_config pcfg, dcfg;
	struct mesh_mgr_node *nA, *nB;
	struct mesh_cfg_model_id model;
	uint8_t uuidA[16], uuidB[16], dkA[16];
	uint8_t req[64], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint16_t addrA = 0, addrB = 0;
	uint8_t status, mstatus;
	uint16_t rni, rai;
	struct mesh_cfg_model_app mout;

	/* MPROV1: create the network. */
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));

	/* The Provisioner node (its sim keys are irrelevant to the exchange). */
	base_config(&pcfg, mgr->netkey, 0x0001);
	ATF_REQUIRE_EQ(0, meshd_node_init(prov, &pcfg));

	/* MPROV2+3: provision two devices; the manager allocates + records. */
	memset(uuidA, 0x11, sizeof(uuidA));
	memset(uuidB, 0x22, sizeof(uuidB));
	provision_device(prov, mgr, uuidA, 1, 0x1001, &addrA, dkA);
	provision_device(prov, mgr, uuidB, 2, 0x1002, &addrB, NULL);

	/* Distinct auto-allocated addresses; B (2 elements) sits just past A. */
	ATF_CHECK_EQ(0x0002, addrA);
	ATF_CHECK_EQ(0x0003, addrB);
	ATF_CHECK(addrA != addrB);
	ATF_CHECK_EQ(2u, mesh_mgr_node_count(mgr));

	/* The roster records both devices, by UUID, with their DevKeys. */
	nA = mesh_mgr_find_by_uuid(mgr, uuidA);
	nB = mesh_mgr_find_by_uuid(mgr, uuidB);
	ATF_REQUIRE(nA != NULL && nB != NULL);
	ATF_CHECK_EQ(addrA, nA->addr);
	ATF_CHECK_EQ(1, nA->num_elements);
	ATF_CHECK_EQ(2, nB->num_elements);
	ATF_CHECK_EQ(0, memcmp(nA->devkey, dkA, 16));
	/* Device B's second element resolves to B. */
	ATF_CHECK(mesh_mgr_find_by_addr(mgr, 0x0004) == nB);

	/*
	 * MPROV4: configure device A.  A Config Server node stands in for the
	 * provisioned device at A's address on the manager's subnet.
	 */
	base_config(&dcfg, mgr->netkey, addrA);
	ATF_REQUIRE_EQ(0, meshd_node_init(dev, &dcfg));

	/* AppKey Add: the node accepts and reports SUCCESS. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_status_parse(reply, reply_len,
	    &status, &rni, &rai));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0, rni);
	ATF_CHECK_EQ(0, rai);

	/* Model App Bind (Generic OnOff Server on A's primary element): SUCCESS. */
	memset(&model, 0, sizeof(model));
	model.model_id = BT_MMGR_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr, addrA, &model,
	    req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_status_parse(reply, reply_len,
	    &mstatus, &mout));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, mstatus);
	ATF_CHECK_EQ(addrA, mout.elem_addr);
	ATF_CHECK_EQ(BT_MMGR_MODEL_GEN_ONOFF_SRV, mout.model.model_id);

	mesh_prov_session_free(&prov->prov_sess);
}

/* ================================================================
 * MPROV4 - virtual-address group messaging: Label-UUID -> 0x8000+ derivation,
 * Model Publication VA Set, Model Subscription VA Add/Delete/Overwrite, and
 * Model Publication/Subscription Get round-trips through a real Config Server.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(virtual_addr_pubsub);
ATF_TC_BODY(virtual_addr_pubsub, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	struct mesh_cfg_model_id model;
	struct mesh_cfg_model_sub msub;
	struct mesh_cfg_model_pub mpub;
	uint8_t label[16];
	uint8_t req[80], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len, n;
	uint8_t status;
	uint16_t va, va_ref, list[8], relem;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 8);
	memset(&model, 0, sizeof(model));
	model.model_id = BT_MMGR_MODEL_GEN_ONOFF_SRV;
	memset(label, 0x5C, sizeof(label));

	/* The Label UUID derives a virtual address in 0x8000..0xBFFF. */
	ATF_REQUIRE_EQ(0, mesh_mgr_label_to_virtual_addr(label, &va));
	ATF_CHECK((va & BT_MMGR_VIRTUAL_MASK) == BT_MMGR_VIRTUAL_PREFIX);
	/* The derivation matches the access-layer primitive exactly. */
	ATF_REQUIRE_EQ(0, mesh_virtual_addr(label, &va_ref));
	ATF_CHECK_EQ(va_ref, va);
	ATF_CHECK_EQ(-1, mesh_mgr_label_to_virtual_addr(NULL, &va));

	/* AppKey Add + Bind so the model can publish/subscribe. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);

	/*
	 * Model Subscription VA Add (0x8020): opcode + ElemAddr + Label(16) +
	 * ModelId.  The Status echoes the DERIVED virtual address, not the label.
	 */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_va_add_pdu(mgr, nA->addr, label,
	    &model, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_MODEL_SUB_VA_ADD);
	ATF_CHECK_EQ(0x02, req[2]);		/* elem addr LE */
	ATF_CHECK_EQ(0x00, req[3]);
	ATF_CHECK_EQ(0, memcmp(req + 4, label, 16));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_status_parse(reply, reply_len,
	    &status, &msub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(va, msub.address);

	/* SIG Model Subscription Get (0x8029) lists the derived virtual address. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_get_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_SIG_MODEL_SUB_GET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_list_parse(reply, reply_len,
	    &status, &relem, &model, list, 8, &n));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(nA->addr, relem);
	ATF_REQUIRE_EQ(1u, n);
	ATF_CHECK_EQ(va, list[0]);

	/* Overwrite to a second label, then Delete it: both SUCCESS. */
	{
		uint8_t label2[16];
		uint16_t va2;

		memset(label2, 0x77, sizeof(label2));
		ATF_REQUIRE_EQ(0, mesh_mgr_label_to_virtual_addr(label2, &va2));
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_va_overwrite_pdu(mgr,
		    nA->addr, label2, &model, req, &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(
		    BT_MMGR_OP_MODEL_SUB_VA_OVERWRITE), req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_status_parse(reply,
		    reply_len, &status, &msub));
		ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
		ATF_CHECK_EQ(va2, msub.address);

		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_va_delete_pdu(mgr,
		    nA->addr, label2, &model, req, &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MMGR_OP_MODEL_SUB_VA_DELETE),
		    req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_sub_status_parse(reply,
		    reply_len, &status, &msub));
		ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	}

	/*
	 * Model Publication VA Set (0x801A): opcode + ElemAddr + Label(16) +
	 * AppKeyIdx/CredFlag + TTL + Period + Retransmit + ModelId.  Then Model
	 * Publication Get (0x8018) reads the derived virtual address back.
	 */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_pub_va_set_pdu(mgr, nA->addr, label,
	    5, 0, 0, &model, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_MODEL_PUB_VA_SET);
	ATF_CHECK_EQ(0, memcmp(req + 4, label, 16));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_pub_status_parse(reply, reply_len,
	    &status, &mpub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(va, mpub.pub_addr);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_pub_get_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_MODEL_PUB_GET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_pub_status_parse(reply, reply_len,
	    &status, &mpub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(va, mpub.pub_addr);
	ATF_CHECK_EQ(5, mpub.ttl);

	/* A truncated Status is rejected without over-reading. */
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_pub_status_parse(reply, 1, &status,
	    &mpub));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_list_parse(reply, 0, &status,
	    &relem, &model, list, 8, &n));
}

/* ================================================================
 * MPROV4 - Model App Get/List: list the AppKey indexes bound to a model on
 * the node, round-tripped through a real Config Server.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_app_list);
ATF_TC_BODY(model_app_list, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	struct mesh_cfg_model_id model;
	uint8_t req[64], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len, n;
	uint8_t status;
	uint16_t relem, apps[8];

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 9);
	memset(&model, 0, sizeof(model));
	model.model_id = BT_MMGR_MODEL_GEN_ONOFF_SRV;

	/* AppKey Add + Bind so there is a binding to enumerate. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(mgr, req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);

	/* SIG Model App Get (0x804B) lists AppKey index 0. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_get_pdu(mgr, nA->addr, &model,
	    req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_SIG_MODEL_APP_GET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_list_parse(reply, reply_len,
	    &status, &relem, &model, apps, 8, &n));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(nA->addr, relem);
	ATF_REQUIRE_EQ(1u, n);
	ATF_CHECK_EQ(0, apps[0]);

	/* A truncated List is rejected without over-reading. */
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_list_parse(reply, 1, &status,
	    &relem, &model, apps, 8, &n));
	/* A wrong-opcode reply (Subscription List) is rejected. */
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_list_parse(req, req_len, &status,
	    &relem, &model, apps, 8, &n));
}

/* ================================================================
 * MPROV4 - Node Identity Get/Set and LPN PollTimeout Get round-trips.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_identity_lpn);
ATF_TC_BODY(node_identity_lpn, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	uint8_t req[32], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint8_t status, identity;
	uint16_t rni, lpn;
	uint32_t poll;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 10);

	/* Node Identity Set (0x8047) RUNNING on the primary subnet, then Get. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_identity_set_pdu(mgr, 0,
	    BT_MMGR_IDENTITY_RUNNING, req, &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_NODE_IDENTITY_SET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_identity_status_parse(reply, reply_len,
	    &status, &rni, &identity));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0, rni);
	ATF_CHECK_EQ(BT_MMGR_IDENTITY_RUNNING, identity);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_identity_get_pdu(mgr, 0, req,
	    &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MMGR_OP_NODE_IDENTITY_GET), req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_identity_status_parse(reply, reply_len,
	    &status, &rni, &identity));
	ATF_CHECK_EQ(BT_MMGR_IDENTITY_RUNNING, identity);

	/* An unknown NetKey index is reported by the server, not accepted. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_identity_get_pdu(mgr, 9, req,
	    &req_len));
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_identity_status_parse(reply, reply_len,
	    &status, &rni, &identity));
	ATF_CHECK_EQ(BT_MMGR_STATUS_INVALID_NETKEY, status);

	/* LPN PollTimeout Get (0x802D) for an LPN address: Status carries 0. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_lpn_polltimeout_get_pdu(mgr, 0x1234, req,
	    &req_len));
	CHECK_OPCODE2(req, BT_MMGR_OP_LPN_POLLTIMEOUT_GET);
	ATF_CHECK_EQ(0x34, req[2]);		/* LPN addr LE */
	ATF_CHECK_EQ(0x12, req[3]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_lpn_polltimeout_status_parse(reply,
	    reply_len, &lpn, &poll));
	ATF_CHECK_EQ(0x1234, lpn);
	ATF_CHECK_EQ(0u, poll);

	/* Truncated Status rejected without over-reading. */
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_lpn_polltimeout_status_parse(reply, 2, &lpn,
	    &poll));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_node_identity_status_parse(reply, 1,
	    &status, &rni, &identity));
}

/* ================================================================
 * MPROV4 - Heartbeat publication / subscription config, with the discovered
 * state recorded into the roster node record.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(heartbeat_config);
ATF_TC_BODY(heartbeat_config, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	struct mesh_hb_pub pub;
	struct mesh_hb_pub gpub;
	struct mesh_hb_sub_status gsub;
	uint8_t req[32], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint8_t status;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 11);

	/* Heartbeat Publication Set (0x8039): publish to a group, TTL 5. */
	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xC001;
	pub.count_log = 0x03;
	pub.period_log = 0x04;
	pub.ttl = 5;
	pub.features = MESH_HB_FEATURE_RELAY;
	pub.net_idx = 0;
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_pub_set_pdu(mgr, &pub, req, &req_len));
	CHECK_OPCODE2(req, BT_MESH11_CFG_OP_HB_PUB_SET);
	ATF_CHECK_EQ(0x01, req[2]);		/* dst 0xC001 LE */
	ATF_CHECK_EQ(0xC0, req[3]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	/* Status opcode is the one-octet 0x06. */
	ATF_CHECK_EQ(BT_MESH11_CFG_OP_HB_PUB_STATUS, reply[0]);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_pub_status_parse(reply, reply_len,
	    &status, &gpub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0xC001, gpub.dst);
	ATF_CHECK_EQ(5, gpub.ttl);

	/* Publication Get (0x8038) reads the configured publication back. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_pub_get_pdu(mgr, req, &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MESH11_CFG_OP_HB_PUB_GET), req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_pub_status_parse(reply, reply_len,
	    &status, &gpub));
	ATF_CHECK_EQ(0xC001, gpub.dst);
	ATF_CHECK_EQ(5, gpub.ttl);

	/* Heartbeat Subscription Set (0x803B): count arriving Heartbeats. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_sub_set_pdu(mgr, 0x0003, 0xC001, 0x05,
	    req, &req_len));
	CHECK_OPCODE2(req, BT_MESH11_CFG_OP_HB_SUB_SET);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_sub_status_parse(reply, reply_len,
	    &gsub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, gsub.status);
	ATF_CHECK_EQ(0x0003, gsub.src);
	ATF_CHECK_EQ(0xC001, gsub.dst);

	/* Subscription Get (0x803A) reads the configured subscription back. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_sub_get_pdu(mgr, req, &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MESH11_CFG_OP_HB_SUB_GET), req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_sub_status_parse(reply, reply_len,
	    &gsub));
	ATF_CHECK_EQ(0x0003, gsub.src);
	ATF_CHECK_EQ(0xC001, gsub.dst);

	/* Truncated Status rejected without over-reading. */
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_hb_pub_status_parse(reply, 1, &status,
	    &gpub));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_hb_sub_status_parse(reply, 2, &gsub));
}

/* ================================================================
 * MPROV4 - Mesh 1.1 config client wrappers: SAR Transmitter/Receiver,
 * On-Demand Private Proxy, Private Beacon / GATT Proxy / Node Identity, and
 * Large Composition Data Get, round-tripped through a real Config Server.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(v11_config_client);
ATF_TC_BODY(v11_config_client, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	uint8_t req[32], reply[MESH_ACCESS_MAX];
	size_t req_len, reply_len;
	uint8_t status, v;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 12);

	/* SAR Transmitter Set (0x806D) then Get (0x806C). */
	{
		struct mesh_cfg_sar_transmitter tx, gtx;

		memset(&tx, 0, sizeof(tx));
		tx.seg_interval_step = 0x3;
		tx.unicast_retrans_count = 0x7;
		tx.multicast_retrans_count = 0x2;
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_tx_set_pdu(mgr, &tx, req,
		    &req_len));
		CHECK_OPCODE2(req, BT_MCFG11_OP_SAR_TRANSMITTER_SET);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_tx_status_parse(reply, reply_len,
		    &gtx));
		ATF_CHECK_EQ(0x7, gtx.unicast_retrans_count);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_tx_get_pdu(mgr, req, &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(
		    BT_MCFG11_OP_SAR_TRANSMITTER_GET), req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_tx_status_parse(reply, reply_len,
		    &gtx));
		ATF_CHECK_EQ(0x3, gtx.seg_interval_step);
	}

	/* SAR Receiver Set (0x8070) then Get (0x806F). */
	{
		struct mesh_cfg_sar_receiver rx, grx;

		memset(&rx, 0, sizeof(rx));
		rx.segments_threshold = 0x11;
		rx.ack_retrans_count = 0x2;
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_rx_set_pdu(mgr, &rx, req,
		    &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MCFG11_OP_SAR_RECEIVER_SET),
		    req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_rx_status_parse(reply, reply_len,
		    &grx));
		ATF_CHECK_EQ(0x11, grx.segments_threshold);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_rx_get_pdu(mgr, req, &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MCFG11_OP_SAR_RECEIVER_GET),
		    req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_sar_rx_status_parse(reply, reply_len,
		    &grx));
		ATF_CHECK_EQ(0x2, grx.ack_retrans_count);
	}

	/* On-Demand Private Proxy Set (0x806A) then Get (0x8069). */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_od_priv_proxy_set_pdu(mgr, 1, req,
	    &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MCFG11_OP_OD_PRIV_PROXY_SET), req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_od_priv_proxy_status_parse(reply, reply_len,
	    &v));
	ATF_CHECK_EQ(1, v);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_od_priv_proxy_get_pdu(mgr, req, &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MCFG11_OP_OD_PRIV_PROXY_GET), req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_od_priv_proxy_status_parse(reply, reply_len,
	    &v));
	ATF_CHECK_EQ(1, v);

	/* Private Beacon Set (0x8061) with a random-update interval, then Get. */
	{
		struct mesh_cfg_priv_beacon pb, gpb;

		memset(&pb, 0, sizeof(pb));
		pb.private_beacon = 1;
		pb.random_update_interval_steps = 0x0A;
		pb.has_random_update = 1;
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_beacon_set_pdu(mgr, &pb, req,
		    &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MCFG11_OP_PRIV_BEACON_SET),
		    req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_beacon_status_parse(reply,
		    reply_len, &gpb));
		ATF_CHECK_EQ(1, gpb.private_beacon);
		ATF_CHECK_EQ(0x0A, gpb.random_update_interval_steps);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_beacon_get_pdu(mgr, req,
		    &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MCFG11_OP_PRIV_BEACON_GET),
		    req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_beacon_status_parse(reply,
		    reply_len, &gpb));
		ATF_CHECK_EQ(1, gpb.private_beacon);
	}

	/* Private GATT Proxy Set (0x8064) then Get (0x8063). */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_gatt_proxy_set_pdu(mgr, 1, req,
	    &req_len));
	ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(BT_MCFG11_OP_PRIV_GATT_PROXY_SET),
	    req[1]);
	cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_gatt_proxy_status_parse(reply,
	    reply_len, &v));
	ATF_CHECK_EQ(1, v);

	/* Private Node Identity Set (0x8067) RUNNING on subnet 0, then Get. */
	{
		struct mesh_cfg_priv_node_identity id;

		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_node_identity_set_pdu(mgr, 0,
		    BT_MMGR_IDENTITY_RUNNING, req, &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(
		    BT_MCFG11_OP_PRIV_NODE_IDENTITY_SET), req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_node_identity_status_parse(reply,
		    reply_len, &status, &id));
		ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
		ATF_CHECK_EQ(BT_MMGR_IDENTITY_RUNNING, id.identity);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_node_identity_get_pdu(mgr, 0,
		    req, &req_len));
		ATF_CHECK_EQ(BT_MMGR_OPCODE_LO(
		    BT_MCFG11_OP_PRIV_NODE_IDENTITY_GET), req[1]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_priv_node_identity_status_parse(reply,
		    reply_len, &status, &id));
		ATF_CHECK_EQ(BT_MMGR_IDENTITY_RUNNING, id.identity);
	}

	/* Large Composition Data Get (0x8074) page 0 offset 0: Status slice. */
	{
		struct mesh_cfg_lcd_status lcd;

		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_lcd_get_pdu(mgr, 0, 0, req,
		    &req_len));
		CHECK_OPCODE2(req, BT_MCFG11_OP_LARGE_COMP_DATA_GET);
		ATF_CHECK_EQ(0x00, req[2]);		/* page */
		ATF_CHECK_EQ(0x00, req[3]);		/* offset LE */
		ATF_CHECK_EQ(0x00, req[4]);
		cfg_exchange(mgr, nA, dev, req, req_len, reply, &reply_len);
		ATF_REQUIRE_EQ(0, mesh_mgr_cfg_lcd_status_parse(reply, reply_len,
		    &lcd));
		ATF_CHECK_EQ(0, lcd.page);
		ATF_CHECK(lcd.total_size > 0);
		/* Truncated Status rejected without over-reading. */
		ATF_CHECK_EQ(-1, mesh_mgr_cfg_lcd_status_parse(reply, 2, &lcd));
	}
}

/* ================================================================
 * MPROV4 - the added families are DevKey-sealed and correlated through the
 * shared transaction state machine like the core Configuration messages.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(added_txn_correlation);
ATF_TC_BODY(added_txn_correlation, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config dcfg;
	struct mesh_mgr_node *nA;
	struct mesh_mgr_txn t;
	struct mesh_hb_pub pub;
	uint8_t req[32], upper[MESH_UPPER_MAX], rupper[MESH_UPPER_MAX];
	size_t req_len, ulen, rulen;
	uint32_t seq;
	uint8_t status;
	struct mesh_hb_pub gpub;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nA = standup_server(mgr, dev, &dcfg, 0x0002, 4, 13);

	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xC003;
	pub.count_log = 0x02;
	pub.period_log = 0x03;
	pub.ttl = 4;
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_pub_set_pdu(mgr, &pub, req, &req_len));

	/* Begin the transaction correlating on the HB Publication Status (0x06). */
	ATF_REQUIRE_EQ(0, mesh_mgr_txn_begin(mgr, &t, nA, req, req_len,
	    BT_MMGR_OP_HB_PUB_STATUS, 0, 100, 3, upper, &ulen, &seq));
	ATF_CHECK_EQ(MESH_MGR_TXN_WAITING, t.state);
	ATF_CHECK_EQ(0u, seq);

	/* The node answers; the reply completes the transaction (no seq reuse). */
	node_reply(mgr, nA, dev, seq, upper, ulen, rupper, &rulen);
	ATF_CHECK_EQ(1, mesh_mgr_txn_rx(&t, mgr, nA, 0, nA->addr, mgr->self_addr,
	    rupper, rulen));
	ATF_CHECK_EQ(MESH_MGR_TXN_COMPLETE, t.state);

	/* The recovered Status parses as a Heartbeat Publication Status. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_hb_pub_status_parse(t.status, t.status_len,
	    &status, &gpub));
	ATF_CHECK_EQ(BT_MMGR_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0xC003, gpub.dst);
}

ATF_TC_WITHOUT_HEAD(manager_guard_matrix);
ATF_TC_BODY(manager_guard_matrix, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	struct mesh_prov_data pdata;
	uint8_t uuid[16] = { 1 }, key[16] = { 2 };
	uint8_t out[MESH_UPPER_MAX];
	uint16_t addr;
	size_t outlen;

	ATF_CHECK_EQ(-1, mesh_mgr_create_network(NULL, NULL, NULL));
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_mgr_set_self(NULL, 1, 1, key));
	ATF_CHECK_EQ(-1, mesh_mgr_set_self(mgr, 0, 1, key));
	ATF_CHECK_EQ(-1, mesh_mgr_alloc_unicast(NULL, 1, &addr));
	ATF_CHECK_EQ(-1, mesh_mgr_alloc_unicast(mgr, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_mgr_alloc_unicast(mgr, 0, &addr));
	ATF_CHECK(mesh_mgr_add_node(NULL, uuid, 2, 1, key, 0) == NULL);
	ATF_CHECK(mesh_mgr_add_node(mgr, NULL, 2, 1, key, 0) == NULL);
	ATF_CHECK(mesh_mgr_add_node(mgr, uuid, 2, 1, NULL, 0) == NULL);
	ATF_CHECK(mesh_mgr_add_node(mgr, uuid, 0, 1, key, 0) == NULL);
	ATF_CHECK(mesh_mgr_find_by_addr(NULL, 1) == NULL);
	ATF_CHECK(mesh_mgr_find_by_uuid(NULL, uuid) == NULL);
	ATF_CHECK(mesh_mgr_find_by_uuid(mgr, NULL) == NULL);
	ATF_CHECK_EQ(-1, mesh_mgr_remove_node(NULL, 2));
	ATF_CHECK_EQ(-1, mesh_mgr_remove_node(mgr, 2));
	ATF_CHECK_EQ(0u, mesh_mgr_node_count(NULL));
	ATF_CHECK(mesh_mgr_node_at(NULL, 0) == NULL);
	ATF_CHECK(mesh_mgr_node_at(mgr, 0) == NULL);
	ATF_CHECK_EQ(-1, mesh_mgr_provision_prepare(NULL, uuid, 1, &pdata));
	ATF_CHECK_EQ(-1, mesh_mgr_provision_prepare(mgr, NULL, 1, &pdata));
	ATF_CHECK_EQ(-1, mesh_mgr_provision_prepare(mgr, uuid, 0, &pdata));
	ATF_CHECK_EQ(-1, mesh_mgr_provision_prepare(mgr, uuid, 1, NULL));
	ATF_CHECK(mesh_mgr_provision_commit(NULL, key, 0) == NULL);
	ATF_CHECK(mesh_mgr_provision_commit(mgr, NULL, 0) == NULL);
	ATF_CHECK(mesh_mgr_provision_commit(mgr, key, 0) == NULL);
	mesh_mgr_provision_abort(NULL);

	ATF_CHECK_EQ(-1, mesh_mgr_cfg_appkey_add_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_appkey_add_pdu(mgr, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_appkey_add_pdu(mgr, out, NULL));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_bind_pdu(mgr, 1, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_add_pdu(mgr, 1, 0xc000,
	    NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_pub_set_pdu(mgr, 1, 0xc000,
	    5, 0, 0, NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_devkey_seal(NULL, NULL, out, 1, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_devkey_seal(mgr, NULL, out, 1, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_devkey_open(NULL, NULL, 0, 0, 0, out, 1,
	    out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_comp_get_pdu(NULL, 0, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_comp_status_apply(NULL, out, 1));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_comp_status_apply((struct mesh_mgr_node *)mgr,
	    NULL, 0));
	mesh_mgr_kr_begin(NULL);
	ATF_CHECK_EQ(-1, mesh_mgr_kr_ack(NULL, 1));
	ATF_CHECK_EQ(-1, mesh_mgr_kr_ack(mgr, 0x7777));
	ATF_CHECK_EQ(0u, mesh_mgr_kr_pending(NULL));

	/* Every Configuration Client family rejects a missing manager. */
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_netkey_add_pdu(NULL, 1, key, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_netkey_update_pdu(NULL, 1, key, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_netkey_delete_pdu(NULL, 1, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_kr_phase_get_pdu(NULL, 1, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_kr_phase_set_pdu(NULL, 1, 2, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_appkey_update_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_appkey_delete_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_appkey_get_pdu(NULL, 0, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_u8_state_get_pdu(NULL, 1, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_u8_state_set_pdu(NULL, 1, 0, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_relay_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_relay_set_pdu(NULL, 0, 0, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_net_transmit_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_net_transmit_set_pdu(NULL, 0, 0, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_unbind_pdu(NULL, 1, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_delete_pdu(NULL, 1, 0xc000,
	    NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_overwrite_pdu(NULL, 1, 0xc000,
	    NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_delete_all_pdu(NULL, 1, NULL,
	    out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_node_reset_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_label_to_virtual_addr(NULL, &addr));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_pub_va_set_pdu(NULL, 1, uuid, 0,
	    0, 0, NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_va_add_pdu(NULL, 1, uuid, NULL,
	    out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_va_delete_pdu(NULL, 1, uuid,
	    NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_va_overwrite_pdu(NULL, 1, uuid,
	    NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_pub_get_pdu(NULL, 1, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_get_pdu(NULL, 1, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_get_pdu(NULL, 1, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_node_identity_get_pdu(NULL, 0, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_node_identity_set_pdu(NULL, 0, 0, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_lpn_polltimeout_get_pdu(NULL, 1, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_hb_pub_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_hb_pub_set_pdu(NULL, NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_hb_sub_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_hb_sub_set_pdu(NULL, 1, 2, 3, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_sar_tx_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_sar_tx_set_pdu(NULL, NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_sar_rx_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_sar_rx_set_pdu(NULL, NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_od_priv_proxy_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_od_priv_proxy_set_pdu(NULL, 0, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_priv_beacon_get_pdu(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_priv_beacon_set_pdu(NULL, NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_priv_gatt_proxy_get_pdu(NULL, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_priv_gatt_proxy_set_pdu(NULL, 0, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_priv_node_identity_get_pdu(NULL, 0, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_priv_node_identity_set_pdu(NULL, 0, 0,
	    out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_lcd_get_pdu(NULL, 0, 0, out, &outlen));
}

ATF_TC_WITHOUT_HEAD(normative_boundary_matrix);
ATF_TC_BODY(normative_boundary_matrix, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	struct mesh_cfg_model_id model;
	uint8_t key[16] = { 0 }, out[MESH_UPPER_MAX];
	size_t outlen;

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	memset(&model, 0, sizeof(model));
	model.model_id = BT_MMGR_MODEL_GEN_ONOFF_SRV;

	/*
	 * MshPRT 1.1 §4.3.1.1: key indexes are exactly 12 bits.
	 * Verify the largest encoded value and the first reserved value using
	 * constants maintained independently of the implementation headers.
	 */
	ATF_CHECK_EQ(0, mesh_mgr_cfg_netkey_add_pdu(mgr,
	    BT_MMGR_KEY_INDEX_MAX, key, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_netkey_add_pdu(mgr,
	    BT_MMGR_KEY_INDEX_FIRST_RESERVED, key, out, &outlen));
	ATF_CHECK_EQ(0, mesh_mgr_cfg_kr_phase_get_pdu(mgr,
	    BT_MMGR_KEY_INDEX_MAX, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_kr_phase_get_pdu(mgr,
	    BT_MMGR_KEY_INDEX_FIRST_RESERVED, out, &outlen));
	mgr->appkey_index = BT_MMGR_KEY_INDEX_MAX;
	ATF_CHECK_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr,
	    BT_MMGR_UNICAST_MAX, &model, out, &outlen));
	mgr->appkey_index = BT_MMGR_KEY_INDEX_FIRST_RESERVED;
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_bind_pdu(mgr,
	    BT_MMGR_UNICAST_MAX, &model, out, &outlen));
	mgr->appkey_index = 0;

	/*
	 * MshPRT 1.1 §4.3.2.15-.24: ElementAddress is unicast; plain
	 * subscription Address is a non-All-Nodes group address; a plain
	 * PublishAddress may be unassigned/unicast/group but never virtual.
	 */
	ATF_CHECK_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(mgr,
	    BT_MMGR_UNICAST_MIN, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_bind_pdu(mgr,
	    BT_MMGR_UNASSIGNED, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_bind_pdu(mgr,
	    BT_MMGR_VIRTUAL_PREFIX, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_unbind_pdu(mgr,
	    BT_MMGR_GROUP_MIN, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_pub_get_pdu(mgr,
	    BT_MMGR_UNASSIGNED, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_get_pdu(mgr,
	    BT_MMGR_VIRTUAL_PREFIX, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_app_get_pdu(mgr,
	    BT_MMGR_GROUP_MIN, &model, out, &outlen));

	ATF_CHECK_EQ(0, mesh_mgr_cfg_model_sub_add_pdu(mgr,
	    BT_MMGR_UNICAST_MIN, BT_MMGR_GROUP_MIN, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_add_pdu(mgr,
	    BT_MMGR_UNICAST_MIN, BT_MMGR_UNASSIGNED, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_add_pdu(mgr,
	    BT_MMGR_UNICAST_MIN, BT_MMGR_UNICAST_MAX, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_add_pdu(mgr,
	    BT_MMGR_UNICAST_MIN, BT_MMGR_VIRTUAL_MAX, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_add_pdu(mgr,
	    BT_MMGR_UNICAST_MIN, BT_MMGR_ALL_NODES, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_delete_pdu(mgr,
	    BT_MMGR_UNASSIGNED, BT_MMGR_GROUP_MIN, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_overwrite_pdu(mgr,
	    BT_MMGR_UNICAST_MIN, BT_MMGR_VIRTUAL_PREFIX, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_delete_all_pdu(mgr,
	    BT_MMGR_ALL_NODES, &model, out, &outlen));

	ATF_CHECK_EQ(0, mesh_mgr_cfg_model_pub_set_pdu(mgr,
	    BT_MMGR_UNICAST_MAX, BT_MMGR_UNASSIGNED, 0, 0, 0, &model, out,
	    &outlen));
	ATF_CHECK_EQ(0, mesh_mgr_cfg_model_pub_set_pdu(mgr,
	    BT_MMGR_UNICAST_MAX, BT_MMGR_GROUP_MIN, 0, 0, 0, &model, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_pub_set_pdu(mgr,
	    BT_MMGR_UNICAST_MAX, BT_MMGR_VIRTUAL_PREFIX, 0, 0, 0, &model, out,
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_pub_va_set_pdu(mgr,
	    BT_MMGR_UNASSIGNED, key, 0, 0, 0, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_va_add_pdu(mgr,
	    BT_MMGR_VIRTUAL_PREFIX, key, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_va_delete_pdu(mgr,
	    BT_MMGR_GROUP_MIN, key, &model, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_model_sub_va_overwrite_pdu(mgr,
	    BT_MMGR_UNASSIGNED, key, &model, out, &outlen));

	/* MshPRT 1.1 §4.3.2.67: LPNAddress is a primary unicast address. */
	ATF_CHECK_EQ(0, mesh_mgr_cfg_lpn_polltimeout_get_pdu(mgr,
	    BT_MMGR_UNICAST_MAX, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_lpn_polltimeout_get_pdu(mgr,
	    BT_MMGR_UNASSIGNED, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_mgr_cfg_lpn_polltimeout_get_pdu(mgr,
	    BT_MMGR_GROUP_MIN, out, &outlen));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, create_network);
	ATF_TP_ADD_TC(tp, alloc_unicast);
	ATF_TP_ADD_TC(tp, roster_ops);
	ATF_TP_ADD_TC(tp, roster_persist);
	ATF_TP_ADD_TC(tp, cfg_client_bytes);
	ATF_TP_ADD_TC(tp, devkey_roundtrip);
	ATF_TP_ADD_TC(tp, comp_data_discovery);
	ATF_TP_ADD_TC(tp, key_management);
	ATF_TP_ADD_TC(tp, key_refresh_config_client);
	ATF_TP_ADD_TC(tp, key_refresh_network_ack);
	ATF_TP_ADD_TC(tp, node_state);
	ATF_TP_ADD_TC(tp, unbind_unsub_reset);
	ATF_TP_ADD_TC(tp, txn_retry_sm);
	ATF_TP_ADD_TC(tp, e2e_create_provision_configure);
	ATF_TP_ADD_TC(tp, virtual_addr_pubsub);
	ATF_TP_ADD_TC(tp, model_app_list);
	ATF_TP_ADD_TC(tp, node_identity_lpn);
	ATF_TP_ADD_TC(tp, heartbeat_config);
	ATF_TP_ADD_TC(tp, v11_config_client);
	ATF_TP_ADD_TC(tp, added_txn_correlation);
	ATF_TP_ADD_TC(tp, manager_guard_matrix);
	ATF_TP_ADD_TC(tp, normative_boundary_matrix);

	return (atf_no_error());
}

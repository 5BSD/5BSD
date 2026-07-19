/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * mesh_provision_configure - a worked example of the libblemesh network-manager
 * (Config Client) API: create a mesh network, record a provisioned node with
 * its DevKey, then build and seal the Configuration messages that commission it
 * (AppKey Add + Model App Bind), recover them to prove the DevKey round-trip,
 * and persist / reload the manager database.
 *
 * This is the in-process, radio-free counterpart of the meshctl(8) workflow:
 *
 *     meshctl create-network
 *     meshctl provision <uuid> 1
 *     meshctl cfg appkey-add  <addr>
 *     meshctl cfg model-bind  <addr> <elem> <model>
 *
 * Build (inside the source tree):  make
 * Run:                             ./mesh_provision_configure
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_manager.h"
#include "mesh_cfg_model.h"

static void
hexdump(const char *label, const uint8_t *p, size_t n)
{
	size_t i;

	printf("%-22s", label);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

int
main(void)
{
	struct mesh_mgr mgr;
	struct mesh_mgr_node *node;
	struct mesh_cfg_model_id model;
	uint8_t uuid[16], devkey[16];
	uint8_t req[64], upper[96], plain[64];
	uint8_t netkey[16], appkey[16];
	size_t req_len, upper_len, plain_len;
	uint32_t seq;
	uint16_t addr;

	/* 1. Create a network: mints the primary NetKey / AppKey and IV Index 0. */
	memset(&mgr, 0, sizeof(mgr));
	if (mesh_mgr_create_network(&mgr, netkey, appkey) != 0) {
		fprintf(stderr, "create-network failed\n");
		return (1);
	}
	printf("Created network: self=0x%04x netidx=%u appidx=%u iv=%u\n",
	    mgr.self_addr, mgr.netkey_index, mgr.appkey_index, mgr.iv_index);
	hexdump("  NetKey", netkey, sizeof(netkey));
	hexdump("  AppKey", appkey, sizeof(appkey));

	/*
	 * 2. Record a provisioned node.  Over the air the DevKey is derived by the
	 * provisioning handshake; here we allocate an address block and store a
	 * demo DevKey directly (as meshd's provisioner does on commit).
	 */
	memset(uuid, 0xA5, sizeof(uuid));
	memset(devkey, 0x42, sizeof(devkey));
	if (mesh_mgr_alloc_unicast(&mgr, 1, &addr) != 0) {
		fprintf(stderr, "address allocation failed\n");
		return (1);
	}
	node = mesh_mgr_add_node(&mgr, uuid, addr, 1, devkey, 0);
	if (node == NULL) {
		fprintf(stderr, "roster add failed\n");
		return (1);
	}
	printf("\nProvisioned node at 0x%04x (roster size %zu)\n", node->addr,
	    mesh_mgr_node_count(&mgr));

	/*
	 * 3. Config AppKey Add: build the plaintext Configuration message, seal it
	 * to the node under its DevKey, then recover it to prove the round-trip.
	 */
	if (mesh_mgr_cfg_appkey_add_pdu(&mgr, req, &req_len) != 0) {
		fprintf(stderr, "appkey-add build failed\n");
		return (1);
	}
	if (mesh_mgr_devkey_seal(&mgr, node, req, req_len, &seq, upper,
	    &upper_len) != 0) {
		fprintf(stderr, "devkey seal failed\n");
		return (1);
	}
	printf("\nConfig AppKey Add (%zu octets), sealed to seq %u:\n", req_len,
	    seq);
	hexdump("  plaintext", req, req_len);
	hexdump("  sealed (upper)", upper, upper_len);
	if (mesh_mgr_devkey_open(&mgr, node, seq, mgr.self_addr, node->addr,
	    upper, upper_len, plain, &plain_len) != 0 ||
	    plain_len != req_len || memcmp(plain, req, req_len) != 0) {
		fprintf(stderr, "devkey open round-trip failed\n");
		return (1);
	}
	printf("  DevKey round-trip OK\n");

	/*
	 * 4. Config Model App Bind: bind the AppKey to the Generic OnOff Server
	 * (SIG model 0x1000) on the node's primary element.
	 */
	memset(&model, 0, sizeof(model));
	model.vendor = 0;
	model.model_id = 0x1000;		/* Generic OnOff Server */
	if (mesh_mgr_cfg_model_app_bind_pdu(&mgr, node->addr, &model, req,
	    &req_len) != 0) {
		fprintf(stderr, "model-bind build failed\n");
		return (1);
	}
	if (mesh_mgr_devkey_seal(&mgr, node, req, req_len, &seq, upper,
	    &upper_len) != 0) {
		fprintf(stderr, "model-bind seal failed\n");
		return (1);
	}
	printf("\nConfig Model App Bind (model 0x%04x) sealed to seq %u\n",
	    model.model_id, seq);

	/* 5. Persist and reload the manager database (network + roster + DevKeys). */
	if (mesh_mgr_save(&mgr, "/tmp/mesh_example.mgr") == 0) {
		struct mesh_mgr reloaded;

		memset(&reloaded, 0, sizeof(reloaded));
		if (mesh_mgr_load(&reloaded, "/tmp/mesh_example.mgr") == 0 &&
		    mesh_mgr_node_count(&reloaded) == mesh_mgr_node_count(&mgr))
			printf("\nPersisted and reloaded %zu node(s) from"
			    " /tmp/mesh_example.mgr\n",
			    mesh_mgr_node_count(&reloaded));
	}

	printf("\nDone.\n");
	return (0);
}

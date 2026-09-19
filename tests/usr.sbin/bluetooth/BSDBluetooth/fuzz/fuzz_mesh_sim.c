/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh multi-node simulator receive
 * pipeline (lib/libmesh/mesh_sim.c) and the Generic-model message parsers
 * (lib/libmesh/mesh_generic.c).
 *
 * The fuzz input is treated as an ATTACKER-INJECTED secured Network PDU
 * dropped onto the shared advertising medium of a fully wired network:
 *
 *   client + OnOff/Level servers, a Relay node, a Friend/LPN pair and a
 *   group subscription.
 *
 * Injecting the raw bytes and stepping the simulator drives every node's
 * whole receive path against untrusted input: network NID/IV candidate
 * matching, deobfuscation + AES-CCM + NetMIC (keyed with the fixed
 * MshPRT_v1.1 Section 8 material so the crypto actually runs), the network
 * message cache, the Relay feature, the Friend Queue, the RPL, lower-transport
 * parse + SAR reassembly, upper-transport AppKey decrypt and access-layer
 * model dispatch.  The overwhelming majority of inputs fail the NetMIC, but
 * only after the parse/deobfuscate/decrypt/reassembly code has chewed on them.
 *
 * The same bytes are also fed directly to the Generic OnOff / Level message
 * decoders and the server receive entry points, exercising the codec length
 * and range checks on arbitrary input.
 *
 * ASan/UBSan catch any out-of-bounds access or undefined behaviour.
 *
 * Reference: MshPRT_v1.1 Section 3.4-3.8; MshMDL_v1.1 Section 3.2 / 7.1.
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_sim.h"
#include "mesh_generic.h"

/* Section 8 canonical NetKey / AppKey (host-order bytes). */
static const uint8_t NETKEY[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t APPKEY[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};

static void
fuzz_generic_parsers(const uint8_t *data, size_t size)
{
	struct mesh_gen_onoff_set os;
	struct mesh_gen_onoff_status ost;
	struct mesh_gen_level_set ls;
	struct mesh_gen_delta_set ds;
	struct mesh_gen_move_set ms;
	struct mesh_gen_level_status lst;
	struct mesh_gen_onoff_srv osrv;
	struct mesh_gen_level_srv lsrv;
	struct mesh_gen_onoff_cli ocli;
	struct mesh_gen_level_cli lcli;
	struct mesh_gen_onoff_status osx;
	struct mesh_gen_level_status lsx;
	int want;

	(void)mesh_gen_onoff_set_decode(data, size, &os);
	(void)mesh_gen_onoff_status_decode(data, size, &ost);
	(void)mesh_gen_level_set_decode(data, size, &ls);
	(void)mesh_gen_delta_set_decode(data, size, &ds);
	(void)mesh_gen_move_set_decode(data, size, &ms);
	(void)mesh_gen_level_status_decode(data, size, &lst);

	/* Server receive entry points across the whole Generic opcode set. */
	mesh_gen_onoff_srv_init(&osrv, 0);
	mesh_gen_level_srv_init(&lsrv, 0);
	if (size >= 1) {
		uint32_t op = 0x8200u | data[0];	/* 0x8200..0x82FF */
		const uint8_t *pp = (size > 1) ? data + 1 : NULL;
		size_t pl = (size > 1) ? size - 1 : 0;

		(void)mesh_gen_onoff_srv_recv(&osrv, 0x0001, op, pp, pl, &osx,
		    &want);
		(void)mesh_gen_level_srv_recv(&lsrv, 0x0001, op, pp, pl, &lsx,
		    &want);
		mesh_gen_onoff_cli_init(&ocli);
		mesh_gen_level_cli_init(&lcli);
		(void)mesh_gen_onoff_cli_recv(&ocli, op, pp, pl);
		(void)mesh_gen_level_cli_recv(&lcli, op, pp, pl);
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mesh_sim *sim;
	struct mesh_node *c, *r, *s1, *s2, *f, *l;
	struct mesh_gen_onoff_srv onoff1, onoff2;
	struct mesh_gen_level_srv level1;
	struct mesh_gen_onoff_cli cli;
	uint8_t *copy;

	if (size > 96)
		size = 96;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	fuzz_generic_parsers(copy, size);

	sim = calloc(1, sizeof(*sim));
	if (sim == NULL) {
		free(copy);
		return (0);
	}
	if (mesh_sim_init(sim, NETKEY, APPKEY, 0x12345678) != 0)
		goto out;

	c = mesh_sim_add_node(sim, 0x0001, 1);
	r = mesh_sim_add_node(sim, 0x0002, 1);
	s1 = mesh_sim_add_node(sim, 0x0003, 1);
	s2 = mesh_sim_add_node(sim, 0x0004, 1);
	f = mesh_sim_add_node(sim, 0x0005, 1);
	l = mesh_sim_add_node(sim, 0x0009, 1);
	if (c == NULL || r == NULL || s1 == NULL || s2 == NULL || f == NULL ||
	    l == NULL)
		goto out;

	mesh_gen_onoff_srv_init(&onoff1, 0);
	mesh_gen_onoff_srv_init(&onoff2, 0);
	mesh_gen_level_srv_init(&level1, 0);
	mesh_gen_onoff_cli_init(&cli);
	(void)mesh_sim_add_model(c, 0, mesh_gen_onoff_cli_model(&cli));
	(void)mesh_sim_add_model(s1, 0, mesh_gen_onoff_srv_model(&onoff1));
	(void)mesh_sim_add_model(s1, 0, mesh_gen_level_srv_model(&level1));
	(void)mesh_sim_add_model(s2, 0, mesh_gen_onoff_srv_model(&onoff2));
	(void)mesh_sim_add_model(l, 0, mesh_gen_onoff_srv_model(&onoff2));
	mesh_sim_set_relay(r, 1);
	(void)mesh_sim_subscribe(s1, 0xC000);
	(void)mesh_sim_subscribe(s2, 0xC000);
	(void)mesh_sim_set_friend(f, 0x0009, 1, 8);
	(void)mesh_sim_set_lpn(l, 0x0005, 0x0000a0);

	/* Attacker injection: the fuzz bytes ARE a received secured Network
	 * PDU on the medium (tx_node -1 => delivered to every node). */
	if (size != 0 && mesh_sim_reinject(sim, -1, copy, size) == 0)
		(void)mesh_sim_run(sim, 6);

	/* Poll the LPN so the Friend delivery + control path is exercised. */
	(void)mesh_sim_lpn_poll(sim, l);

out:
	free(sim);
	free(copy);
	return (0);
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Probe-tap build of meshd_node.c for meshd_test.
 *
 * meshd_node.c is shared by several Mesh daemon tests.  This private wrapper
 * lets meshd_test compile the application-socket probe sites with
 * -DMESHD_WITH_PROBE_TAP without changing the shared production-style object
 * used by the rest of the suite.
 */

#include "meshd_node.c"

int ptap_meshd_node_handler_guard_sweep(struct meshd_node *);
int ptap_meshd_node_internal_state_sweep(struct meshd_node *);

/*
 * White-box sweep for handler-local validation.  The public dispatcher rejects
 * malformed Access PDUs before selecting a handler, so these otherwise valid
 * defensive arms need a test-only call site below the translation-unit include.
 */
int
ptap_meshd_node_handler_guard_sweep(struct meshd_node *nd)
{
	struct mesh_access_pdu ap;
	struct meshd_node saved;
	uint8_t bad[] = { 0x7f };
	uint8_t pdu[40], params[32];
	uint8_t reply[MESH_ACCESS_PAYLOAD_MAX];
	size_t i, j, plen, reply_len;

	if (nd == NULL)
		return (-1);
	saved = *nd;
	memset(&ap, 0, sizeof(ap));
	for (i = 0; i < nitems(meshd_cfg_table); i++) {
		ap.opcode = meshd_cfg_table[i].opcode;
		reply_len = SIZE_MAX;
		(void)meshd_cfg_table[i].fn(nd, &ap, bad, sizeof(bad), reply, 0,
		    &reply_len);

		/* Opcode-only is valid for Get/Reset handlers and short for setters. */
		plen = sizeof(pdu);
		if (mesh_access_pdu_build(ap.opcode, NULL, 0, pdu, &plen) == 0) {
			reply_len = SIZE_MAX;
			(void)meshd_cfg_table[i].fn(nd, &ap, pdu, plen, reply, 0,
			    &reply_len);
		}

		/* Systematically cross each handler's exact-size parser and status
		 * validation.  Zero and all-one payloads exercise valid defaults and
		 * reserved/out-of-range identifiers without coupling the test to the
		 * individual wire structure sizes.  Restore node-local state between
		 * calls so one setter cannot mask a later handler arm. */
		for (j = 0; j <= sizeof(params); j++) {
			memset(params, 0, sizeof(params));
			plen = sizeof(pdu);
			if (mesh_access_pdu_build(ap.opcode, params, j, pdu,
			    &plen) == 0) {
				*nd = saved;
				reply_len = 0;
				(void)meshd_cfg_table[i].fn(nd, &ap, pdu, plen,
				    reply, sizeof(reply), &reply_len);
			}
			memset(params, 0xff, sizeof(params));
			plen = sizeof(pdu);
			if (mesh_access_pdu_build(ap.opcode, params, j, pdu,
			    &plen) == 0) {
				*nd = saved;
				reply_len = 0;
				(void)meshd_cfg_table[i].fn(nd, &ap, pdu, plen,
				    reply, sizeof(reply), &reply_len);
			}
			for (size_t k = 0; k < sizeof(params); k++)
				params[k] = (k & 1) != 0 ?
				    (uint8_t)(saved.addr >> 8) : (uint8_t)saved.addr;
			plen = sizeof(pdu);
			if (mesh_access_pdu_build(ap.opcode, params, j, pdu,
			    &plen) == 0) {
				*nd = saved;
				reply_len = 0;
				(void)meshd_cfg_table[i].fn(nd, &ap, pdu, plen,
				    reply, sizeof(reply), &reply_len);
			}
			for (size_t k = 0; k < sizeof(params); k++)
				params[k] = (uint8_t)k;
			plen = sizeof(pdu);
			if (mesh_access_pdu_build(ap.opcode, params, j, pdu,
			    &plen) == 0) {
				*nd = saved;
				reply_len = 0;
				(void)meshd_cfg_table[i].fn(nd, &ap, pdu, plen,
				    reply, sizeof(reply), &reply_len);
			}
		}
	}
	*nd = saved;
	return ((int)nitems(meshd_cfg_table));
}

int
ptap_meshd_node_internal_state_sweep(struct meshd_node *nd)
{
	struct meshd_app_surface *apps;
	struct meshd_app_client cl;
	struct meshd_app_event ev;
	struct meshd_app_reg reg;
	struct mesh_cfg_model_app bind;
	struct mesh_cfg_model_sub sub;
	struct mesh_cfg_model_sub_va subva;
	struct mesh_cfg_model_pub pub;
	struct mesh_cfg_model_pub_va pubva;
	struct mesh_cfg_model_id id, other;
	struct meshd_model_entry model;
	struct mesh_model runtime_saved, *runtime;
	struct mesh_sim_rx rx;
	struct mesh_friend_out fout;
	struct mesh_lpn_out lout;
	struct mesh_fq_entry fq;
	struct mesh_prov_data pd;
	struct mesh_gen_battery_status battery;
	struct mesh_gen_location_global global;
	struct mesh_gen_location_local local;
	struct meshd_config cfg;
	uint8_t key[16] = { 0 }, label[16] = { 1 };
	uint8_t packet[64] = { 0 }, response[64];
	uint16_t app_binding, sub_addr, virtual_addr;
	int sub_is_va;
	size_t packet_len, response_len;
	int iv_changed;
	size_t i;

	if (nd == NULL)
		return (-1);
	apps = calloc(1, sizeof(*apps));
	if (apps == NULL)
		return (-1);
	memset(&id, 0, sizeof(id));
	id.model_id = 0x1000;
	other = id;
	other.model_id++;

	(void)meshd_model_id_eq(&id, &other);
	id.vendor = other.vendor = 1;
	id.company_id = 1;
	other.company_id = 2;
	(void)meshd_model_id_eq(&id, &other);
	other = id;
	(void)meshd_model_id_eq(&id, &other);

	(void)meshd_app_surface_register(NULL, 1, &id, 0, 0);
	(void)meshd_app_surface_register(apps, 1, NULL, 0, 0);
	(void)meshd_app_surface_register(apps, 1, &id, 0, 0);
	(void)meshd_app_surface_register(apps, 1, &id, 0, 0);
	(void)meshd_app_surface_unregister(apps, 2, &id);
	(void)meshd_app_surface_unregister(apps, 1, &id);
	(void)meshd_app_surface_unregister(NULL, 1, &id);
	(void)meshd_app_surface_event_count(NULL);
	(void)meshd_app_surface_event_dropped(NULL);
	(void)meshd_app_surface_event_pop(NULL, &ev);
	(void)meshd_app_surface_event_pop(apps, NULL);

	memset(&reg, 0, sizeof(reg));
	reg.valid = 1;
	reg.elem_addr = 1;
	reg.id = id;
	memset(&rx, 0, sizeof(rx));
	rx.params_len = sizeof(rx.params) + 1;
	meshd_app_surface_queue_rx(NULL, &rx, &reg, -1);
	apps->ev_count = MESHD_APP_EVENT_MAX;
	meshd_app_surface_queue_rx(apps, &rx, &reg, -1);
	(void)meshd_app_surface_event_pop(apps, &ev);

	memset(apps, 0, sizeof(*apps));
	apps->n_regs = MESHD_MAX_APP_REGS;
	(void)meshd_app_surface_register(apps, 1, &id, 0, 0);
	memset(apps, 0, sizeof(*apps));
	apps->n_regs = 1;
	for (i = 0; i < MESHD_MAX_APP_REGS; i++) {
		apps->regs[i].valid = 1;
		apps->regs[i].elem_addr = (uint16_t)(i + 2);
	}
	(void)meshd_app_surface_register(apps, 1, &id, 0, 0);
	free(apps);

	/* Exhaust and reopen each fixed-size roster allocator. */
	memset(&nd->db, 0, sizeof(nd->db));
	for (i = 0; i < MESHD_MAX_NETKEYS; i++)
		nd->db.netkeys[i].valid = 1;
	(void)meshd_alloc_netkey(nd);
	nd->db.netkeys[1].valid = 0;
	(void)meshd_alloc_netkey(nd);
	(void)meshd_find_netkey(nd, 0xfff);
	for (i = 0; i < MESHD_MAX_APPKEYS; i++)
		nd->db.appkeys[i].valid = 1;
	(void)meshd_alloc_appkey(nd);
	nd->db.appkeys[1].valid = 0;
	(void)meshd_alloc_appkey(nd);
	(void)meshd_find_appkey(nd, 0xfff);

	nd->db.n_models = 0;
	(void)meshd_find_model(nd, nd->addr, &id);
	(void)meshd_find_or_add_model(nd, nd->addr, &id);
	(void)meshd_find_or_add_model(nd, nd->addr, &id);
	nd->db.n_models = MESHD_MAX_MODELS;
	(void)meshd_find_or_add_model(nd, nd->addr, &other);
	(void)meshd_element_valid(NULL, 1);
	(void)meshd_element_valid(nd, (uint16_t)(nd->addr - 1));
	(void)meshd_element_valid(nd,
	    (uint16_t)(nd->addr + nd->self->n_elements));

	memset(&model, 0, sizeof(model));
	(void)meshd_sub_mutate(&model, MESH_CFG_OP_MODEL_SUB_ADD, 0xc001, NULL);
	(void)meshd_sub_mutate(&model, MESH_CFG_OP_MODEL_SUB_ADD, 0xc001, NULL);
	(void)meshd_sub_mutate(&model, MESH_CFG_OP_MODEL_SUB_DELETE, 0xc002, NULL);
	(void)meshd_sub_mutate(&model, MESH_CFG_OP_MODEL_SUB_VA_ADD, 0x8001,
	    label);
	(void)meshd_sub_mutate(&model, MESH_CFG_OP_MODEL_SUB_VA_DELETE, 0x8001,
	    label);
	model.n_subs = MESHD_MAX_SUBS;
	(void)meshd_sub_mutate(&model, MESH_CFG_OP_MODEL_SUB_ADD, 0xc003, NULL);
	(void)meshd_sub_mutate(&model, MESH_CFG_OP_MODEL_SUB_OVERWRITE, 0xc004,
	    NULL);

	/* Binding status matrix: address, key, model, Config Server and capacity. */
	memset(&bind, 0, sizeof(bind));
	bind.elem_addr = 0;
	bind.app_idx = 7;
	bind.model = id;
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_BIND, &bind);
	bind.elem_addr = nd->addr;
	memset(&nd->db, 0, sizeof(nd->db));
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_BIND, &bind);
	nd->db.appkeys[0].valid = 1;
	nd->db.appkeys[0].app_idx = bind.app_idx;
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_BIND, &bind);
	nd->db.n_models = 1;
	nd->db.models[0].valid = 1;
	nd->db.models[0].elem_addr = nd->addr;
	nd->db.models[0].id = bind.model;
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_UNBIND, &bind);
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_BIND, &bind);
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_BIND, &bind);
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_UNBIND, &bind);
	nd->db.models[0].n_app = MESHD_MAX_BINDINGS;
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_BIND, &bind);
	nd->db.models[0].id.vendor = 0;
	nd->db.models[0].id.model_id = 0;
	bind.model = nd->db.models[0].id;
	(void)meshd_do_bind(nd, MESH_CFG_OP_MODEL_APP_BIND, &bind);

	(void)meshd_devkey_rx(NULL, 0, 0, 0, key, sizeof(key), key, &i);
	(void)meshd_devkey_rx(nd, 0, (uint16_t)(nd->addr + 1), 0, key,
	    sizeof(key), key, &i);
	(void)meshd_remote_devkey(NULL, 1, key);
	(void)meshd_remote_devkey(nd, 1, NULL);
	(void)meshd_remote_devkey(nd, 1, key);
	(void)meshd_remote_devkey_rx(NULL, 0, 0, 0, key, sizeof(key));

	/* Application-client guards sit above the surface registry and have
	 * independent active/model/opcode validation. */
	memset(&cl, 0, sizeof(cl));
	meshd_app_client_init(NULL, -1);
	meshd_app_client_fini(NULL);
	(void)meshd_app_client_register_model(NULL, &cl, 0, &id);
	(void)meshd_app_client_register_model(nd, &cl, nd->addr, &id);
	meshd_app_client_init(&cl, -1);
	(void)meshd_app_client_register_model(nd, &cl, 0, &id);
	(void)meshd_app_client_register_model(nd, &cl, nd->addr, NULL);
	(void)meshd_app_client_register_opcode(nd, &cl, nd->addr, NULL, 0);
	(void)meshd_app_client_register_opcode(nd, &cl, nd->addr, &id,
	    UINT32_MAX);
	(void)meshd_app_client_unregister_model(NULL, nd->addr, &id);
	(void)meshd_app_client_unregister_model(&cl, nd->addr, NULL);
	(void)meshd_app_client_event_count(NULL);
	(void)meshd_app_client_event_dropped(NULL);
	(void)meshd_app_client_event_pop(NULL, &ev);
	meshd_app_client_fini(&cl);

	/* Exercise exact application-model routing: vendor identity, explicit
	 * opcode, AppKey binding, group subscription, and virtual subscription. */
	apps = calloc(1, sizeof(*apps));
	if (apps == NULL)
		return (-1);
	runtime = &nd->self->models[0][0];
	runtime_saved = *runtime;
	memset(&reg, 0, sizeof(reg));
	reg.valid = 1;
	reg.elem_addr = nd->self->elems[0].addr;
	reg.id.model_id = runtime->model_id;
	reg.id.vendor = 1;
	reg.id.company_id = 0x1234;
	reg.has_opcode = 1;
	reg.opcode = 0xc11234;
	apps->regs[0] = reg;
	apps->n_regs = 1;
	runtime->company_id = reg.id.company_id;
	runtime->app_opcodes[0] = reg.opcode;
	runtime->n_app_opcodes = 1;
	app_binding = 7;
	runtime->app_idx = &app_binding;
	runtime->n_app = 1;
	runtime->bindings_configured = 1;
	sub_addr = 0xc123;
	sub_is_va = 0;
	runtime->subs = &sub_addr;
	runtime->sub_is_va = &sub_is_va;
	runtime->labels = (const uint8_t (*)[MESH_LABEL_UUID_LEN])&label;
	runtime->n_subs = 1;
	runtime->subscriptions_configured = 1;
	memset(&nd->self->rx, 0, sizeof(nd->self->rx));
	nd->self->rx.valid = 1;
	nd->self->rx.opcode = reg.opcode;
	nd->self->rx.app_idx = 8;
	nd->self->rx.dst = sub_addr;
	(void)meshd_app_match_rx(nd, apps); /* wrong AppKey */
	nd->self->rx.app_idx = app_binding;
	(void)meshd_app_match_rx(nd, apps); /* group subscription */
	memset(label, 0x5a, sizeof(label));
	if (mesh_virtual_addr(label, &virtual_addr) == 0) {
		sub_is_va = 1;
		nd->self->rx.dst = virtual_addr;
		(void)meshd_app_match_rx(nd, apps);
	}
	/* Explicit opcode requested but not registered by the runtime model. */
	runtime->n_app_opcodes = 0;
	(void)meshd_app_match_rx(nd, apps);
	*runtime = runtime_saved;
	memset(&nd->self->rx, 0, sizeof(nd->self->rx));
	free(apps);

	memset(&battery, 0, sizeof(battery));
	memset(&global, 0, sizeof(global));
	memset(&local, 0, sizeof(local));
	(void)meshd_set_battery(NULL, &battery);
	(void)meshd_set_battery(nd, NULL);
	(void)meshd_set_location_global(NULL, &global);
	(void)meshd_set_location_global(nd, NULL);
	(void)meshd_set_location_local(NULL, &local);
	(void)meshd_set_location_local(nd, NULL);

	/* Public node APIs promise defensive rejection for absent objects and
	 * malformed transport inputs.  Keep that contract covered as the Mesh
	 * surface grows instead of testing only the happy-path helpers. */
	memset(&fout, 0, sizeof(fout));
	memset(&lout, 0, sizeof(lout));
	memset(&fq, 0, sizeof(fq));
	memset(&pd, 0, sizeof(pd));
	memset(&cfg, 0, sizeof(cfg));
	packet_len = sizeof(packet);
	(void)meshd_node_init(NULL, &cfg);
	(void)meshd_node_init(nd, NULL);
	meshd_set_bearer(NULL, NULL);
	(void)meshd_node_restore(NULL, key, key, 0, 1);
	(void)meshd_node_restore(nd, NULL, key, 0, 1);
	(void)meshd_node_tick(NULL, 0, &iv_changed);
	(void)meshd_provision_local(NULL, &pd);
	(void)meshd_provision_local(nd, NULL);
	(void)meshd_provision_recv_data(NULL, key, key, packet, key);
	(void)meshd_bearer_rx(NULL, packet, 1);
	(void)meshd_bearer_rx(nd, NULL, 1);
	(void)meshd_beacon_emit(NULL);
	(void)meshd_beacon_rx(NULL, packet, 1);
	(void)meshd_beacon_rx(nd, NULL, 1);
	(void)meshd_send_onoff(NULL, 1, 0, 0);
	(void)meshd_send_level(NULL, 1, 0, 0);
	(void)meshd_send_power_onoff(NULL, 1, 0, 0);
	(void)meshd_send_dtt(NULL, 1, 0, 0);
	(void)meshd_send_power_level(NULL, 1, 0, 0);
	(void)meshd_send_power_default(NULL, 1, 0, 0);
	(void)meshd_send_power_range(NULL, 1, 0, 1, 0);
	(void)meshd_send_access_raw(NULL, 1, packet, 1);
	(void)meshd_send_devkey_raw(NULL, 1, 0, 0, packet, 1);
	(void)meshd_publish_raw(NULL, 1, 0, 0, packet, 1);
	(void)meshd_foundation_recv(NULL, packet, 1, packet,
	    sizeof(packet), &packet_len);
	(void)meshd_kr_begin(NULL, key);
	(void)meshd_kr_advance(NULL);
	(void)meshd_kr_finish(NULL);
	(void)meshd_kr_phase(NULL);
	(void)meshd_friend_enable(NULL, 1, 1, 1, 0, 1);
	(void)meshd_friend_input(NULL, 1, packet, 1, 0, 0, 0, 0, 0, &fout);
	(void)meshd_friend_input(nd, 1, NULL, 1, 0, 0, 0, 0, 0, &fout);
	packet[0] = 0x7f;
	(void)meshd_friend_input(nd, 1, packet, 1, 0, 0, 0, 0, 0, &fout);
	(void)meshd_friend_enable(nd, 1, 1, 1, 0, 1);
	(void)meshd_friend_input(nd, 1, packet, 1, 0, 0, 0, 0, 0, &fout);
	(void)meshd_friend_tick(NULL, 0, &fout);
	(void)meshd_friend_enqueue(NULL, &fq);
	(void)meshd_friend_enqueue(nd, NULL);
	(void)meshd_lpn_enable(NULL, 0, 0, 0, 0, 1, 1, 1, 0, &lout);
	(void)meshd_lpn_recv_offer(NULL, packet, 1, 1, 0);
	nd->lpn_enabled = 0;
	(void)meshd_lpn_recv_offer(nd, packet, 1, 1, 0);
	(void)meshd_lpn_recv_update(NULL, packet, 1, 0, &lout);
	(void)meshd_lpn_recv_update(nd, packet, 1, 0, &lout);
	(void)meshd_lpn_tick(NULL, 0, &lout);
	(void)meshd_lpn_tick(nd, 0, &lout);
	(void)meshd_provisioner_begin(NULL, key, 1, key, key, 0, &pd, 1, 1,
	    0, packet, &packet_len);
	(void)meshd_provisioner_recv(NULL, packet, 1, 0);
	nd->provisioner_active = 0;
	(void)meshd_provisioner_recv(nd, packet, 1, 0);
	(void)meshd_provisioner_poll(NULL, 0, packet, &packet_len);
	(void)meshd_provisioner_poll(nd, 0, packet, &packet_len);
	(void)meshd_provisioner_drain(NULL, 0);
	(void)meshd_provisioner_done(NULL);
	(void)meshd_provisioner_begin_mgr(NULL, NULL, key, 1, 1, key, key, 0,
	    1, 1, 0, packet, &packet_len);
	(void)meshd_provisioner_commit_mgr(NULL, NULL, 0);
	(void)meshd_provision_ota_begin(NULL, key, 1, 0);
	(void)meshd_provision_ota_begin(nd, NULL, 1, 0);
	(void)meshd_provision_ota_begin(nd, key, 0, 0);
	(void)meshd_provision_gatt_begin(NULL, "00:00:00:00:00:00", 0,
	    MESHD_ADAPTER_DEFAULT, key, 1);
	(void)meshd_provision_gatt_begin(nd, NULL, 0, MESHD_ADAPTER_DEFAULT, key, 1);
	(void)meshd_provision_gatt_begin(nd, "bad", 0, MESHD_ADAPTER_DEFAULT, key, 1);
	(void)meshd_provision_ota_commit(NULL, 0);
	(void)meshd_provision_ota_commit(nd, 0);

	/* Drive complete valid Config Model state transitions, complementing the
	 * malformed-size sweep above with real encoded request PDUs. */
	memset(&nd->db, 0, sizeof(nd->db));
	nd->db.netkeys[0].valid = 1;
	nd->db.netkeys[0].net_idx = 0;
	memcpy(nd->db.netkeys[0].key, key, sizeof(key));
	nd->db.appkeys[0].valid = 1;
	nd->db.appkeys[0].net_idx = 0;
	nd->db.appkeys[0].app_idx = 7;
	memcpy(nd->db.appkeys[0].key, key, sizeof(key));
	nd->db.n_models = 1;
	nd->db.models[0].valid = 1;
	nd->db.models[0].elem_addr = nd->addr;
	nd->db.models[0].id.vendor = 0;
	nd->db.models[0].id.model_id = 0x1000;
	(void)mesh_sim_add_appkey(nd->self, 0, 7, key);

	memset(&bind, 0, sizeof(bind));
	bind.elem_addr = nd->addr;
	bind.app_idx = 7;
	bind.model = nd->db.models[0].id;
	packet_len = sizeof(packet);
	if (mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND, &bind,
	    packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}
	packet_len = sizeof(packet);
	if (mesh_cfg_model_app_get_build(MESH_CFG_OP_SIG_MODEL_APP_GET,
	    nd->addr, &bind.model, packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}

	memset(&sub, 0, sizeof(sub));
	sub.elem_addr = nd->addr;
	sub.address = 0xc123;
	sub.model = bind.model;
	packet_len = sizeof(packet);
	if (mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD, &sub,
	    packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}
	packet_len = sizeof(packet);
	if (mesh_cfg_model_sub_get_build(MESH_CFG_OP_SIG_MODEL_SUB_GET,
	    nd->addr, &sub.model, packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}
	packet_len = sizeof(packet);
	if (mesh_cfg_model_sub_del_all_build(nd->addr, &sub.model, packet,
	    &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}

	memset(&subva, 0, sizeof(subva));
	subva.elem_addr = nd->addr;
	subva.model = bind.model;
	memset(subva.label, 0x5a, sizeof(subva.label));
	packet_len = sizeof(packet);
	if (mesh_cfg_model_sub_va_build(MESH_CFG_OP_MODEL_SUB_VA_ADD, &subva,
	    packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}

	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = nd->addr;
	pub.pub_addr = 0xc234;
	pub.app_idx = 7;
	pub.ttl = 5;
	pub.model = bind.model;
	packet_len = sizeof(packet);
	if (mesh_cfg_model_pub_set_build(&pub, packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}
	packet_len = sizeof(packet);
	if (mesh_cfg_model_pub_get_build(nd->addr, &pub.model, packet,
	    &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}
	memset(&pubva, 0, sizeof(pubva));
	pubva.elem_addr = nd->addr;
	pubva.app_idx = 7;
	pubva.ttl = 5;
	pubva.model = bind.model;
	memset(pubva.label, 0xa5, sizeof(pubva.label));
	packet_len = sizeof(packet);
	if (mesh_cfg_model_pub_va_set_build(&pubva, packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}

	packet_len = sizeof(packet);
	if (mesh_cfg_appkey_get_build(0, packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}
	packet_len = sizeof(packet);
	if (mesh_cfg_appkey_delete_build(0, 7, packet, &packet_len) == 0) {
		response_len = 0;
		(void)meshd_foundation_recv(nd, packet, packet_len, response,
		    sizeof(response), &response_len);
	}

	/* Manager-backed DeviceKey sending has independent index, roster and
	 * local-key encryption paths above the simulator transport. */
	nd->mgr = calloc(1, sizeof(*nd->mgr));
	if (nd->mgr == NULL)
		return (-1);
	if (mesh_mgr_create_network(nd->mgr, NULL, NULL) == 0) {
		nd->mgr_active = 1;
		nd->mgr->self_addr = nd->addr;
		nd->mgr->netkey_index = nd->netkey_index;
		nd->mgr->iv_index = mesh_iv_tx_index(&nd->self->iv);
		memcpy(nd->mgr->netkey, nd->self->netkey, 16);
		packet_len = sizeof(packet);
		if (mesh_access_pdu_build(MESH_OP_GEN_ONOFF_GET, NULL, 0, packet,
		    &packet_len) == 0) {
			(void)meshd_send_devkey_raw(nd, nd->addr + 1, 0,
			    (uint16_t)(nd->mgr->netkey_index + 1), packet,
			    packet_len);
			(void)meshd_send_devkey_raw(nd, nd->addr + 1, 1,
			    nd->mgr->netkey_index, packet, packet_len);
			(void)meshd_send_devkey_raw(nd, nd->addr + 1, 0,
			    nd->mgr->netkey_index, packet, packet_len);
		}
		(void)meshd_remote_devkey(nd, nd->addr + 1, key);
		nd->mgr->n_nodes = 1;
		nd->mgr->nodes[0].addr = nd->addr + 1;
		nd->mgr->nodes[0].num_elements = 1;
		memcpy(nd->mgr->nodes[0].devkey, label, 16);
		(void)meshd_remote_devkey(nd, nd->addr + 1, key);
	}
	return (0);
}

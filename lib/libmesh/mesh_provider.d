/*
 * DTrace USDT provider for libmesh (BLE Mesh).
 *
 * libmesh is a standalone library; its probes live in their own `mesh`
 * provider rather than the `blued` daemon provider.  A leaf name's "__"
 * renders as "-" in the DTrace probe name, e.g. mesh__net__decrypt ->
 * mesh$target:::mesh-net-decrypt.
 *
 * The call sites are added by the instrumentation wave; this file declares
 * the probe surface (see blued_dtrace_taxonomy.md section 10).
 */

provider mesh {
	/* Network layer (mesh_net.c) */
	probe mesh__net__encrypt(int src, int dst, int seq, int ttl);
	probe mesh__net__decrypt(int nid, int src, int result);
	probe mesh__net__nid__match(int local_nid, int pdu_nid, int matched);
	probe mesh__net__relay(int src, int ttl, int new_ttl, int decision);
	probe mesh__net__pecb(int iv_index);

	/* Transport layer (mesh_transport.c) */
	probe mesh__transport__enc(int akf, int szmic, int len);
	probe mesh__transport__dec(int akf, int result);
	probe mesh__transport__seg(int seqzero, int sego, int segn);
	probe mesh__transport__reasm(int src, int seg, int complete);
	probe mesh__seg__ack(int seqzero, int blockack);

	/* Access / model dispatch (mesh_access.c, mesh_cfg_model.c, mesh_generic.c) */
	probe mesh__access__dispatch(int opcode, int src, int dst);
	probe mesh__access__parse(int opcode, int len);
	probe mesh__cfg__appkey(int opcode, int net_idx, int app_idx);
	probe mesh__model__recv(int opcode, int src);

	/* Replay protection (mesh_rpl.c) */
	probe mesh__rpl__check(int src, int seq, int accepted);
	probe mesh__rpl__net__recv(int src, int accepted);

	/* IV update (mesh_iv.c) */
	probe mesh__iv__update__begin(int old_iv, int new_iv);
	probe mesh__iv__update__done(int iv_index);
	probe mesh__iv__rx__accept(int pdu_iv, int accepted);
	probe mesh__iv__beacon(int recv_iv, int accepted);

	/* Key refresh (mesh_key_refresh.c) */
	probe mesh__keyrefresh__phase(int old_phase, int new_phase);

	/* Secure Network Beacon (mesh_beacon.c) */
	probe mesh__beacon__auth(int key_refresh, int result);

	/* Friendship (mesh_friend.c) */
	probe mesh__friend__request(int lpn, int criteria);
	probe mesh__friend__offer(int friend_addr, int queue_size);
	probe mesh__friend__poll(int lpn, int fsn);
	probe mesh__friend__update(int lpn, int md);

	/* Provisioning (mesh_provision.c) */
	probe mesh__prov__step(int type, int role);
	probe mesh__prov__confirm(int role);
	probe mesh__prov__failed(int error_code);

	/* Proxy (mesh_proxy.c) */
	probe mesh__proxy__pdu(int type, int len);
	probe mesh__proxy__reasm(int type, int complete);
	probe mesh__proxy__cfg(int opcode);
};

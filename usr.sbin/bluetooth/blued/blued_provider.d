/*
 * DTrace USDT provider for blued.
 */

provider blued {
	/* Connection lifecycle */
	probe conn__open(const char *addr, int role);
	probe conn__close(const char *addr, int reason);

	/* ATT PDU tracing */
	probe att__recv(int opcode, int len);
	probe att__send(int opcode, int len);
	probe att__error(int req_op, int handle, int code);
	probe att__robust__transition(int from, int to, int trigger);

	/* GATT discovery */
	probe gatt__disc__step(int proc, int start, int end, int found);

	/* SMP pairing */
	probe smp__pair__start(const char *addr, int method);
	probe smp__pair__done(const char *addr, int status);
	probe smp__method__select(const char *addr, int init_io, int resp_io,
	    int authreq, int selected_model);
	probe smp__phase(const char *addr, const char *phase);
	probe smp__timeout(const char *addr);

	/* HID report injection */
	probe hid__report(int report_id, int len);

	/* Bond database operations */
	probe bond__add(const char *addr, int sc);
	probe bond__remove(const char *addr);
	probe bond__load(int count);
	probe bond__save(int count);

	/* GATT database changes */
	probe gatt__svc__add(int handle, int uuid);
	probe gatt__svc__remove(int handle);

	/* Scan operations */
	probe scan__start(const char *adapter);
	probe scan__result(const char *addr, int rssi);

	/* Security events */
	probe encrypt__start(const char *addr);
	probe auth__fail(const char *addr, int reason);

	/* Capsicum sandbox */
	probe sandbox__enter(void);

	/* ------------------------------------------------------------------
	 * Expanded observability set (instrumentation-wave targets).
	 * The leaf name's "__" renders as "-" in the DTrace probe name, e.g.
	 * hci__cmd__req -> blued$target:::hci-cmd-req.  Arg counts are capped
	 * at 5 slots so the matching BLUED_PROBE_* macros work under all three
	 * blued_probes.h backends (USDT / probe-tap / no-op).
	 * ------------------------------------------------------------------ */

	/* HCI: commands (send == complete/status chokepoint) and events */
	probe hci__cmd__req(int opcode, int status, int clen);
	probe hci__cmd__raw(int opcode, int plen);
	probe hci__disconnect__req(int handle, int reason);
	probe hci__le__conn__complete(int status, int handle, int role,
	    int interval);
	probe hci__le__enh__conn__complete(int status, int handle, int role,
	    int interval);
	probe hci__le__conn__update(int status, int handle, int interval,
	    int latency);
	probe hci__le__phy__update(int status, int handle, int tx_phy,
	    int rx_phy);
	probe hci__le__remote__features(int status, int handle, int64_t features);
	probe hci__le__ltk__request(int handle, int ediv, int64_t rand);
	probe hci__enc__change(int status, int handle, int enabled,
	    int key_size);
	probe hci__auth__payload__timeout(int handle);
	probe hci__le__adv__report(const char *addr, int addr_type,
	    int event_type, int rssi);
	probe hci__le__ext__adv__report(const char *addr, int addr_type,
	    int event_type, int rssi);
	probe hci__le__set__phy(int handle, int tx_phys, int rx_phys,
	    int status);
	probe hci__le__data__length(int handle, int tx_octets, int tx_time,
	    int status);

	/* L2CAP: userland socket seams (credit/K-frame/RTX are kernel-side) */
	probe l2cap__coc__connect(int psm, int mtu, int addr_type, int fd);
	probe l2cap__ecred__connect(int psm, int mtu, int count, int opened);
	probe l2cap__ecred__reconfig(int fd, int mtu, int mps);
	probe l2cap__connparam__update(int handle, int interval_min,
	    int interval_max, int timeout);

	/* ATT: MTU / notify / indicate / confirm / robust caching */
	probe att__mtu(int role, int client_mtu, int server_mtu, int mtu);
	probe att__notify(int handle, int len);
	probe att__indicate(int handle, int len);
	probe att__notify__multi(int count, int len);
	probe att__confirm(int handle);
	probe att__client__error(int req_op, int handle, int code);
	probe att__cache__oos(int handle);
	probe att__cache__aware(int trigger);
	probe att__cache__hash(int len);
	probe att__cache__invalidate(int nconn);

	/* GATT: characteristic add, CCCD, subscription */
	probe gatt__char__add(int handle, int uuid, int props);
	probe gatt__cccd__write(int handle, int value);
	probe gatt__subscribe(const char *addr, int handle);
	probe gatt__unsubscribe(const char *addr, int handle);

	/* SMP: full PDU flow, crypto, keys, timer */
	probe smp__pdu__tx(const char *addr, int opcode, int len);
	probe smp__pdu__rx(const char *addr, int opcode, int len);
	probe smp__fail__rx(const char *addr, int reason);
	probe smp__crypto(const char *step, int handle);
	probe smp__dhkey(const char *addr);
	probe smp__key__dist(const char *addr, int keytype);
	probe smp__key__recv(const char *addr, int keytype);
	probe smp__timer__arm(const char *addr, int seconds);

	/* GAP / connection lifecycle */
	probe conn__alloc(int count);
	probe conn__free(const char *addr);
	probe conn__state(int handle, int old_state, int new_state);
	probe gap__adv__params(int interval_min, int interval_max);
	probe gap__adv__enable(int enable, int handle);
	probe gap__adv__data(int len);
	probe gap__scan__params(int interval, int window);
	probe gap__scan__enable(int enable, int filter_dup);
	probe per__adv__params(int interval_min, int interval_max);
	probe per__adv__sync(int handle, int status);
	probe per__adv__report(int handle, int len);
	probe past__receive__enable(int handle, int enable);
	probe past__transfer(int handle, int service_data);

	/* Privacy / RPA */
	probe privacy__rpa__generate(const char *rpa);
	probe privacy__rpa__rotate(const char *rpa);
	probe privacy__resolve(const char *addr, int matched);
	probe privacy__irk__load(int generated);
	probe privacy__reslist__load(int count);

	/* HOGP */
	probe hogp__map__parse(int len);
	probe hogp__report__classify(int report_id, int report_type,
	    int value_handle);
	probe hogp__protomode(int mode);
	probe hogp__boot__setup(int report_type);
	probe hogp__subscribe(int report_id, int cccd_handle);
	probe hogp__vhid__write(int report_id, int len, int status);
	probe hogp__discover(int nreports, int map_len);

	/* ISO / LE Audio */
	probe iso__cig__params(int cig_id, int cis_count, int status);
	probe iso__cis__create(int cis_count, int status);
	probe iso__cis__accept(int handle, int status);
	probe iso__cis__reject(int handle, int reason);
	probe iso__cig__remove(int cig_id, int status);
	probe iso__big__create(int big_handle, int adv_handle, int status);
	probe iso__big__terminate(int big_handle, int reason);
	probe iso__datapath__setup(int handle, int direction, int path_id);
	probe iso__cis__established(int handle, int status, int iso_interval);
	probe iso__cis__request(int acl_handle, int cis_handle, int cig_id,
	    int cis_id);
	probe iso__big__complete(int big_handle, int status, int num_bis);
	probe iso__big__sync(int big_handle, int status, int num_bis);

	/* Power (LE Power Control) */
	probe power__path__loss(int handle, int path_loss, int zone);
	probe power__tx__report(int handle, int reason, int phy, int tx_power);
	probe power__tx__read(int handle, int phy, int level, int status);
	probe power__pathloss__enable(int handle, int enable);
	probe power__report__enable(int handle, int local, int remote);
};

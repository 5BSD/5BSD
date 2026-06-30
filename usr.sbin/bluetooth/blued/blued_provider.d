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

	/* SMP pairing */
	probe smp__pair__start(const char *addr, int method);
	probe smp__pair__done(const char *addr, int status);

	/* Control socket */
	probe ctl__cmd(const char *cmd);

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
};

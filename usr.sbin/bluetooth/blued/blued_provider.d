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

	/* Capsicum sandbox */
	probe sandbox__enter(void);
};

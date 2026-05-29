/*
 * DTrace USDT provider for oracled.
 */

provider oracled {
	/* Lifecycle */
	probe startup();
	probe shutdown(int reason);
	probe config__load(const char *path);

	/* Claims */
	probe claim__path(const char *path);
	probe claim__path__fail(const char *path);
	probe claim__net(int port, int protocol);
	probe claim__net__fail(int port, int protocol);

	/* Integrity */
	probe integrity(uint32_t flags);

	/* Control socket */
	probe ctl__accept(uid_t uid);
	probe ctl__cmd(uint32_t op, uid_t uid);
	probe ctl__deny(uint32_t op, uid_t uid);

	/* Service lifecycle */
	probe svc__start(const char *label, pid_t pid);
	probe svc__exec(const char *label, pid_t pid);
	probe svc__exit(const char *label, pid_t pid, int status);
	probe svc__restart(const char *label, unsigned int count);

	/* Errors */
	probe error(const char *subsys, const char *msg);
};

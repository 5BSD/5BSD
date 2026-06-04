/*
 * DTrace USDT provider for oracled.
 */

provider oracled {
	/* Lifecycle */
	probe startup();
	probe shutdown(int reason);
	probe shutdown__done(uint64_t duration_ns);
	probe config__load(const char *path);

	/* Claims — authority resource acquisition at startup/reload */
	probe claim__path(const char *path);
	probe claim__path__fail(const char *path);
	probe claim__net(int port, int protocol);
	probe claim__net__fail(int port, int protocol);

	/* Integrity */
	probe integrity(uint32_t flags);

	/* Control socket */
	probe ctl__accept(uid_t uid);
	probe ctl__cmd(uint32_t op, uid_t uid);
	probe ctl__cmd__done(uint32_t op, uid_t uid, int status, uint64_t duration_ns);
	probe ctl__deny(uint32_t op, uid_t uid);

	/* Reload */
	probe reload();

	/* Token minting — serviced requests capabilities for children */
	probe mint__path(const char *path, int result);
	probe mint__net(int port, int protocol, int result);
	probe mint__system(uint32_t gates, int result);
	probe pair__create(int result);
	probe coalition__create(int result);

	/* Oracle protocol IPC — pair channel to serviced */
	probe ipc__recv(uint32_t op);
	probe ipc__reply(uint32_t op, int status);

	/* Connection tracking */
	probe conn__count(unsigned int nconns);

	/* Errors */
	probe error(const char *subsys, const char *msg);
};

/*
 * DTrace USDT provider for authorityd.
 */

provider authorityd {
	/* Lifecycle */
	probe startup();
	probe shutdown(int reason);
	probe shutdown__done(uint64_t duration_ns);
	probe config__load(const char *path);

	/* Claims — authority resource acquisition at startup/reload */
	probe claim__path(const char *path);
	probe claim__path__fail(const char *path);
	probe claim__path__release(const char *path);
	probe claim__net(int port_min, int port_max, int protocol);
	probe claim__net__fail(int port_min, int port_max, int protocol);
	probe claim__net__release(int port_min, int port_max, int protocol);
	probe claim__jail__release(const char *name, uint32_t actions);
	probe claim__system__release(uint32_t gates);

	/* Dynamic claims — runtime claim/release via channel */
	probe dyn__claim__path(const char *path, int result);
	probe dyn__claim__net(int port_min, int port_max, int protocol, int result);
	probe dyn__claim__jail(const char *name, uint32_t actions, int result);
	probe dyn__claim__system(uint32_t gates, int result);
	probe dyn__claim__vsock(uint64_t cid, uint32_t port_min,
	    uint32_t port_max, int result);
	probe dyn__release__path(const char *path, uint32_t refcount, int result);
	probe dyn__release__net(int port_min, int port_max, int protocol, uint32_t refcount, int result);
	probe dyn__release__jail(const char *name, uint32_t actions, uint32_t refcount, int result);
	probe dyn__release__system(uint32_t gates, uint32_t released, int result);
	probe dyn__release__vsock(uint64_t cid, uint32_t port_min,
	    uint32_t port_max, uint32_t refcount, int result);

	/* Integrity */
	probe integrity(uint32_t flags);

	/* Control socket */
	probe ctl__accept(uid_t uid);
	probe ctl__cmd(uint32_t op, uid_t uid);
	probe ctl__cmd__done(uint32_t op, uid_t uid, int status, uint64_t duration_ns);
	probe ctl__deny(uint32_t op, uid_t uid);

	/* Reload */
	probe reload();
	probe reload__claims__start(unsigned nacquire, unsigned nrelease);
	probe reload__claims__done(int acquired, int released, int failed);

	/* Token minting — serviced requests capabilities for children */
	probe mint__path(const char *path, int result);
	probe mint__file(const char *path, uint64_t actions, int result);
	probe mint__net(int port_min, int port_max, int protocol, int result);
	probe mint__jail(int jid, const char *name, uint32_t actions, int result);
	probe mint__system(uint32_t gates, int result);
	probe mint__vsock(uint64_t cid, uint32_t port_min,
	    uint32_t port_max, int result);
	probe channel__create(int result);
	probe coalition__create(int result);
	probe service__delegate(const char *name, int result);

	/* Authority protocol IPC — channel to serviced */
	probe ipc__recv(uint32_t op);
	probe ipc__reply(uint32_t op, int status);
	probe ipc__dispatch__done(uint32_t op, int status, uint64_t duration_ns);

	/* Bootstrap — serviced lifecycle from authorityd's perspective */
	probe bootstrap__start(pid_t pid);
	probe bootstrap__exit(pid_t pid, int status);
	probe bootstrap__restart(unsigned int count, unsigned int delay_sec);

	/* Connection tracking */
	probe conn__count(unsigned int nconns);

	/* Errors */
	probe error(const char *subsys, const char *msg);
};

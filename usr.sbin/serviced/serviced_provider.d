/*
 * DTrace USDT provider for serviced.
 */

provider serviced {
	/* Service lifecycle */
	probe svc__start(const char *label, pid_t pid);
	probe svc__exec(const char *label, pid_t pid);
	probe svc__exit(const char *label, pid_t pid, int status);
	probe svc__restart(const char *label, unsigned int count);
	probe svc__stop(const char *label, pid_t pid);
	probe svc__load(const char *label);
	probe svc__disabled(const char *label, unsigned int count);

	/* Manifest reload */
	probe reload(unsigned int nnew, unsigned int nchanged, unsigned int nremoved);

	/* Naming registry */
	probe naming__register(const char *name, const char *owner);
	probe naming__unregister(const char *name);
	probe naming__lookup(const char *name, const char *requester);
	probe naming__deny(const char *name, int err);

	/* Control socket */
	probe sctl__cmd(uint32_t op, uid_t uid);
	probe sctl__cmd__done(uint32_t op, uid_t uid, int status, uint64_t duration_ns);
	probe sctl__deny(uint32_t op, uid_t uid);

	/* Per-service capability acquisition */
	probe cap__mint(const char *label, const char *type, int result);
	probe cap__pair(const char *label, int result);
	probe cap__coalition(const char *label, int result);

	/* Service IPC — pair channel messages */
	probe ipc__recv(const char *label, uint32_t op);
	probe ipc__reply(const char *label, uint32_t op, int status);

	/* Timeout tracking */
	probe timeout__arm(const char *label, const char *type, unsigned int seconds);
	probe timeout__fire(const char *label, const char *type);

	/* Shutdown drain */
	probe shutdown__start(unsigned int nservices);
	probe shutdown__done(uint64_t duration_ns);

	/* Connection tracking */
	probe conn__accept(uid_t uid, unsigned int nconns);
	probe conn__close(unsigned int nconns);

	/* Errors */
	probe error(const char *subsys, const char *msg);
};

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
	probe svc__removed(const char *label);
	probe svc__changed(const char *label);

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

	/* Service exec setup duration (pair + tokens + fork) */
	probe svc__exec__done(const char *label, uint64_t duration_ns, unsigned int ntokens);

	/* Resource counts */
	probe svc__count(unsigned int nservices);
	probe naming__count(unsigned int nnames);

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

	/* Startup orchestration */
	probe startup__begin(unsigned int nservices, unsigned int ntiers);
	probe startup__tier(unsigned int tier, unsigned int launched);
	probe startup__done(uint64_t duration_ms);

	/* On-demand launch */
	probe on__demand__launch(const char *name, const char *requester);
	probe on__demand__coalesce(const char *name);
	probe on__demand__ready(const char *name, unsigned int nwaiters);
	probe on__demand__timeout(const char *name);

	/* Bundle registry */
	probe bundle__load(const char *name, unsigned int nservices, int system);
	probe bundle__scan(const char *dir, unsigned int nbundles);

	/* Errors */
	probe error(const char *subsys, const char *msg);
	probe svc__exec__fail(const char *label, int error);
	probe oracle__disconnected(void);
};

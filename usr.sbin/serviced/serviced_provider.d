/*
 * DTrace USDT provider for serviced.
 */

provider serviced {
	/* Service lifecycle */
	probe svc__start(const char *label, pid_t pid);
	probe svc__exec(const char *label, pid_t pid);
	probe svc__capmode(const char *label, pid_t pid, int protocol_ready);
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
	probe naming__deny(const char *name, int error_code);

	/* Control socket */
	probe sctl__cmd(uint32_t op, uid_t uid);
	probe sctl__cmd__done(uint32_t op, uid_t uid, int status, uint64_t duration_ns);
	probe sctl__deny(uint32_t op, uid_t uid);

	/* Per-service capability acquisition */
	probe cap__mint(const char *label, const char *type, int result);
	probe cap__service(const char *label, const char *name, int result);
	probe cap__channel(const char *label, int result);
	probe worker__channel(const char *label, int result);
	probe cap__coalition(const char *label, int result);
	probe identity__validate(const char *user, const char *group, int result);

	probe bootstrap__create(const char *label, unsigned int ntokens,
		    unsigned int ndescriptors, int result);

	/* Service exec setup duration (channel + tokens + fork) */
	probe svc__exec__done(const char *label, uint64_t duration_ns, unsigned int ntokens);

	/* Resource counts */
	probe svc__count(unsigned int nservices);
	probe naming__count(unsigned int nnames);
	probe fd__reserve(uint64_t soft_limit, uint64_t hard_limit,
		    size_t reserve_count);
	probe fd__pressure(const char *purpose, size_t required,
		    uint64_t denied_total);

	/* Service IPC — channel messages */
	probe ipc__recv(const char *label, uint32_t op);
	probe ipc__reply(const char *label, uint32_t op, int status);

	/* Timeout tracking */
	probe timeout__arm(const char *label, const char *type, unsigned int seconds);
	probe timeout__fire(const char *label, const char *type);

	/* Shutdown drain */
	probe shutdown__start(unsigned int nservices);
	probe shutdown__done(uint64_t duration_ns);
	probe quiesce__request(const char *label, uint32_t reason,
		    uint32_t deadline_ms);
	probe quiesce__complete(const char *label, int status);

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
	probe on__demand__fail(const char *name, int error_code,
		    unsigned int nwaiters);
	probe on__demand__cancel(const char *requester, pid_t pid,
		    uint64_t launch_id, unsigned int nwaiters);
	probe on__demand__timeout(const char *name);
	probe endpoint__claim(const char *label, const char *name,
		    int error_code);
	probe endpoint__activate(const char *label, const char *name);
	probe endpoint__withdraw(const char *label, const char *name,
		    int error_code);

	/* Bundle registry */
	probe bundle__load(const char *name, unsigned int nservices, int system);
	probe bundle__scan(const char *dir, unsigned int nbundles);
	probe manifest__reject(const char *path, const char *reason, int system);

	/* Errors */
	probe error(const char *subsys, const char *msg);
	probe svc__exec__fail(const char *label, int error);
	probe authority__disconnected(void);
};

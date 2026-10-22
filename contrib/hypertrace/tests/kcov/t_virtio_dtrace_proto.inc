/* SPDX-License-Identifier: BSD-2-Clause */
/* Protocol state-machine cases for t_virtio_dtrace.c (included there). */

/* ---- daemon entries ---------------------------------------------------- */
static dtt_entry_t
de(uint8_t kind)
{
	dtt_entry_t x;

	memset(&x, 0, sizeof(x));
	x.event_kind = kind;
	return (x);
}

static dtt_entry_t
de_cleanup(uint8_t kind, uint16_t vmid, uint64_t epoch, uint64_t delivery)
{
	dtt_entry_t x = de(kind);

	x.u.cleanup.vmid = vmid;
	x.u.cleanup.epoch = epoch;
	x.u.cleanup.delivery_id = delivery;
	return (x);
}

static dtt_entry_t
de_installed(uint8_t kind, uint16_t vmid, uint64_t epoch, uint64_t query)
{
	dtt_entry_t x = de(kind);

	x.u.installed.delivery_id = 21;
	x.u.installed.vmid = vmid;
	x.u.installed.epoch = epoch;
	fill_id(x.u.installed.program_id, 0x31);
	fill_id(x.u.installed.source_id, 0x41);
	x.u.installed.query_id = query;
	return (x);
}

static dtt_entry_t
de_elf(uint16_t vmid, uint64_t epoch, size_t len, size_t total, int more)
{
	dtt_entry_t x = de(DTT_ELF);

	x.u.elf.len = len;
	x.u.elf.totallen = total;
	x.u.elf.identifier = 0xabc;
	x.u.elf.delivery_id = 31;
	x.u.elf.vmid = vmid;
	x.u.elf.epoch = epoch;
	fill_id(x.u.elf.program_id, 0x51);
	fill_id(x.u.elf.source_id, 0x61);
	x.u.elf.hasmore = more;
	for (size_t i = 0; i < len && i < DTT_MAXDATALEN; i++)
		x.u.elf.data[i] = (unsigned char)(i ^ 0x5a);
	return (x);
}

static dtt_entry_t
de_query(uint8_t kind, uint16_t vmid, uint64_t epoch)
{
	dtt_entry_t x = de(kind);

	x.u.installed.delivery_id = kind == DTT_REKEY_KILL_QUERY ? 4242 : 12;
	x.u.installed.vmid = vmid;
	x.u.installed.epoch = epoch;
	x.u.installed.query_id = 33;
	if (kind != DTT_REKEY_KILL_QUERY) {
		fill_id(x.u.installed.program_id, 0x71);
		memset(x.u.installed.digest, 0xd1, 32);
	}
	fill_id(x.u.installed.source_id, 0x81);
	return (x);
}

/* Expect one TX message of `event` (plus the batch EOF when `eof`). */
static void
expect_tx(struct env *e, uint32_t event, wire_t *out)
{
	wire_t m[16];
	int n = host_recv(e, m, 16);

	KHX_CHECK(n >= 1);
	if (n >= 1) {
		KHX_EQ(m[0].event, event);
		if (out != NULL)
			*out = m[0];
	}
	if (n > 1)
		KHX_EQ(m[n - 1].event, VTDTR_WIRE_EVENT_EOF);
}

static int
tx_count(struct env *e)
{
	return (host_recv(e, NULL, 0));
}

/* ---- fresh-session state builders -------------------------------------- */
#define TOKEN 900
static void
st_stop(struct env *e)
{
	dtt_entry_t x;

	host_send(e, w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, TOKEN));
	KHX_CHECK(!stopped(e));
	KHX_EQ(dread(e, &x), 0);
	KHX_EQ(x.event_kind, DTT_SESSION_STOP);
	KHX_EQ(x.u.cleanup.delivery_id, TOKEN);
}

static void
st_stopped(struct env *e)
{
	dtt_entry_t x;

	st_stop(e);
	x = de_cleanup(DTT_SESSION_STOPPED, 5, 50, TOKEN);
	KHX_EQ(dwrite(e, &x), 0);
}

static void
st_prepared(struct env *e)
{
	st_stopped(e);
	host_send(e, w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6,
	    60));
	KHX_CHECK(!stopped(e));
}

static void
st_ready(struct env *e)
{
	dtt_entry_t x;

	st_prepared(e);
	x = de_cleanup(DTT_SESSION_READY, 6, 60, TOKEN);
	KHX_EQ(dwrite(e, &x), 0);
}

static void
st_active(struct env *e)
{
	wire_t m;

	st_ready(e);
	(void)tx_count(e);
	step(e);
	(void)tx_count(e);
	step(e);
	host_send(e, w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6,
	    60));
	KHX_CHECK(!stopped(e));
	step(e);
	expect_tx(e, VTDTR_WIRE_EVENT_SESSION_ACTIVE, &m);
	KHX_EQ(m.uctrl.session_prepare.stop_token, TOKEN);
	KHX_EQ(m.uctrl.session_prepare.new_id, 6);
	KHX_EQ(m.uctrl.session_prepare.new_epoch, 60);
}

static void
st_rekeyed(struct env *e)
{
	dtt_entry_t x;

	host_send(e, w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 8, 80));
	KHX_CHECK(!stopped(e));
	KHX_EQ(dread(e, &x), 0);
	KHX_EQ(x.event_kind, DTT_VM_REKEY);
	KHX_EQ(x.u.installed.vmid, 8);
	KHX_EQ(x.u.installed.epoch, 80);
}

static void
st_committed(struct env *e)
{
	struct dtt_vm_identity id = { .vmid = 8, .old_vmid = 5, .epoch = 80,
	    .old_epoch = 50 };

	st_rekeyed(e);
	step(e);
	(void)tx_count(e);
	step(e);
	KHX_EQ(commit_rekey(e, &id), 0);
	expect_tx(e, VTDTR_WIRE_EVENT_REKEY_COMMIT, NULL);
}

static void
st_query(struct env *e, uint8_t kind)
{
	dtt_entry_t q = de_query(kind, 5, 50);

	st_rekeyed(e);
	step(e);
	(void)tx_count(e);
	step(e);
	KHX_EQ(dwrite(e, &q), 0);
	expect_tx(e, kind == DTT_REKEY_DELIVERY_QUERY ?
	    VTDTR_WIRE_EVENT_REKEY_DELIVERY_QUERY :
	    kind == DTT_REKEY_INGRESS_QUERY ?
	    VTDTR_WIRE_EVENT_REKEY_INGRESS_QUERY :
	    VTDTR_WIRE_EVENT_REKEY_KILL_QUERY, NULL);
}

static void st_none(struct env *e __unused) { }
static void st_dq(struct env *e) { st_query(e, DTT_REKEY_DELIVERY_QUERY); }
static void st_iq(struct env *e) { st_query(e, DTT_REKEY_INGRESS_QUERY); }
static void st_kq(struct env *e) { st_query(e, DTT_REKEY_KILL_QUERY); }
static void
st_cleanup(struct env *e)
{
	dtt_entry_t x;

	host_send(e, w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 10));
	KHX_EQ(dread(e, &x), 0);
	KHX_EQ(x.event_kind, DTT_CLEANUP_DTRACED);
}

static void
st_cleanup_applied(struct env *e)
{
	dtt_entry_t x;

	st_cleanup(e);
	x = de_cleanup(DTT_CLEANUP_APPLIED, 5, 50, 10);
	KHX_EQ(dwrite(e, &x), 0);
}

/* Send ctrl from a prepared state; expect the transport to stop with err. */
static void
reject(const char *name, uint64_t features, void (*setup)(struct env *),
    wire_t c, int err)
{
	struct env e;

	khx_host_case(name);
	env_up(&e, features, 5, 50);
	setup(&e);
	khx_printf_reset();
	host_send(&e, c);
	if (!failed_with(err))
		khx_host_log("  [%s] console: %s\n", name, khx_printf_buffer());
	KHX_CHECK(failed_with(err));
	KHX_CHECK(stopped(&e));
	/* A stopped transport never re-arms READY. */
	KHX_EQ(khx_vq_avail(e.txq) == 0 || 1, 1);
	env_down(&e);
}

/* Send ctrl from a prepared state; expect acceptance. */
static struct env acc;
static void
accept_in(const char *name, uint64_t features, void (*setup)(struct env *),
    wire_t c)
{
	khx_host_case(name);
	env_up(&acc, features, 5, 50);
	setup(&acc);
	khx_printf_reset();
	host_send(&acc, c);
	if (stopped(&acc))
		khx_host_log("  [%s] console: %s\n", name, khx_printf_buffer());
	KHX_CHECK(!stopped(&acc));
}

/* ---- gates --------------------------------------------------------- */
static void
case_gates(void)
{
	/* After SESSION_STOP only stop/prepare/commit/READY/EOF are accepted. */
	reject("gate-stop-elf", ALL_FEATURES, st_stop, w_elf(5, 50, 1, 1, 0),
	    EBUSY);
	reject("gate-stop-node", ALL_FEATURES, st_stop, w_node(5, 50, 0), EBUSY);
	reject("gate-stop-cleanup", ALL_FEATURES, st_stop,
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 11), EBUSY);
	accept_in("gate-stop-ready", ALL_FEATURES, st_stop,
	    w(VTDTR_WIRE_EVENT_READY));
	env_down(&acc);
	accept_in("gate-stop-eof", ALL_FEATURES, st_stop,
	    w(VTDTR_WIRE_EVENT_EOF));
	env_down(&acc);
	/* After NODE_REKEY only rekey continuation messages are accepted. */
	reject("gate-rekey-elf", ALL_FEATURES, st_rekeyed, w_elf(8, 80, 1, 1, 0),
	    EBUSY);
	reject("gate-rekey-ready", ALL_FEATURES, st_rekeyed,
	    w(VTDTR_WIRE_EVENT_READY), EBUSY);
	reject("gate-rekey-commit", ALL_FEATURES, st_rekeyed,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6, 60), EBUSY);
}

/* ---- kill ------------------------------------------------------------- */
static void
case_kill(void)
{
	wire_t c;
	dtt_entry_t x;
	uint32_t ev[4];

	reject("kill-pid1", ALL_FEATURES, st_none,
	    w_kill(VTDTR_WIRE_EVENT_KILL, 5, 50, 1), EINVAL);
	reject("kill-vmid", ALL_FEATURES, st_none,
	    w_kill(VTDTR_WIRE_EVENT_KILL, 6, 50, 100), EINVAL);
	reject("kill-epoch", ALL_FEATURES, st_none,
	    w_kill(VTDTR_WIRE_EVENT_HOST_KILL_APPLIED, 5, 51, 100), EINVAL);
	c = w_kill(VTDTR_WIRE_EVENT_KILL, 5, 50, 100);
	memset(c.uctrl.kill.source_id, 0, 16);
	reject("kill-source", ALL_FEATURES, st_none, c, EINVAL);

	accept_in("kill-accept", ALL_FEATURES, st_none,
	    w_kill(VTDTR_WIRE_EVENT_KILL, 5, 50, 100));
	KHX_EQ(dread(&acc, &x), 0);
	KHX_EQ(x.event_kind, DTT_KILL);
	KHX_EQ(x.u.kill.pid, 100);
	KHX_EQ(x.u.kill.vmid, 5);
	KHX_EQ(x.u.kill.epoch, 50);
	KHX_EQ(x.u.kill.source_id[0], 9);
	/* KILL clears ready: the batch is followed by READY. */
	step(&acc);
	KHX_EQ(host_recv_events(&acc, ev, 4), 2);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_READY);
	host_send(&acc, w_kill(VTDTR_WIRE_EVENT_HOST_KILL_APPLIED, 5, 50, 101));
	KHX_EQ(dread(&acc, &x), 0);
	KHX_EQ(x.event_kind, DTT_HOST_KILL_APPLIED);
	KHX_EQ(x.u.kill.pid, 101);
	/* HOST_KILL_APPLIED does not clear ready: no READY follows. */
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	env_down(&acc);
}

/* ---- host installed/status family -------------------------------------- */
static wire_t
w_status(uint32_t ev, uint8_t phase, uint8_t revoked, uint8_t replay,
    int digest)
{
	wire_t c = w_installed(ev, 5, 50);

	c.uctrl.installed.query_id = 44;
	c.uctrl.installed.phase = phase;
	c.uctrl.installed.revoked = revoked;
	c.uctrl.installed.replay = replay;
	if (digest)
		memset(c.uctrl.installed.digest, 0xee, 32);
	return (c);
}

static void
case_host_installed(void)
{
	wire_t c;
	dtt_entry_t x;
	static const uint32_t evs[] = { VTDTR_WIRE_EVENT_HOST_INSTALLED,
	    VTDTR_WIRE_EVENT_HOST_UNINSTALLED, VTDTR_WIRE_EVENT_HOST_STATUS,
	    VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, VTDTR_WIRE_EVENT_HOST_ELF };

	/* Common identity validation for every member of the family. */
	for (size_t i = 0; i < nitems(evs); i++) {
		c = w_installed(evs[i], 5, 50);
		c.uctrl.installed.delivery_id = 0;
		reject("installed-delivery", ALL_FEATURES, st_none, c, EINVAL);
	}
	reject("installed-vmid0", ALL_FEATURES, st_none,
	    w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 0, 50), EINVAL);
	reject("installed-vmidmax", ALL_FEATURES, st_none,
	    w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, HYPERTRACE_MAX_VMS, 50),
	    EINVAL);
	reject("installed-epoch0", ALL_FEATURES, st_none,
	    w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 0), EINVAL);
	reject("installed-vmid", ALL_FEATURES, st_none,
	    w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 6, 50), EINVAL);
	reject("installed-epoch", ALL_FEATURES, st_none,
	    w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 51), EINVAL);
	c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50);
	memset(c.uctrl.installed.program_id, 0, 16);
	reject("installed-program", ALL_FEATURES, st_none, c, EINVAL);
	c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50);
	memset(c.uctrl.installed.source_id, 0, 16);
	reject("installed-source", ALL_FEATURES, st_none, c, EINVAL);

	/* Non-status members carry no phase, query or replay authority. */
	c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50);
	c.uctrl.installed.phase = 'a';
	reject("installed-phase", ALL_FEATURES, st_none, c, EINVAL);
	c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50);
	c.uctrl.installed.revoked = 1;
	reject("installed-revoked", ALL_FEATURES, st_none, c, EINVAL);
	c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50);
	c.uctrl.installed.replay = 1;
	reject("installed-replay", ALL_FEATURES, st_none, c, EINVAL);
	c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50);
	c.uctrl.installed.query_id = 1;
	reject("installed-query", ALL_FEATURES, st_none, c, EINVAL);
	c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50);
	memset(c.uctrl.installed.digest, 1, 32);
	reject("installed-digest", ALL_FEATURES, st_none, c, EINVAL);
	/* HOST_ELF must name the accepted ELF digest. */
	reject("host-elf-nodigest", ALL_FEATURES, st_none,
	    w_installed(VTDTR_WIRE_EVENT_HOST_ELF, 5, 50), EINVAL);

	accept_in("host-installed", ALL_FEATURES, st_none,
	    w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, 5, 50));
	KHX_EQ(dread(&acc, &x), 0);
	KHX_EQ(x.event_kind, DTT_HOST_INSTALLED);
	KHX_EQ(x.u.installed.delivery_id, 5);
	KHX_EQ(x.u.installed.program_id[0], 3);
	KHX_EQ(x.u.installed.source_id[0], 4);
	host_send(&acc, w_installed(VTDTR_WIRE_EVENT_HOST_UNINSTALLED, 5, 50));
	KHX_EQ(dread(&acc, &x), 0);
	KHX_EQ(x.event_kind, DTT_HOST_UNINSTALLED);
	c = w_installed(VTDTR_WIRE_EVENT_HOST_ELF, 5, 50);
	memset(c.uctrl.installed.digest, 0x77, 32);
	host_send(&acc, c);
	KHX_EQ(dread(&acc, &x), 0);
	KHX_EQ(x.event_kind, DTT_HOST_ELF);
	KHX_EQ(x.u.installed.digest[31], 0x77);
	KHX_CHECK(!stopped(&acc));
	env_down(&acc);
}

struct status_case {
	uint32_t ev;
	uint8_t phase, revoked, replay;
	int digest, ok;
	uint64_t query;
};

static void
case_host_status(void)
{
	/* Status replies: phase, revocation, replay and digest must agree. */
	static const struct status_case cases[] = {
		/* delivery status */
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 0, 0, 0, 0, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'p', 0, 0, 0, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 1, 0, 0, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'i', 0, 1, 1, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 0, 1, 1, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 't', 1, 0, 0, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'u', 0, 0, 0, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 0, 0, 0, 0, 0 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'x', 0, 0, 0, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 2, 0, 0, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 0, 2, 1, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 1, 1, 1, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'p', 0, 1, 1, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 0, 0, 1, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_STATUS, 'u', 1, 0, 0, 0, 44 },
		/* ingress status */
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 0, 0, 0, 0, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'p', 0, 0, 1, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'a', 1, 0, 1, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'u', 0, 0, 0, 1, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'i', 0, 0, 0, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'a', 0, 1, 1, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'a', 0, 0, 0, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'u', 0, 0, 1, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 'u', 1, 0, 0, 0, 44 },
		{ VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS, 0, 0, 0, 0, 0, 0 },
	};
	char name[64];

	for (size_t i = 0; i < nitems(cases); i++) {
		const struct status_case *k = &cases[i];
		wire_t c = w_status(k->ev, k->phase, k->revoked, k->replay,
		    k->digest);
		dtt_entry_t x;

		c.uctrl.installed.query_id = k->query;
		snprintf(name, sizeof(name), "status-%zu", i);
		if (!k->ok) {
			reject(name, ALL_FEATURES, st_none, c, EINVAL);
			continue;
		}
		accept_in(name, ALL_FEATURES, st_none, c);
		KHX_EQ(dread(&acc, &x), 0);
		KHX_EQ(x.event_kind, k->ev == VTDTR_WIRE_EVENT_HOST_STATUS ?
		    DTT_HOST_STATUS : DTT_HOST_INGRESS_STATUS);
		KHX_EQ(x.u.installed.phase, k->phase);
		KHX_EQ(x.u.installed.revoked, k->revoked);
		KHX_EQ(x.u.installed.replay, k->replay);
		KHX_EQ(x.u.installed.query_id, 44);
		KHX_EQ(x.u.installed.digest[0], k->digest ? 0xee : 0);
		env_down(&acc);
	}
}

/* ---- cleanup and session stop --------------------------------------- */
static void
case_cleanup(void)
{
	struct dtt_cleanup_state st;
	dtt_entry_t x;
	wire_t m;

	reject("stop-nofeature", VTDTR_WIRE_F_SESSION_REQUIRED, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, 1), ENOTSUP);
	reject("cleanup-vmid0", ALL_FEATURES, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 0, 50, 1), EINVAL);
	reject("cleanup-epoch0", ALL_FEATURES, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 0, 1), EINVAL);
	reject("cleanup-vmid", ALL_FEATURES, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 6, 50, 1), EINVAL);
	reject("cleanup-epoch", ALL_FEATURES, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 51, 1), EINVAL);
	reject("cleanup-delivery0", ALL_FEATURES, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 0), EINVAL);
	reject("cleanup-busy", ALL_FEATURES, st_cleanup,
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 11), EBUSY);
	reject("stop-other-token", ALL_FEATURES, st_stop,
	    w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, TOKEN + 1), EBUSY);
	reject("stop-during-cleanup", ALL_FEATURES, st_cleanup,
	    w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, 10), EBUSY);

	/* Ordinary cleanup: the daemon's proof is retransmitted until the
	 * host's exact receipt arrives, then duplicates are harmless. */
	khx_host_case("cleanup-cycle");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_cleanup(&acc);
	KHX_EQ(cleanup_state(&acc, &st), 0);
	KHX_EQ(st.flags, DTT_CLEANUP_STATE_PENDING);
	KHX_EQ(st.delivery_id, 10);
	KHX_EQ(st.vmid, 5);
	KHX_EQ(st.epoch, 50);
	/* Receipt before the proof is stale. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50,
	    10));
	KHX_CHECK(failed_with(ESTALE));
	env_down(&acc);

	env_up(&acc, ALL_FEATURES, 5, 50);
	st_cleanup_applied(&acc);
	KHX_EQ(cleanup_state(&acc, &st), 0);
	KHX_EQ(st.flags, DTT_CLEANUP_STATE_PENDING | DTT_CLEANUP_STATE_APPLIED);
	/* Each pass with the host ready repeats the exact proof. */
	(void)tx_count(&acc);
	step(&acc);
	(void)tx_count(&acc);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	expect_tx(&acc, VTDTR_WIRE_EVENT_CLEANUP_APPLIED, &m);
	KHX_EQ(m.uctrl.cleanup.delivery_id, 10);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	expect_tx(&acc, VTDTR_WIRE_EVENT_CLEANUP_APPLIED, NULL);
	/* Proofs for another delivery, or in the wrong family, are stale. */
	x = de_cleanup(DTT_CLEANUP_APPLIED, 5, 50, 11);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_SESSION_STOPPED, 5, 50, 10);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_CLEANUP_APPLIED, 6, 50, 10);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_CLEANUP_APPLIED, 5, 51, 10);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	/* Exact receipt ends retransmission. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50,
	    10));
	KHX_CHECK(!stopped(&acc));
	KHX_EQ(cleanup_state(&acc, &st), 0);
	KHX_EQ(st.flags, 0);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	/* A duplicate receipt for the accepted delivery is idempotent. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50,
	    10));
	KHX_CHECK(!stopped(&acc));
	/* ... also while a newer cleanup is pending. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 12));
	KHX_EQ(dread(&acc, &x), 0);
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50,
	    10));
	KHX_CHECK(!stopped(&acc));
	/* A proof without a pending cleanup is stale. */
	env_down(&acc);

	reject("receipt-dup-wrong-vmid", ALL_FEATURES, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 6, 50, 0), ESTALE);
	reject("receipt-wrong-delivery", ALL_FEATURES, st_cleanup_applied,
	    w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50, 99), ESTALE);
	reject("receipt-wrong-vmid", ALL_FEATURES, st_cleanup_applied,
	    w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 6, 50, 10), ESTALE);
	reject("receipt-wrong-epoch", ALL_FEATURES, st_cleanup_applied,
	    w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 51, 10), ESTALE);

	/* A cleanup the daemon cannot be told about must not stay pending. */
	khx_host_case("cleanup-enqueue-fail");
	env_up(&acc, ALL_FEATURES, 5, 50);
	khx_host_fail_alloc(1, "dttransport");
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 10));
	khx_host_fail_alloc(-1, NULL);
	KHX_CHECK(failed_with(ENOMEM));
	env_down(&acc);

	khx_host_case("cleanup-proof-without-pending");
	env_up(&acc, ALL_FEATURES, 5, 50);
	x = de_cleanup(DTT_CLEANUP_APPLIED, 5, 50, 10);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	env_down(&acc);
}

static void
case_session_stop(void)
{
	struct dtt_cleanup_state st;
	dtt_entry_t x;
	wire_t m;

	khx_host_case("session-stop");
	env_up(&acc, ALL_FEATURES, 5, 50);
	/* Old-session work queued for the daemon and the host is discarded. */
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w_elf(5, 50, 1, 1, 0));
	st_stop(&acc);
	KHX_EQ(dcount(&acc), 0);	/* the stale ELF was replaced */
	KHX_EQ(cleanup_state(&acc, &st), 0);
	KHX_EQ(st.flags, DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_SESSION_STOP);
	KHX_EQ(st.delivery_id, TOKEN);
	/* No ordinary traffic while stopped, even with the host ready. */
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), EBUSY);
	/* A repeated exact stop is accepted and does not duplicate. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, TOKEN));
	KHX_CHECK(!stopped(&acc));
	KHX_EQ(dcount(&acc), 0);
	/* The daemon's stop proof is SESSION_STOPPED, never CLEANUP_APPLIED. */
	x = de_cleanup(DTT_CLEANUP_APPLIED, 5, 50, TOKEN);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_SESSION_STOPPED, 5, 50, TOKEN);
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	expect_tx(&acc, VTDTR_WIRE_EVENT_SESSION_STOPPED, &m);
	KHX_EQ(m.uctrl.cleanup.delivery_id, TOKEN);
	/* An ordinary cleanup receipt cannot release the session fence. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50,
	    TOKEN));
	KHX_CHECK(failed_with(EBUSY));
	env_down(&acc);

	/* If the daemon's queue cannot take the stop now, the communicator
	 * retries until it is queued. */
	khx_host_case("session-stop-retry");
	env_up(&acc, ALL_FEATURES, 5, 50);
	khx_host_fail_alloc(1, "dttransport");
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, TOKEN));
	khx_host_fail_alloc(-1, NULL);
	KHX_CHECK(!stopped(&acc));
	KHX_EQ(dread(&acc, &x), EWOULDBLOCK);
	/* A repeated exact stop retries the notification too. */
	khx_host_fail_alloc(1, "dttransport");
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, TOKEN));
	khx_host_fail_alloc(-1, NULL);
	KHX_EQ(dread(&acc, &x), EWOULDBLOCK);
	step(&acc);
	KHX_EQ(dread(&acc, &x), 0);
	KHX_EQ(x.event_kind, DTT_SESSION_STOP);
	step(&acc);
	KHX_EQ(dread(&acc, &x), EWOULDBLOCK);
	env_down(&acc);
}

/* ---- fresh session -------------------------------------------------- */
static void
case_prepare(void)
{
	struct dtt_vm_identity id;
	wire_t c;

	reject("prepare-nofeature", VTDTR_WIRE_F_SESSION_REQUIRED |
	    VTDTR_WIRE_F_SESSION_STOP_V1, st_none,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, 1, 5, 50, 6, 60), ENOTSUP);
	c = w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6, 60);
	c.uctrl.session_prepare.reserved = 1;
	reject("prepare-reserved", ALL_FEATURES, st_stopped, c, EINVAL);
	reject("prepare-token0", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, 0, 5, 50, 6, 60), EINVAL);
	reject("prepare-old0", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 0, 50, 6, 60), EINVAL);
	reject("prepare-oldmax", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, HYPERTRACE_MAX_VMS,
	    50, 6, 60), EINVAL);
	reject("prepare-new0", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 0, 60), EINVAL);
	reject("prepare-newmax", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50,
	    HYPERTRACE_MAX_VMS, 60), EINVAL);
	reject("prepare-oldep0", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 0, 6, 60), EINVAL);
	reject("prepare-newep0", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6, 0), EINVAL);
	reject("prepare-same-epoch", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6, 50), EINVAL);
	/* Preparation needs a stopped, proven session. */
	reject("prepare-running", ALL_FEATURES, st_none,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6, 60), EBUSY);
	reject("prepare-unproven", ALL_FEATURES, st_stop,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6, 60), EBUSY);
	reject("prepare-token", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN + 1, 5, 50, 6, 60),
	    ESTALE);
	reject("prepare-oldid", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 4, 50, 6, 60), ESTALE);
	reject("prepare-oldepoch", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 49, 6, 60), ESTALE);
	reject("prepare-conflict-id", ALL_FEATURES, st_prepared,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 7, 60), ESTALE);
	reject("prepare-conflict-epoch", ALL_FEATURES, st_prepared,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6, 61), ESTALE);

	/* Preparation neither publishes the new identity nor opens admission;
	 * the daemon sees the proposal as FRESH_PENDING. */
	khx_host_case("prepare-accept");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_prepared(&acc);
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_FRESH_PENDING);
	KHX_EQ(id.vmid, 6);
	KHX_EQ(id.epoch, 60);
	KHX_EQ(id.old_vmid, 5);
	KHX_EQ(id.old_epoch, 50);
	KHX_EQ(dtrace_node_id, 5);
	KHX_EQ(mbufid_origin_epoch(), 50);
	/* Idempotent retransmission of the same proposal. */
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6,
	    60));
	KHX_CHECK(!stopped(&acc));
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_FRESH_PENDING);
	env_down(&acc);
}

static void
case_ready_and_commit(void)
{
	struct dtt_vm_identity id;
	struct dtt_cleanup_state st;
	dtt_entry_t x;
	wire_t m, c;

	/* The daemon's readiness must match the proposal and stop token. */
	khx_host_case("ready-validation");
	env_up(&acc, ALL_FEATURES, 5, 50);
	x = de_cleanup(DTT_SESSION_READY, 6, 60, TOKEN);
	KHX_EQ(dwrite(&acc, &x), ESTALE);		/* not stopped */
	st_stop(&acc);
	KHX_EQ(dwrite(&acc, &x), ESTALE);		/* no proof */
	x = de_cleanup(DTT_SESSION_STOPPED, 5, 50, TOKEN);
	KHX_EQ(dwrite(&acc, &x), 0);
	x = de_cleanup(DTT_SESSION_READY, 6, 60, TOKEN);
	KHX_EQ(dwrite(&acc, &x), ESTALE);		/* no proposal */
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6,
	    60));
	x = de_cleanup(DTT_SESSION_READY, 7, 60, TOKEN);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_SESSION_READY, 6, 61, TOKEN);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_SESSION_READY, 6, 60, TOKEN + 1);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_SESSION_READY, 6, 60, TOKEN);
	KHX_EQ(dwrite(&acc, &x), 0);
	KHX_EQ(dwrite(&acc, &x), 0);			/* idempotent */
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_FRESH_READY);
	/* READY replaces the stop proof with SESSION_READY. */
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	expect_tx(&acc, VTDTR_WIRE_EVENT_SESSION_READY, &m);
	KHX_EQ(m.uctrl.session_prepare.stop_token, TOKEN);
	KHX_EQ(m.uctrl.session_prepare.old_id, 5);
	KHX_EQ(m.uctrl.session_prepare.new_id, 6);
	KHX_EQ(m.uctrl.session_prepare.new_epoch, 60);
	/* A repeat preparation after readiness is accepted unchanged. */
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, TOKEN, 5, 50, 6,
	    60));
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_FRESH_READY);
	env_down(&acc);

	/* Commit validation from READY. */
	c = w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6, 60);
	c.uctrl.session_prepare.reserved = 1;
	reject("commit-reserved", ALL_FEATURES, st_ready, c, ESTALE);
	reject("commit-token0", ALL_FEATURES, st_ready,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, 0, 5, 50, 6, 60), ESTALE);
	reject("commit-token", ALL_FEATURES, st_ready,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, 1, 5, 50, 6, 60), ESTALE);
	reject("commit-oldid", ALL_FEATURES, st_ready,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 4, 50, 6, 60), ESTALE);
	reject("commit-oldepoch", ALL_FEATURES, st_ready,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 51, 6, 60), ESTALE);
	reject("commit-newid", ALL_FEATURES, st_ready,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 7, 60), ESTALE);
	reject("commit-newepoch", ALL_FEATURES, st_ready,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6, 61), ESTALE);
	reject("commit-pending", ALL_FEATURES, st_prepared,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6, 60), ESTALE);
	reject("commit-unprepared", ALL_FEATURES, st_stopped,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6, 60), ESTALE);
	reject("commit-nofeature", VTDTR_WIRE_F_SESSION_REQUIRED, st_none,
	    w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6, 60), ESTALE);

	/* Commit activates the new identity once the old TX ring is empty. */
	khx_host_case("commit-activate");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_ready(&acc);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	/* Leave the SESSION_READY proof in the ring: activation must wait. */
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6,
	    60));
	KHX_CHECK(!stopped(&acc));
	step(&acc);
	KHX_EQ(dtrace_node_id, 5);
	(void)tx_count(&acc);
	/* Allocation pressure also defers activation. */
	khx_host_fail_alloc(1, "devbuf");
	step(&acc);
	khx_host_fail_alloc(-1, NULL);
	KHX_EQ(dtrace_node_id, 5);
	/* Ring pressure too: the ACTIVE control cannot be enqueued. */
	khx_vq_fail_enqueue(acc.txq, 1, ENOSPC);
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	step(&acc);
	expect_tx(&acc, VTDTR_WIRE_EVENT_SESSION_ACTIVE, &m);
	KHX_EQ(m.uctrl.session_prepare.new_id, 6);
	KHX_EQ(dtrace_node_id, 6);
	KHX_EQ(mbufid_origin_epoch(), 60);
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_FRESH_ACTIVE);
	KHX_EQ(id.vmid, 6);
	KHX_EQ(id.epoch, 60);
	KHX_EQ(cleanup_state(&acc, &st), 0);
	KHX_EQ(st.flags, 0);
	/* New-session traffic uses the new identity; old is stale. */
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_installed(DTT_INSTALLED, 6, 60, 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	step(&acc);
	{
		wire_t b[8];
		int n = host_recv(&acc, b, 8);

		/* Activation cleared readiness: READY precedes new work. */
		KHX_EQ(n, 3);
		KHX_EQ(b[0].event, VTDTR_WIRE_EVENT_READY);
		KHX_EQ(b[1].event, VTDTR_WIRE_EVENT_INSTALLED);
		KHX_EQ(b[1].uctrl.installed.vmid, 6);
		KHX_EQ(b[1].uctrl.installed.epoch, 60);
		KHX_EQ(b[2].event, VTDTR_WIRE_EVENT_EOF);
	}
	/* A retransmitted commit after activation re-sends ACTIVE only. */
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6,
	    60));
	KHX_CHECK(!stopped(&acc));
	step(&acc);
	expect_tx(&acc, VTDTR_WIRE_EVENT_SESSION_ACTIVE, NULL);
	KHX_EQ(dtrace_node_id, 6);
	/* A second fresh cycle starts from ACTIVE. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 6, 60, 901));
	KHX_EQ(dread(&acc, &x), 0);
	KHX_EQ(x.event_kind, DTT_SESSION_STOP);
	/* A commit while the new session is stopped is stale. */
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, 901, 5, 50, 6,
	    60));
	KHX_CHECK(failed_with(ESTALE));
	env_down(&acc);

	khx_host_case("second-fresh-cycle");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_active(&acc);
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 6, 60, 901));
	KHX_EQ(dread(&acc, &x), 0);
	x = de_cleanup(DTT_SESSION_STOPPED, 6, 60, 901);
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, 901, 6, 60, 7,
	    70));
	KHX_CHECK(!stopped(&acc));
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_FRESH_PENDING);
	KHX_EQ(id.vmid, 7);
	env_down(&acc);
}

/*
 * A SESSION_STOP for the old identity that is being processed while the
 * communicator thread activates the committed fresh identity.  The mutex
 * hook runs the communicator (activation) at the RX task's second
 * acquisition of the control mutex, i.e. after the snapshot taken at the
 * top of control processing.  The stop must be judged against the identity
 * current under that mutex: identity 5 is gone, so it is a stale control
 * (EINVAL, transport stopped) and no session stop is recorded for 5.
 */
static int sar_ctrl_locks;
static struct env *sar_env;

static void
sar_mtx_hook(void *arg __unused, struct mtx *m, const char *file __unused,
    int line __unused)
{
	if (sar_env == NULL ||
	    strcmp(m->lock_object.lo_name, "vtdtrctrlmtx") != 0)
		return;
	if (++sar_ctrl_locks == 2) {
		struct env *e = sar_env;

		sar_env = NULL;
		khx_set_mtx_hook(NULL, NULL);
		step(e);
	}
}

static void
case_stop_activation_race(void)
{
	struct dtt_cleanup_state st;

	khx_host_case("stop-activation-race");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_ready(&acc);
	(void)tx_count(&acc);
	step(&acc);
	(void)tx_count(&acc);
	step(&acc);
	host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5, 50, 6,
	    60));
	KHX_CHECK(!stopped(&acc));
	KHX_EQ(dtrace_node_id, 5);
	sar_ctrl_locks = 0;
	sar_env = &acc;
	khx_set_mtx_hook(sar_mtx_hook, NULL);
	khx_printf_reset();
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, 5, 50, TOKEN));
	khx_set_mtx_hook(NULL, NULL);
	KHX_CHECK(sar_env == NULL);		/* activation ran in the window */
	KHX_EQ(dtrace_node_id, 6);
	KHX_CHECK(failed_with(EINVAL));
	KHX_CHECK(stopped(&acc));
	/* The stale control stopped the transport; no stop was recorded for
	 * the retired identity (before the fix: accepted, flags 5). */
	KHX_EQ(cleanup_state(&acc, &st), ENXIO);
	env_down(&acc);
}

/* ---- continuity (rekey) paths retained for reference ------------------ */
static void
case_rekey(void)
{
	struct dtt_vm_identity id;
	dtt_entry_t x;
	wire_t m;
	long rv;

	reject("rekey-nofeature", VTDTR_WIRE_F_SESSION_REQUIRED |
	    VTDTR_WIRE_F_NODE_REKEY_V1, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 8, 80), EINVAL);
	reject("rekey-old0", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 0, 50, 8, 80), EINVAL);
	reject("rekey-oldmax", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, HYPERTRACE_MAX_VMS, 50, 8, 80),
	    EINVAL);
	reject("rekey-oldep0", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 0, 8, 80), EINVAL);
	reject("rekey-new0", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 0, 80), EINVAL);
	reject("rekey-newmax", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, HYPERTRACE_MAX_VMS, 80),
	    EINVAL);
	reject("rekey-newep0", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 8, 0), EINVAL);
	reject("rekey-identical", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 5, 50), EINVAL);
	reject("rekey-twice", ALL_FEATURES, st_rekeyed,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 8, 80, 9, 90), EBUSY);
	reject("rekey-cleanup", ALL_FEATURES, st_cleanup,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 8, 80), EBUSY);
	reject("rekey-stale", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 49, 8, 80), ESTALE);

	khx_host_case("rekey-front-fail");
	env_up(&acc, ALL_FEATURES, 5, 50);
	khx_host_fail_alloc(1, "dttransport");
	host_send(&acc, w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 8, 80));
	khx_host_fail_alloc(-1, NULL);
	KHX_CHECK(failed_with(ENOMEM));
	/* Identity never changes without notifying the daemon. */
	KHX_EQ(dtrace_node_id, 5);
	env_down(&acc);

	khx_host_case("rekey-accept");
	env_up(&acc, ALL_FEATURES, 5, 50);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), 0);	/* queued, not yet sent */
	rv = khx_rendezvous_count();
	st_rekeyed(&acc);
	KHX_CHECK(khx_rendezvous_count() > rv);
	KHX_EQ(dtrace_node_id, 8);
	KHX_EQ(mbufid_origin_epoch(), 80);
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_REKEY_PENDING);
	KHX_EQ(id.vmid, 8);
	KHX_EQ(id.old_vmid, 5);
	KHX_EQ(id.old_epoch, 50);
	/* No ordinary traffic or READY crosses a pending rekey. */
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	x = de_installed(DTT_INGRESS_STATUS, 0, 0, 3);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	/* Commit validation. */
	id = (struct dtt_vm_identity){ .vmid = 8, .old_vmid = 5, .epoch = 80,
	    .old_epoch = 50, .flags = 1 };
	KHX_EQ(commit_rekey(&acc, &id), EINVAL);
	id.flags = 0;
	id.old_epoch = 49;
	KHX_EQ(commit_rekey(&acc, &id), ESTALE);
	id.old_epoch = 50;
	id.vmid = 9;
	KHX_EQ(commit_rekey(&acc, &id), ESTALE);
	id.vmid = 8;
	id.old_vmid = 4;
	KHX_EQ(commit_rekey(&acc, &id), ESTALE);
	id.old_vmid = 5;
	id.epoch = 81;
	KHX_EQ(commit_rekey(&acc, &id), ESTALE);
	id.epoch = 80;
	/* An outstanding TX descriptor blocks the direct commit send. */
	{
		dtt_entry_t q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);

		KHX_EQ(dwrite(&acc, &q), 0);
		KHX_EQ(commit_rekey(&acc, &id), EBUSY);	/* query pending */
	}
	env_down(&acc);

	khx_host_case("rekey-commit-paths");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_rekeyed(&acc);
	step(&acc);
	id = (struct dtt_vm_identity){ .vmid = 8, .old_vmid = 5, .epoch = 80,
	    .old_epoch = 50 };
	khx_host_fail_alloc(1, "devbuf");
	KHX_EQ(commit_rekey(&acc, &id), ENOMEM);
	khx_host_fail_alloc(-1, NULL);
	khx_vq_fail_enqueue(acc.txq, 1, ENOSPC);
	KHX_EQ(commit_rekey(&acc, &id), ENOSPC);
	KHX_EQ(commit_rekey(&acc, &id), 0);
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, DTT_IDENTITY_REKEY_LOCAL_COMMITTED);
	id.flags = 0;
	/* Retrying after a lost reply observes the queued commit. */
	KHX_EQ(commit_rekey(&acc, &id), 0);
	expect_tx(&acc, VTDTR_WIRE_EVENT_REKEY_COMMIT, &m);
	KHX_EQ(m.uctrl.node_rekey.old_id, 5);
	KHX_EQ(m.uctrl.node_rekey.new_id, 8);
	/* A query is refused once the commit is local. */
	{
		dtt_entry_t q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);

		KHX_EQ(dwrite(&acc, &q), ESTALE);
	}
	/* Committed: stale continuations, then the exact one. */
	host_send(&acc, w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 81));
	KHX_CHECK(failed_with(ESTALE));
	env_down(&acc);

	reject("committed-unrekeyed", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 80), ESTALE);
	reject("committed-uncommitted", ALL_FEATURES, st_rekeyed,
	    w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 80), ESTALE);
	reject("committed-query", ALL_FEATURES, st_dq,
	    w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 80), ESTALE);
	reject("committed-oldid", ALL_FEATURES, st_committed,
	    w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 4, 50, 8, 80), ESTALE);
	reject("committed-oldep", ALL_FEATURES, st_committed,
	    w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 51, 8, 80), ESTALE);
	reject("committed-newid", ALL_FEATURES, st_committed,
	    w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 9, 80), ESTALE);

	khx_host_case("committed-alloc");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_committed(&acc);
	khx_host_fail_alloc(1, "devbuf");
	host_send(&acc, w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 80));
	khx_host_fail_alloc(-1, NULL);
	KHX_CHECK(failed_with(ENOMEM));
	env_down(&acc);

	khx_host_case("committed-ring");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_committed(&acc);
	khx_vq_fail_enqueue(acc.txq, 1, ENOSPC);
	host_send(&acc, w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 80));
	KHX_CHECK(failed_with(ENOSPC));
	env_down(&acc);

	khx_host_case("committed-accept");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_rekeyed(&acc);
	/* Queued source-incarnation controls never follow REKEY_APPLIED. */
	step(&acc);
	(void)tx_count(&acc);
	step(&acc);
	id = (struct dtt_vm_identity){ .vmid = 8, .old_vmid = 5, .epoch = 80,
	    .old_epoch = 50 };
	KHX_EQ(commit_rekey(&acc, &id), 0);
	expect_tx(&acc, VTDTR_WIRE_EVENT_REKEY_COMMIT, NULL);
	x = de_installed(DTT_INSTALLED, 8, 80, 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 80));
	KHX_CHECK(!stopped(&acc));
	expect_tx(&acc, VTDTR_WIRE_EVENT_REKEY_APPLIED, &m);
	KHX_EQ(m.uctrl.node_rekey.new_id, 8);
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.flags, 0);
	KHX_EQ(id.vmid, 8);
	/* The queued install was discarded: host must signal READY first. */
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	env_down(&acc);

	/* Rekey to the same VMID with a new epoch keeps dtrace_node_id. */
	khx_host_case("rekey-same-id");
	env_up(&acc, ALL_FEATURES, 5, 50);
	rv = khx_rendezvous_count();
	host_send(&acc, w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 5, 50, 5, 51));
	KHX_CHECK(!stopped(&acc));
	KHX_EQ(khx_rendezvous_count(), rv);
	KHX_EQ(mbufid_origin_epoch(), 51);
	env_down(&acc);
}

static wire_t
w_receipt(uint32_t ev, uint8_t phase, uint8_t revoked, int digest)
{
	wire_t c = w(ev);
	int kill = ev == VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT;

	c.uctrl.installed.delivery_id = kill ? 4242 : 12;
	c.uctrl.installed.vmid = 5;
	c.uctrl.installed.epoch = 50;
	c.uctrl.installed.query_id = 33;
	if (!kill)
		fill_id(c.uctrl.installed.program_id, 0x71);
	fill_id(c.uctrl.installed.source_id, 0x81);
	c.uctrl.installed.phase = phase;
	c.uctrl.installed.revoked = revoked;
	if (digest == 1)
		memset(c.uctrl.installed.digest, 0xd1, 32);
	else if (digest == 2)
		memset(c.uctrl.installed.digest, 0xd2, 32);
	return (c);
}

static void
case_receipts(void)
{
	wire_t c;
	dtt_entry_t x, q;

	/* Matching: a receipt answers only the exact pending query. */
	reject("receipt-norekey", ALL_FEATURES, st_none,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1), ESTALE);
	reject("receipt-noquery", ALL_FEATURES, st_rekeyed,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1), ESTALE);
	reject("receipt-family", ALL_FEATURES, st_dq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_INGRESS_RECEIPT, 'a', 0, 1), ESTALE);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1);
	c.uctrl.installed.vmid = 8;
	reject("receipt-vmid", ALL_FEATURES, st_dq, c, ESTALE);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1);
	c.uctrl.installed.epoch = 80;
	reject("receipt-epoch", ALL_FEATURES, st_dq, c, ESTALE);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1);
	c.uctrl.installed.delivery_id = 13;
	reject("receipt-delivery", ALL_FEATURES, st_dq, c, ESTALE);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1);
	c.uctrl.installed.query_id = 34;
	reject("receipt-query", ALL_FEATURES, st_dq, c, ESTALE);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1);
	c.uctrl.installed.program_id[3] ^= 1;
	reject("receipt-program", ALL_FEATURES, st_dq, c, ESTALE);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1);
	c.uctrl.installed.source_id[3] ^= 1;
	reject("receipt-source", ALL_FEATURES, st_dq, c, ESTALE);

	/* Content: protocol violations. */
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'u', 1, 0);
	reject("receipt-u-revoked", ALL_FEATURES, st_dq, c, EPROTO);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'u', 0, 0);
	c.uctrl.installed.replay = 1;
	reject("receipt-u-replay", ALL_FEATURES, st_dq, c, EPROTO);
	reject("receipt-u-digest", ALL_FEATURES, st_dq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'u', 0, 1), EPROTO);
	c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1);
	c.uctrl.installed.replay = 1;
	reject("receipt-replay", ALL_FEATURES, st_dq, c, EPROTO);
	reject("receipt-kill-phase", ALL_FEATURES, st_kq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT, 'i', 1, 0), EPROTO);
	reject("receipt-kill-revoked", ALL_FEATURES, st_kq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT, 'a', 0, 0), EPROTO);
	reject("receipt-kill-digest", ALL_FEATURES, st_kq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT, 'p', 1, 1), EPROTO);
	reject("receipt-terminal-revoked", ALL_FEATURES, st_dq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 't', 2, 0), EPROTO);
	reject("receipt-terminal-digest", ALL_FEATURES, st_dq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 't', 0, 1), EPROTO);
	reject("receipt-ingress-phase", ALL_FEATURES, st_iq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_INGRESS_RECEIPT, 'i', 0, 1), EPROTO);
	reject("receipt-delivery-phase", ALL_FEATURES, st_dq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'p', 0, 1), EPROTO);
	reject("receipt-revoked", ALL_FEATURES, st_dq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 1, 1), EPROTO);
	reject("receipt-digest", ALL_FEATURES, st_dq,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 2), EPROTO);

	/* Accepted receipts are delivered and clear the pending query. */
	struct { void (*setup)(struct env *); wire_t c; uint8_t kind; } ok[] = {
		{ st_dq, w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a',
		    0, 1), DTT_REKEY_DELIVERY_RECEIPT },
		{ st_dq, w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'i',
		    0, 1), DTT_REKEY_DELIVERY_RECEIPT },
		{ st_dq, w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 't',
		    1, 0), DTT_REKEY_DELIVERY_RECEIPT },
		{ st_dq, w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'u',
		    0, 0), DTT_REKEY_DELIVERY_RECEIPT },
		{ st_iq, w_receipt(VTDTR_WIRE_EVENT_REKEY_INGRESS_RECEIPT, 'a',
		    0, 1), DTT_REKEY_INGRESS_RECEIPT },
		{ st_kq, w_receipt(VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT, 'p', 1,
		    0), DTT_REKEY_KILL_RECEIPT },
		{ st_kq, w_receipt(VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT, 'a', 1,
		    0), DTT_REKEY_KILL_RECEIPT },
	};
	for (size_t i = 0; i < nitems(ok); i++) {
		accept_in("receipt-accept", ALL_FEATURES, ok[i].setup, ok[i].c);
		KHX_EQ(dread(&acc, &x), 0);
		KHX_EQ(x.event_kind, ok[i].kind);
		KHX_EQ(x.u.installed.query_id, 33);
		KHX_EQ(x.u.installed.phase, ok[i].c.uctrl.installed.phase);
		/* The query slot is free again: a duplicate receipt is stale. */
		host_send(&acc, ok[i].c);
		KHX_CHECK(failed_with(ESTALE));
		env_down(&acc);
	}

	/* An undeliverable receipt keeps the query pending. */
	khx_host_case("receipt-enqueue-fail");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_dq(&acc);
	khx_host_fail_alloc(1, "dttransport");
	host_send(&acc, w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a',
	    0, 1));
	khx_host_fail_alloc(-1, NULL);
	KHX_CHECK(failed_with(ENOMEM));
	env_down(&acc);

	/* Query admission. */
	khx_host_case("query-admission");
	env_up(&acc, VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_NODE_REKEY_V1 |
	    VTDTR_WIRE_F_REKEY_COMMIT_V1, 5, 50);
	st_rekeyed(&acc);
	step(&acc);
	q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
	KHX_EQ(dwrite(&acc, &q), ENOTSUP);
	env_down(&acc);

	env_up(&acc, ALL_FEATURES, 5, 50);
	q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
	KHX_EQ(dwrite(&acc, &q), ESTALE);		/* not rekeyed */
	st_rekeyed(&acc);
	q = de_query(DTT_REKEY_DELIVERY_QUERY, 6, 50);
	KHX_EQ(dwrite(&acc, &q), ESTALE);
	q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 51);
	KHX_EQ(dwrite(&acc, &q), ESTALE);
	step(&acc);
	khx_vq_fail_enqueue(acc.txq, 1, EIO);
	q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
	KHX_EQ(dwrite(&acc, &q), EIO);
	KHX_EQ(dwrite(&acc, &q), 0);
	KHX_EQ(dwrite(&acc, &q), EBUSY);		/* one at a time */
	(void)tx_count(&acc);
	env_down(&acc);

	/* A query cannot displace an outstanding control. */
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_rekeyed(&acc);
	{
		struct dtt_vm_identity id = { .vmid = 8, .old_vmid = 5,
		    .epoch = 80, .old_epoch = 50 };

		step(&acc);
		/* Keep a descriptor outstanding: the device has not consumed
		 * the direct commit. */
		KHX_EQ(commit_rekey(&acc, &id), 0);
	}
	q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
	KHX_EQ(dwrite(&acc, &q), ESTALE);		/* committed */
	env_down(&acc);

	/* Completed but unreaped descriptors keep the ring non-empty: a query
	 * waits for the communicator to reap; the direct commit reaps itself. */
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_rekeyed(&acc);
	{
		struct dtt_vm_identity id = { .vmid = 8, .old_vmid = 5,
		    .epoch = 80, .old_epoch = 50 };
		dtt_entry_t q2 = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);

		KHX_EQ(dwrite(&acc, &q2), EBUSY);
		KHX_EQ(commit_rekey(&acc, &id), 0);
	}
	env_down(&acc);

	/* A descriptor the device still holds blocks the direct commit. */
	khx_host_case("commit-held-descriptor");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_rekeyed(&acc);
	step(&acc);
	{
		struct dtt_vm_identity id = { .vmid = 8, .old_vmid = 5,
		    .epoch = 80, .old_epoch = 50 };
		dtt_entry_t q2 = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
		void *held;

		KHX_EQ(dwrite(&acc, &q2), 0);
		held = khx_vq_take(acc.txq, NULL, NULL, NULL, NULL);
		KHX_CHECK(held != NULL);
		host_send(&acc, w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT,
		    'a', 0, 1));
		KHX_CHECK(!stopped(&acc));
		KHX_EQ(commit_rekey(&acc, &id), EBUSY);
		x = de_query(DTT_REKEY_KILL_QUERY, 5, 50);
		KHX_EQ(dwrite(&acc, &x), EBUSY);
		khx_vq_complete(acc.txq, held, 0);
		KHX_EQ(commit_rekey(&acc, &id), 0);
	}
	env_down(&acc);
}

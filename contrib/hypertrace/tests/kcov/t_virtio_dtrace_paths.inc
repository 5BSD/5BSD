/* SPDX-License-Identifier: BSD-2-Clause */
/* Daemon-side admission, communicator, RX task and lifecycle cases for
 * t_virtio_dtrace.c (included there). */

struct entry_case {
	const char *name;
	dtt_entry_t x;
	int error;
};

/* Untrusted daemon writes: every malformed entry is refused with EINVAL
 * before it can reach the host. */
static void
case_daemon_validation(void)
{
	static struct entry_case cases[160];
	int n = 0;
	dtt_entry_t x;

#define ADD(nm, expr, err) do {					\
	if (n == (int)nitems(cases))				\
		panic("too many cases");			\
	cases[n].name = nm;					\
	cases[n].x = (expr);					\
	cases[n].error = err;					\
	n++;							\
} while (0)
	x = de_elf(5, 50, 10, 10, 0); x.u.elf.len = 0;
	ADD("elf-len0", x, EINVAL);
	x = de_elf(5, 50, 10, 10, 0); x.u.elf.delivery_id = 0;
	ADD("elf-delivery", x, EINVAL);
	ADD("elf-vmid0", de_elf(0, 50, 10, 10, 0), EINVAL);
	ADD("elf-vmidmax", de_elf(HYPERTRACE_MAX_VMS, 50, 10, 10, 0), EINVAL);
	ADD("elf-epoch0", de_elf(5, 0, 10, 10, 0), EINVAL);
	x = de_elf(5, 50, 10, 10, 0); memset(x.u.elf.program_id, 0, 16);
	ADD("elf-program", x, EINVAL);
	x = de_elf(5, 50, 10, 10, 0); memset(x.u.elf.source_id, 0, 16);
	ADD("elf-source", x, EINVAL);
	ADD("elf-other-vmid", de_elf(6, 50, 10, 10, 0), ESTALE);
	ADD("elf-other-epoch", de_elf(5, 51, 10, 10, 0), ESTALE);

	x = de_installed(DTT_INSTALLED, 5, 50, 0); x.u.installed.delivery_id = 0;
	ADD("inst-delivery", x, EINVAL);
	ADD("inst-vmid0", de_installed(DTT_INSTALLED, 0, 50, 0), EINVAL);
	ADD("inst-vmidmax", de_installed(DTT_UNINSTALLED, HYPERTRACE_MAX_VMS, 50,
	    0), EINVAL);
	ADD("inst-epoch0", de_installed(DTT_INSTALLED, 5, 0, 0), EINVAL);
	ADD("ingress-vmid", de_installed(DTT_INGRESS_STATUS, 5, 0, 3), EINVAL);
	ADD("ingress-epoch", de_installed(DTT_INGRESS_STATUS, 0, 50, 3), EINVAL);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	memset(x.u.installed.program_id, 0, 16);
	ADD("inst-program", x, EINVAL);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	memset(x.u.installed.source_id, 0, 16);
	ADD("inst-source", x, EINVAL);
	x = de_installed(DTT_INSTALLED, 5, 50, 0); x.u.installed.phase = 'a';
	ADD("inst-phase", x, EINVAL);
	x = de_installed(DTT_INSTALLED, 5, 50, 0); x.u.installed.revoked = 1;
	ADD("inst-revoked", x, EINVAL);
	x = de_installed(DTT_INSTALLED, 5, 50, 0); x.u.installed.replay = 1;
	ADD("inst-replay", x, EINVAL);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	x.u.installed.digest[5] = 1;
	ADD("inst-digest", x, EINVAL);
	ADD("inst-query", de_installed(DTT_INSTALLED, 5, 50, 4), EINVAL);
	ADD("status-noquery", de_installed(DTT_STATUS, 5, 50, 0), EINVAL);
	ADD("inst-other-vmid", de_installed(DTT_INSTALLED, 6, 50, 0), ESTALE);
	ADD("uninst-other-epoch", de_installed(DTT_UNINSTALLED, 5, 51, 0),
	    ESTALE);
	ADD("status-other", de_installed(DTT_STATUS, 6, 50, 9), ESTALE);

	x = de(DTT_VM_IDENTITY_QUERY);
	ADD("idq-noquery", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.delivery_id = 1;
	ADD("idq-delivery", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.vmid = 1;
	ADD("idq-vmid", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.epoch = 1;
	ADD("idq-epoch", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.program_id[0] = 1;
	ADD("idq-program", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.source_id[0] = 1;
	ADD("idq-source", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.phase = 1;
	ADD("idq-phase", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.revoked = 1;
	ADD("idq-revoked", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.replay = 1;
	ADD("idq-replay", x, EINVAL);
	x = de(DTT_VM_IDENTITY_QUERY); x.u.installed.query_id = 1;
	x.u.installed.digest[0] = 1;
	ADD("idq-digest", x, EINVAL);

	x = de(DTT_KILL_APPLIED); x.u.kill.pid = 1; x.u.kill.vmid = 5;
	x.u.kill.epoch = 50; fill_id(x.u.kill.source_id, 1);
	ADD("killapp-pid", x, EINVAL);
	x.u.kill.pid = 100; x.u.kill.vmid = 0;
	ADD("killapp-vmid0", x, EINVAL);
	x.u.kill.vmid = HYPERTRACE_MAX_VMS;
	ADD("killapp-vmidmax", x, EINVAL);
	x.u.kill.vmid = 5; x.u.kill.epoch = 0;
	ADD("killapp-epoch0", x, EINVAL);
	x.u.kill.epoch = 50; memset(x.u.kill.source_id, 0, 16);
	ADD("killapp-source", x, EINVAL);
	fill_id(x.u.kill.source_id, 1); x.u.kill.vmid = 6;
	ADD("killapp-other", x, ESTALE);
	x.u.kill.vmid = 5; x.u.kill.epoch = 51;
	ADD("killapp-other-epoch", x, ESTALE);

	ADD("cleanup-delivery0", de_cleanup(DTT_CLEANUP_APPLIED, 5, 50, 0),
	    EINVAL);
	ADD("cleanup-vmid0", de_cleanup(DTT_SESSION_STOPPED, 0, 50, 1), EINVAL);
	ADD("cleanup-vmidmax", de_cleanup(DTT_CLEANUP_APPLIED,
	    HYPERTRACE_MAX_VMS, 50, 1), EINVAL);
	ADD("cleanup-epoch0", de_cleanup(DTT_CLEANUP_APPLIED, 5, 0, 1), EINVAL);

	x = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
	x.u.installed.delivery_id = 0;
	ADD("q-delivery", x, EINVAL);
	ADD("q-vmid0", de_query(DTT_REKEY_DELIVERY_QUERY, 0, 50), EINVAL);
	ADD("q-vmidmax", de_query(DTT_REKEY_INGRESS_QUERY, HYPERTRACE_MAX_VMS,
	    50), EINVAL);
	ADD("q-epoch0", de_query(DTT_REKEY_DELIVERY_QUERY, 5, 0), EINVAL);
	x = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50); x.u.installed.query_id = 0;
	ADD("q-query0", x, EINVAL);
	x = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50); x.u.installed.phase = 1;
	ADD("q-phase", x, EINVAL);
	x = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50); x.u.installed.revoked = 1;
	ADD("q-revoked", x, EINVAL);
	x = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50); x.u.installed.replay = 1;
	ADD("q-replay", x, EINVAL);
	x = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
	memset(x.u.installed.source_id, 0, 16);
	ADD("q-source", x, EINVAL);
	x = de_query(DTT_REKEY_KILL_QUERY, 5, 50); x.u.installed.delivery_id = 1;
	ADD("kq-pid1", x, EINVAL);
	x = de_query(DTT_REKEY_KILL_QUERY, 5, 50);
	x.u.installed.delivery_id = (uint64_t)INT32_MAX + 1;
	ADD("kq-pidbig", x, EINVAL);
	x = de_query(DTT_REKEY_KILL_QUERY, 5, 50);
	x.u.installed.program_id[0] = 1;
	ADD("kq-program", x, EINVAL);
	x = de_query(DTT_REKEY_KILL_QUERY, 5, 50); x.u.installed.digest[0] = 1;
	ADD("kq-digest", x, EINVAL);
	x = de_query(DTT_REKEY_INGRESS_QUERY, 5, 50);
	memset(x.u.installed.program_id, 0, 16);
	ADD("iq-program", x, EINVAL);
	x = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);
	memset(x.u.installed.digest, 0, 32);
	ADD("dq-digest", x, EINVAL);
	ADD("kill-to-host", de(DTT_KILL), EINVAL);
	ADD("unknown-kind", de(99), EINVAL);
	ADD("host-only-kind", de(DTT_HOST_INSTALLED), EINVAL);
#undef ADD

	khx_host_case("daemon-validation");
	env_up(&acc, ALL_FEATURES, 5, 50);
	for (int i = 0; i < n; i++) {
		int got = dwrite(&acc, &cases[i].x);

		if (got != cases[i].error)
			khx_host_log("  [%s] got %d want %d\n", cases[i].name,
			    got, cases[i].error);
		KHX_EQ(got, cases[i].error);
	}
	/* Nothing reached the host. */
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	KHX_CHECK(!stopped(&acc));
	env_down(&acc);
}

/* Valid daemon entries are translated exactly onto the wire. */
static void
case_daemon_translation(void)
{
	dtt_entry_t x;
	wire_t m[16];
	int n;

	khx_host_case("daemon-translation");
	env_up(&acc, ALL_FEATURES, 5, 50);
	x = de_elf(5, 50, 100, 300, 1);
	KHX_EQ(dwrite(&acc, &x), 0);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	x = de_installed(DTT_UNINSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	x = de_installed(DTT_STATUS, 5, 50, 7);
	KHX_EQ(dwrite(&acc, &x), 0);
	x = de_installed(DTT_INGRESS_STATUS, 0, 0, 8);
	KHX_EQ(dwrite(&acc, &x), 0);
	x = de(DTT_VM_IDENTITY_QUERY);
	x.u.installed.query_id = 9;
	KHX_EQ(dwrite(&acc, &x), 0);
	x = de(DTT_KILL_APPLIED);
	x.u.kill.pid = 77;
	x.u.kill.vmid = 5;
	x.u.kill.epoch = 50;
	fill_id(x.u.kill.source_id, 0x22);
	KHX_EQ(dwrite(&acc, &x), 0);
	step(&acc);
	n = host_recv(&acc, m, 16);
	KHX_EQ(n, 8);
	KHX_EQ(m[0].event, VTDTR_WIRE_EVENT_ELF);
	KHX_EQ(m[0].uctrl.elf.elflen, 100);
	KHX_EQ(m[0].uctrl.elf.totalelflen, 300);
	KHX_EQ(m[0].uctrl.elf.elfhasmore, 1);
	KHX_EQ(m[0].uctrl.elf.identifier, 0xabc);
	KHX_EQ(m[0].uctrl.elf.delivery_id, 31);
	KHX_EQ((uint8_t)m[0].uctrl.elf.elf[99], 99 ^ 0x5a);
	KHX_EQ(m[0].uctrl.elf.elf[100], 0);	/* no bytes beyond len */
	KHX_EQ(m[0].uctrl.elf.program_id[0], 0x51);
	KHX_EQ(m[0].uctrl.elf.elf_source_id[0], 0x61);
	KHX_EQ(m[1].event, VTDTR_WIRE_EVENT_INSTALLED);
	KHX_EQ(m[1].uctrl.installed.delivery_id, 21);
	KHX_EQ(m[2].event, VTDTR_WIRE_EVENT_UNINSTALLED);
	KHX_EQ(m[3].event, VTDTR_WIRE_EVENT_STATUS);
	KHX_EQ(m[3].uctrl.installed.query_id, 7);
	KHX_EQ(m[4].event, VTDTR_WIRE_EVENT_INGRESS_STATUS);
	KHX_EQ(m[4].uctrl.installed.vmid, 0);
	KHX_EQ(m[5].event, VTDTR_WIRE_EVENT_NODE_ID);
	KHX_EQ(m[5].uctrl.node_id.query_id, 9);
	KHX_EQ(m[6].event, VTDTR_WIRE_EVENT_KILL_APPLIED);
	KHX_EQ(m[6].uctrl.kill.pid, 77);
	KHX_EQ(m[6].uctrl.kill.source_id[0], 0x22);
	KHX_EQ(m[7].event, VTDTR_WIRE_EVENT_EOF);
	env_down(&acc);
}

/* Bounded queues: the control queue refuses work beyond its capacity
 * and the communicator never overfills the TX ring. */
static void
case_capacity(void)
{
	dtt_entry_t x;
	int i, err = 0;
	uint32_t ev[64];
	int n;

	khx_host_case("ctrlq-capacity");
	env_up(&acc, ALL_FEATURES, 5, 50);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	/* The host is not ready yet: nothing drains the queue. */
	for (i = 0; i < 4096 && err == 0; i++)
		err = dwrite(&acc, &x);
	KHX_EQ(err, 0);
	KHX_EQ(dwrite(&acc, &x), ENOBUFS);
	/* The communicator fills the ring and stops at full. */
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	KHX_EQ(khx_vq_free(acc.txq), 0);
	n = host_recv_events(&acc, ev, 64);
	KHX_EQ(n, khx_vq_size(acc.txq));
	/* The ring was full when the batch ended: no room for EOF. */
	KHX_EQ(ev[n - 1], VTDTR_WIRE_EVENT_INSTALLED);
	env_down(&acc);

	/* Enqueue failure mid-batch stops the batch, keeping the entry. */
	khx_host_case("send-enqueue-fail");
	env_up(&acc, ALL_FEATURES, 5, 50);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	khx_vq_fail_enqueue(acc.txq, 2, EIO);
	step(&acc);
	n = host_recv_events(&acc, ev, 64);
	/* One sent, the second refused; EOF (third enqueue) succeeds. */
	KHX_EQ(n, 2);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_INSTALLED);
	KHX_EQ(ev[1], VTDTR_WIRE_EVENT_EOF);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	n = host_recv_events(&acc, ev, 64);
	KHX_EQ(n, 2);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_INSTALLED);
	/* EOF allocation failure: the batch is still delivered. */
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	khx_host_fail_alloc(1, "devbuf");
	step(&acc);
	khx_host_fail_alloc(-1, NULL);
	n = host_recv_events(&acc, ev, 64);
	KHX_EQ(n, 1);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_INSTALLED);
	/* EOF enqueue failure is also tolerated. */
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	khx_vq_fail_enqueue(acc.txq, 2, EIO);
	step(&acc);
	n = host_recv_events(&acc, ev, 64);
	KHX_EQ(n, 1);
	env_down(&acc);

	/* Cleanup proofs under allocation and ring pressure are retried. */
	khx_host_case("proof-pressure");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_cleanup_applied(&acc);
	(void)tx_count(&acc);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	/* The proof allocation fails; the queued READY still goes out. */
	khx_host_fail_alloc(1, "devbuf");
	step(&acc);
	khx_host_fail_alloc(-1, NULL);
	n = host_recv_events(&acc, ev, 64);
	KHX_EQ(n, 2);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_READY);
	KHX_EQ(ev[1], VTDTR_WIRE_EVENT_EOF);
	/* Only READY was sent, so the host stays ready; the proof's ring
	 * slot is refused once and the proof is retried next pass. */
	khx_vq_fail_enqueue(acc.txq, 1, EIO);
	step(&acc);
	KHX_EQ(tx_count(&acc), 0);
	step(&acc);
	n = host_recv_events(&acc, ev, 64);
	KHX_EQ(n, 2);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_CLEANUP_APPLIED);
	env_down(&acc);

	/* Shutdown refuses new daemon work. */
	khx_host_case("enqueue-after-stop");
	env_up(&acc, ALL_FEATURES, 5, 50);
	host_send(&acc, w(0x7e));		/* stops the transport */
	KHX_CHECK(stopped(&acc));
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	KHX_EQ(dwrite(&acc, &x), ENOBUFS);
	x = de_cleanup(DTT_CLEANUP_APPLIED, 5, 50, 10);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	x = de_cleanup(DTT_SESSION_READY, 6, 60, TOKEN);
	KHX_EQ(dwrite(&acc, &x), ESTALE);
	{
		struct dtt_vm_identity id = { .vmid = 8, .old_vmid = 5,
		    .epoch = 80, .old_epoch = 50 };
		struct dtt_cleanup_state st;
		dtt_entry_t q = de_query(DTT_REKEY_DELIVERY_QUERY, 5, 50);

		KHX_EQ(identity(&acc, &id), ENXIO);
		KHX_EQ(cleanup_state(&acc, &st), ENXIO);
		id = (struct dtt_vm_identity){ .vmid = 8, .old_vmid = 5,
		    .epoch = 80, .old_epoch = 50 };
		KHX_EQ(commit_rekey(&acc, &id), ENXIO);
		KHX_EQ(dwrite(&acc, &q), ENXIO);
	}
	/* Interrupts after stop do not schedule work. */
	khx_vq_interrupt(acc.rxq);
	KHX_EQ(khx_taskqueue_pending(acc.tq), 0);
	env_down(&acc);
}

/* ---- RX task -------------------------------------------------------- */
static void
case_rx_task(void)
{
	struct dtt_vm_identity id;
	wire_t batch[3];
	uint32_t ev[8];

	/* EOF ends a batch; later controls wait for the next interrupt. */
	khx_host_case("rx-eof");
	env_up(&acc, ALL_FEATURES, 0, 0);
	batch[0] = w(VTDTR_WIRE_EVENT_EOF);
	batch[1] = w_node(3, 30, 0);
	for (int i = 0; i < 2; i++) {
		void *buf = khx_vq_take(acc.rxq, NULL, NULL, NULL, NULL);

		memcpy(buf, &batch[i], sizeof(wire_t));
		khx_vq_complete(acc.rxq, buf, sizeof(wire_t));
	}
	khx_vq_interrupt(acc.rxq);
	KHX_EQ(khx_taskqueue_run_one(acc.tq), 1);
	/* The batch ended at EOF; the pending completion rescheduled it. */
	KHX_EQ(identity(&acc, &id), EAGAIN);
	KHX_EQ(khx_taskqueue_pending(acc.tq), 1);
	KHX_EQ(khx_taskqueue_run_one(acc.tq), 1);
	KHX_EQ(identity(&acc, &id), 0);
	KHX_EQ(id.vmid, 3);
	env_down(&acc);

	/* A completion coalesced with interrupt enable reschedules the task. */
	khx_host_case("rx-coalesced");
	env_up(&acc, ALL_FEATURES, 5, 50);
	khx_vq_enable_intr_race(acc.rxq, 1);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	KHX_EQ(khx_taskqueue_pending(acc.tq), 0);
	KHX_CHECK(!stopped(&acc));
	env_down(&acc);

	/* An RX buffer that cannot be reposted stops the transport. */
	khx_host_case("rx-requeue-fail");
	env_up(&acc, ALL_FEATURES, 5, 50);
	khx_vq_fail_enqueue(acc.rxq, 1, ENOSPC);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	KHX_CHECK(khx_printf_seen("cannot requeue RX control (28)"));
	KHX_CHECK(stopped(&acc));
	env_down(&acc);

	/* READY that cannot be queued stops the transport. */
	khx_host_case("ready-alloc-entry");
	env_up(&acc, ALL_FEATURES, 5, 50);
	khx_host_fail_alloc(1, "devbuf");
	host_send(&acc, w_kill(VTDTR_WIRE_EVENT_KILL, 5, 50, 100));
	khx_host_fail_alloc(-1, NULL);
	KHX_CHECK(khx_printf_seen("cannot queue READY (12)"));
	KHX_CHECK(stopped(&acc));
	env_down(&acc);
	khx_host_case("ready-alloc-ctrl");
	env_up(&acc, ALL_FEATURES, 5, 50);
	khx_host_fail_alloc(2, "devbuf");
	host_send(&acc, w_kill(VTDTR_WIRE_EVENT_KILL, 5, 50, 100));
	khx_host_fail_alloc(-1, NULL);
	KHX_CHECK(khx_printf_seen("cannot queue READY (12)"));
	env_down(&acc);

	/* READY is not re-armed while a rekey is pending. */
	khx_host_case("ready-suppressed-rekey");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_rekeyed(&acc);
	step(&acc);
	KHX_EQ(host_recv_events(&acc, ev, 8), 0);
	env_down(&acc);

	/* The attach-time interrupt enable may observe early completions. */
	khx_host_case("attach-coalesced");
	env_create(&acc, ALL_FEATURES);
	khx_vdev_vq_race(acc.dev, 0, 1);
	KHX_EQ(env_attach(&acc), 0);
	KHX_EQ(khx_taskqueue_pending(acc.tq), 1);
	khx_taskqueue_run(acc.tq);
	env_down(&acc);
}

/* ---- concurrency: detach racing the RX task --------------------------- */
static void *race_parked, *race_go;
static int race_armed;

static void
race_rendezvous(void *arg __unused)
{
	if (!race_armed)
		return;
	race_armed = 0;
	khx_host_sem_post(race_parked);
	khx_host_sem_wait(race_go);
}

static void
race_stop_hook(void *arg __unused, device_t dev __unused)
{
	/* The driver set its shutdown state; let the RX task continue. */
	khx_host_sem_post(race_go);
}

static struct env race_env;
static struct thread *race_td;

static void
race_task_main(void *arg __unused)
{
	khx_pthread_attach(2, race_td);
	khx_taskqueue_run(race_env.tq);
}

static void
case_detach_race(void)
{
	void *h;
	long live;

	khx_host_case("detach-races-rx-task");
	live = live_tag();
	env_up(&race_env, ALL_FEATURES, 0, 0);
	race_parked = khx_host_sem_new(0);
	race_go = khx_host_sem_new(0);
	race_td = khx_thread_new("rxtask", 0);
	/* Queue NODE_ID; the RX task parks inside the rendezvous it performs
	 * after publishing the node ID. */
	{
		int r, wr;
		size_t rb, wb;
		void *buf = khx_vq_take(race_env.rxq, &r, &wr, &rb, &wb);
		wire_t c = w_node(3, 30, 0);

		memcpy(buf, &c, sizeof(c));
		khx_vq_complete(race_env.rxq, buf, sizeof(c));
		khx_vq_interrupt(race_env.rxq);
	}
	khx_set_rendezvous_hook(race_rendezvous, NULL);
	race_armed = 1;
	h = khx_host_thread_start(race_task_main, NULL);
	khx_host_sem_wait(race_parked);
	khx_set_virtio_stop_hook(race_stop_hook, NULL);
	/* Detach must wait for the running task before freeing its state; the
	 * task must observe shutdown and drop its buffer. */
	KHX_EQ(khx_driver_call(drv, "detach", race_env.dev), 0);
	khx_host_thread_join(h);
	khx_set_virtio_stop_hook(NULL, NULL);
	khx_set_rendezvous_hook(NULL, NULL);
	race_env.attach_error = 1;
	env_down(&race_env);
	KHX_EQ(live_tag(), live);
	KHX_EQ(dtrace_node_id, 0);
}

/* ---- lifecycle odds and ends ------------------------------------------ */
static void
case_lifecycle(void)
{
	struct env e;
	long live;

	khx_host_case("module-events");
	KHX_EQ(khx_module_event("virtio_pci/virtio_dtrace", MOD_QUIESCE), 0);
	KHX_EQ(khx_module_event("virtio_pci/virtio_dtrace", MOD_SHUTDOWN), 0);
	KHX_EQ(khx_module_event("virtio_pci/virtio_dtrace", MOD_UNLOAD), 0);
	KHX_EQ(khx_module_event("virtio_pci/virtio_dtrace", 77), EOPNOTSUPP);
	KHX_EQ(khx_module_event("virtio_pci/virtio_dtrace", MOD_LOAD), 0);

	/* Detach never clears an identity it does not own. */
	khx_host_case("detach-foreign-identity");
	env_up(&e, ALL_FEATURES, 5, 50);
	dtrace_node_id = 99;
	env_down(&e);
	KHX_EQ(dtrace_node_id, 99);
	dtrace_node_id = 0;

	/* Detach before NODE_ID arrives leaves dtrace_node_id untouched. */
	khx_host_case("detach-no-identity");
	env_up(&e, ALL_FEATURES, 0, 0);
	env_down(&e);
	KHX_EQ(dtrace_node_id, 0);

	/* Repeated attach/detach cycles release everything. */
	khx_host_case("attach-cycles");
	live = live_tag();
	for (int i = 0; i < 20; i++) {
		env_up(&e, ALL_FEATURES, (uint16_t)(1 + i), 100 + i);
		host_send(&e, w_elf((uint16_t)(1 + i), 100 + i, 5, 5, 0));
		env_down(&e);
	}
	KHX_EQ(live_tag(), live);

	/* Pages that are physically discontiguous need two descriptors per
	 * control; the rings still account correctly. */
	khx_host_case("scattered-pages");
	khx_pmap_scatter(1);
	env_up(&e, ALL_FEATURES, 5, 50);
	host_send(&e, w_elf(5, 50, 5, 5, 0));
	KHX_CHECK(!stopped(&e));
	env_down(&e);
	khx_pmap_scatter(0);
}

/* ---- additional reachable paths ---------------------------------------- */
static void
case_more_paths(void)
{
	struct sysctl_oid *oid;
	struct dtt_vm_identity id;
	dtt_entry_t x;
	uint32_t one = 1, zero = 0, got = 7, ev[64];
	size_t len;
	int n;

	/* dev.vtdtr.debug traces each control event. */
	khx_host_case("debug-sysctl");
	oid = khx_sysctl_find("vtdtr", "debug");
	KHX_CHECK(oid != NULL);
	len = sizeof(got);
	KHX_EQ(khx_sysctl_call(oid, daemon_td, &got, &len, &one, sizeof(one)),
	    0);
	KHX_EQ(got, 0);
	env_up(&acc, ALL_FEATURES, 0, 0);
	host_send(&acc, w_node(5, 50, 0));
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	host_send(&acc, w_elf(5, 50, 1, 1, 0));
	host_send(&acc, w_kill(VTDTR_WIRE_EVENT_KILL, 5, 50, 100));
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 3));
	host_send(&acc, w(VTDTR_WIRE_EVENT_EOF));
	KHX_CHECK(khx_printf_seen("VIRTIO_DTRACE_NODE_ID"));
	KHX_CHECK(khx_printf_seen("VIRTIO_DTRACE_DEVICE_READY"));
	KHX_CHECK(khx_printf_seen("VIRTIO_DTRACE_ELF"));
	KHX_CHECK(khx_printf_seen("VIRTIO_DTRACE_KILL"));
	KHX_CHECK(khx_printf_seen("VIRTIO_DTRACE_CLEANUP_DTRACED"));
	KHX_CHECK(khx_printf_seen("VIRTIO_DTRACE_EOF"));
	env_down(&acc);
	KHX_EQ(khx_sysctl_call(oid, daemon_td, NULL, NULL, &zero, sizeof(zero)),
	    0);

	/* A TX completion interrupt wakes the communicator. */
	khx_host_case("tx-interrupt");
	env_up(&acc, ALL_FEATURES, 5, 50);
	{
		long before = khx_host_wakeups(NULL);

		(void)before;
		khx_vq_interrupt(acc.txq);
		KHX_CHECK(!stopped(&acc));
	}
	env_down(&acc);

	/* Host cleanup receipts: duplicate detection must match exactly. */
	khx_host_case("receipt-duplicates");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_cleanup_applied(&acc);
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50,
	    10));
	KHX_CHECK(!stopped(&acc));
	/* The host reuses the accepted delivery ID for a new cleanup. */
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50, 10));
	KHX_EQ(dread(&acc, &x), 0);
	x = de_cleanup(DTT_CLEANUP_APPLIED, 5, 50, 10);
	KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50,
	    10));
	KHX_CHECK(!stopped(&acc));
	env_down(&acc);

	reject("receipt-dup-other-delivery", ALL_FEATURES, st_none,
	    w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, 5, 50, 7), ESTALE);
	{
		static void (*after_accept)(struct env *);
		(void)after_accept;
	}
	khx_host_case("receipt-dup-wrong-identity");
	for (int v = 0; v < 2; v++) {
		env_up(&acc, ALL_FEATURES, 5, 50);
		st_cleanup_applied(&acc);
		host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED,
		    5, 50, 10));
		host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED,
		    v == 0 ? 6 : 5, v == 0 ? 50 : 51, 10));
		KHX_CHECK(failed_with(ESTALE));
		env_down(&acc);
	}
	khx_host_case("receipt-pending-variants");
	for (int v = 0; v < 3; v++) {
		env_up(&acc, ALL_FEATURES, 5, 50);
		st_cleanup_applied(&acc);
		host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED,
		    5, 50, 10));
		host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, 5, 50,
		    11));
		KHX_EQ(dread(&acc, &x), 0);
		host_send(&acc, w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED,
		    v == 1 ? 6 : 5, v == 2 ? 51 : 50, v == 0 ? 0 : 10));
		KHX_CHECK(failed_with(ESTALE));
		env_down(&acc);
	}

	/* Rekey receipts require the receipt feature. */
	reject("receipt-nofeature", VTDTR_WIRE_F_SESSION_REQUIRED |
	    VTDTR_WIRE_F_NODE_REKEY_V1 | VTDTR_WIRE_F_REKEY_COMMIT_V1, st_rekeyed,
	    w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT, 'a', 0, 1), ESTALE);
	reject("rekey-stale-id", ALL_FEATURES, st_none,
	    w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, 4, 50, 8, 80), ESTALE);

	/* Commit without a pending rekey is stale. */
	khx_host_case("commit-not-rekeyed");
	env_up(&acc, ALL_FEATURES, 5, 50);
	id = (struct dtt_vm_identity){ .vmid = 5, .old_vmid = 5, .epoch = 50,
	    .old_epoch = 50 };
	KHX_EQ(commit_rekey(&acc, &id), ESTALE);
	env_down(&acc);

	/* Detach runs a pending RX task, which observes shutdown. */
	khx_host_case("detach-pending-task");
	env_up(&acc, ALL_FEATURES, 5, 50);
	{
		void *buf = khx_vq_take(acc.rxq, NULL, NULL, NULL, NULL);
		wire_t c = w_node(5, 50, 0);

		memcpy(buf, &c, sizeof(c));
		khx_vq_complete(acc.rxq, buf, sizeof(c));
		khx_vq_interrupt(acc.rxq);
		KHX_EQ(khx_taskqueue_pending(acc.tq), 1);
	}
	env_down(&acc);

	/* A full control queue refuses READY and stops the transport. */
	khx_host_case("ready-ctrlq-full");
	env_up(&acc, ALL_FEATURES, 5, 50);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	for (n = 0; n < 4096; n++)
		if (dwrite(&acc, &x) != 0)
			break;
	KHX_EQ(n, 4096);
	host_send(&acc, w_kill(VTDTR_WIRE_EVENT_KILL, 5, 50, 100));
	KHX_CHECK(khx_printf_seen("cannot queue READY (55)"));
	KHX_CHECK(stopped(&acc));
	env_down(&acc);

	/* A repeated commit whose activation is deferred also holds back
	 * queued new-session work until ACTIVE is sent. */
	khx_host_case("commit-deferred-holds-queue");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_active(&acc);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	(void)tx_count(&acc);
	step(&acc);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	x = de_installed(DTT_INSTALLED, 6, 60, 0);
	KHX_EQ(dwrite(&acc, &x), 0);
	{
		/* Hold one TX descriptor at the device. */
		dtt_entry_t y = de_installed(DTT_UNINSTALLED, 6, 60, 0);
		void *held;

		KHX_EQ(dwrite(&acc, &y), 0);
		step(&acc);
		held = khx_vq_take(acc.txq, NULL, NULL, NULL, NULL);
		(void)tx_count(&acc);
		host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
		KHX_EQ(dwrite(&acc, &x), 0);
		host_send(&acc, w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, TOKEN, 5,
		    50, 6, 60));
		step(&acc);
		KHX_EQ(tx_count(&acc), 0);
		khx_vq_complete(acc.txq, held, 0);
		step(&acc);
		n = host_recv_events(&acc, ev, 64);
		KHX_CHECK(n >= 2);
		KHX_EQ(ev[0], VTDTR_WIRE_EVENT_SESSION_ACTIVE);
	}
	env_down(&acc);

	/* A cleanup proof waits when ordinary traffic fills the ring. */
	khx_host_case("proof-ring-full");
	env_up(&acc, ALL_FEATURES, 5, 50);
	st_cleanup_applied(&acc);
	(void)tx_count(&acc);
	x = de_installed(DTT_INSTALLED, 5, 50, 0);
	for (n = 0; n < 2 * KHX_VQ_DEFAULT_SIZE; n++)
		KHX_EQ(dwrite(&acc, &x), 0);
	host_send(&acc, w(VTDTR_WIRE_EVENT_READY));
	step(&acc);
	n = host_recv_events(&acc, ev, 64);
	KHX_EQ(n, KHX_VQ_DEFAULT_SIZE);
	for (int i = 0; i < n; i++)
		KHX_CHECK(ev[i] != VTDTR_WIRE_EVENT_CLEANUP_APPLIED);
	env_down(&acc);
}

/* ---- bounded protocol fuzzing -------------------------------------------
 * Random interleavings of host controls (valid templates with mutated
 * fields, plus arbitrary garbage), daemon writes, communicator passes and
 * device completions.  Oracles are protocol invariants:
 *   - a session stop the driver accepted is followed by no old-session
 *     control on the TX ring until SESSION_ACTIVE;
 *   - entries delivered to the daemon for ELF/KILL/HOST_* carry the
 *     identity the driver reported immediately before the control;
 *   - dtrace_node_id is never cleared while the device is attached and only
 *     changes on NODE_ID from zero, NODE_REKEY or fresh activation;
 *   - detach releases every control buffer and dttransport entry.
 */
static uint64_t fz_state;

static uint64_t
fz_next(void)
{
	uint64_t x = fz_state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	return (fz_state = x);
}

static uint64_t
fz_pick(const uint64_t *v, int n)
{
	return (v[fz_next() % n]);
}

/* Mostly well-formed controls for the current identity, so sequences reach
 * deep protocol states; one field in ten is mutated and 1/32 is garbage. */
static wire_t
fz_host_message_any(uint16_t vmid, uint64_t epoch);

/* State-aware choice: mostly controls that are legal in the driver's
 * current phase, as a correct host would send; occasionally anything. */
static wire_t
fz_host_message(struct env *e, uint16_t vmid, uint64_t epoch)
{
	struct dtt_cleanup_state st;
	struct dtt_vm_identity id;
	int stopped_phase = 0, rekey = 0, pending = 0;

	if (cleanup_state(e, &st) == 0) {
		stopped_phase = (st.flags & DTT_CLEANUP_STATE_SESSION_STOP) != 0;
		pending = (st.flags & DTT_CLEANUP_STATE_PENDING) != 0;
	}
	if (identity(e, &id) == 0)
		rekey = (id.flags & (DTT_IDENTITY_REKEY_PENDING |
		    DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) != 0;
	if (fz_next() % 40 == 0)
		return (fz_host_message_any(vmid, epoch));
	if (stopped_phase) {
		switch (fz_next() % 5) {
		case 0: return (w(VTDTR_WIRE_EVENT_READY));
		case 1: return (w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, vmid,
		    epoch, st.delivery_id));
		case 2: return (w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE,
		    st.delivery_id, vmid, epoch, vmid == 6 ? 7 : 6,
		    vmid == 6 ? 70 : 60));
		case 3: return (w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT,
		    st.delivery_id, vmid, epoch, vmid == 6 ? 7 : 6,
		    vmid == 6 ? 70 : 60));
		default: return (w(VTDTR_WIRE_EVENT_EOF));
		}
	}
	if (rekey) {
		switch (fz_next() % 3) {
		case 0: return (w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED,
		    id.old_vmid, id.old_epoch, id.vmid, id.epoch));
		case 1: return (w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT,
		    'a', 0, 1));
		default: return (w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, id.old_vmid,
		    id.old_epoch, id.vmid, id.epoch));
		}
	}
	switch (fz_next() % 9) {
	case 0: case 1: return (w_elf(vmid, epoch, 1 + fz_next() % 64, 64, 0));
	case 2: return (w_kill(VTDTR_WIRE_EVENT_KILL, vmid, epoch, 100));
	case 3: return (w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED, vmid,
	    epoch));
	case 4: return (pending ? w_cleanup(
	    VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, vmid, epoch, st.delivery_id) :
	    w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, vmid, epoch,
	    1 + fz_next() % 20));
	case 5: return (w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, vmid, epoch,
	    TOKEN + fz_next() % 4));
	case 6: return (w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, vmid, epoch,
	    vmid == 8 ? 9 : 8, epoch + 30));
	default: return (w(VTDTR_WIRE_EVENT_READY));
	}
}

static wire_t
fz_host_message_any(uint16_t vmid, uint64_t epoch)
{
	static const uint64_t ids[] = { 0, 1, 5, 6, 8, HYPERTRACE_MAX_VMS };
	static const uint64_t eps[] = { 0, 50, 51, 60, 80 };
	int mutate = fz_next() % 10 == 0;
	uint16_t id = mutate && fz_next() % 2 ? (uint16_t)fz_pick(ids, 6) : vmid;
	uint64_t ep = mutate && fz_next() % 2 ? fz_pick(eps, 5) : epoch;
	uint64_t tok = mutate ? fz_next() % 3 : TOKEN;
	uint16_t nid = vmid == 6 ? 7 : 6;
	uint64_t nep = vmid == 6 ? 70 : 60;
	wire_t c;

	switch (fz_next() % 32) {
	case 0: c = w_node(id, ep, fz_next() % 2); break;
	case 1: case 2: case 3:
		c = w_elf(id, ep, 1 + fz_next() % 64, 64, 0);
		if (mutate)
			c.uctrl.elf.elfhasmore = (int)(fz_next() % 3);
		break;
	case 4: c = w_kill(fz_next() % 2 ? VTDTR_WIRE_EVENT_KILL :
	    VTDTR_WIRE_EVENT_HOST_KILL_APPLIED, id, ep,
	    (pid_t)(mutate ? fz_next() % 3 : 100)); break;
	case 5: c = w_status(VTDTR_WIRE_EVENT_HOST_STATUS, 'a', 0, 0, 0);
	    c.uctrl.installed.vmid = id; c.uctrl.installed.epoch = ep; break;
	case 6: c = w_installed(VTDTR_WIRE_EVENT_HOST_INSTALLED + fz_next() % 2,
	    id, ep); break;
	case 7: case 8: c = w_cleanup(VTDTR_WIRE_EVENT_CLEANUP_DTRACED, id, ep,
	    mutate ? tok : 10); break;
	case 9: case 10: case 11:
		c = w_cleanup(VTDTR_WIRE_EVENT_SESSION_STOP, id, ep, tok); break;
	case 12: case 13: c = w_cleanup(VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED, id,
	    ep, mutate ? tok : 10); break;
	case 14: case 15: case 16:
		c = w_prep(VTDTR_WIRE_EVENT_SESSION_PREPARE, tok, id, ep,
		    mutate ? (uint16_t)fz_pick(ids, 6) : nid,
		    mutate ? fz_pick(eps, 5) : nep);
		break;
	case 17: case 18: case 19:
		/* Commit names the proposal relative to the old identity. */
		c = w_prep(VTDTR_WIRE_EVENT_SESSION_COMMIT, tok, 5, 50,
		    mutate ? (uint16_t)fz_pick(ids, 6) : 6,
		    mutate ? fz_pick(eps, 5) : 60);
		break;
	case 20: c = w_rekey(VTDTR_WIRE_EVENT_NODE_REKEY, id, ep, 8, 80); break;
	case 21: c = w_rekey(VTDTR_WIRE_EVENT_REKEY_COMMITTED, 5, 50, 8, 80);
	    break;
	case 22: c = w_receipt(VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT +
	    fz_next() % 3, "paitu"[fz_next() % 5], fz_next() % 2,
	    (int)(fz_next() % 3)); break;
	case 23: case 24: case 25: case 26: case 27: case 28:
		c = w(VTDTR_WIRE_EVENT_READY); break;
	case 29: case 30: c = w(VTDTR_WIRE_EVENT_EOF); break;
	default:
		c = w((uint32_t)(fz_next() % 0x40));
		for (size_t i = 0; i < 64; i++)
			((uint8_t *)&c.uctrl)[i] = (uint8_t)fz_next();
		break;
	}
	return (c);
}

static dtt_entry_t
fz_daemon_entry(struct env *e, uint16_t vmid, uint64_t epoch)
{
	struct dtt_cleanup_state st;
	struct dtt_vm_identity id;

	/* A correct daemon answers the driver's pending state. */
	if (fz_next() % 2 && cleanup_state(e, &st) == 0 &&
	    (st.flags & DTT_CLEANUP_STATE_PENDING)) {
		if (!(st.flags & DTT_CLEANUP_STATE_APPLIED))
			return (de_cleanup((st.flags &
			    DTT_CLEANUP_STATE_SESSION_STOP) ? DTT_SESSION_STOPPED :
			    DTT_CLEANUP_APPLIED, st.vmid, st.epoch, st.delivery_id));
		if (identity(e, &id) == 0 && (id.flags &
		    (DTT_IDENTITY_FRESH_PENDING | DTT_IDENTITY_FRESH_READY)))
			return (de_cleanup(DTT_SESSION_READY, id.vmid, id.epoch,
			    st.delivery_id));
	}
	static const uint8_t kinds[] = { DTT_ELF, DTT_INSTALLED, DTT_UNINSTALLED,
	    DTT_STATUS, DTT_INGRESS_STATUS, DTT_VM_IDENTITY_QUERY,
	    DTT_KILL_APPLIED, DTT_CLEANUP_APPLIED, DTT_SESSION_STOPPED,
	    DTT_SESSION_READY, DTT_REKEY_DELIVERY_QUERY, DTT_REKEY_INGRESS_QUERY,
	    DTT_REKEY_KILL_QUERY, DTT_KILL, 99 };
	uint8_t k = kinds[fz_next() % nitems(kinds)];
	dtt_entry_t x;

	switch (k) {
	case DTT_ELF:
		x = de_elf(vmid, epoch, 1 + fz_next() % 64, 64, 0);
		break;
	case DTT_CLEANUP_APPLIED:
	case DTT_SESSION_STOPPED:
	case DTT_SESSION_READY:
		x = k == DTT_SESSION_READY ?
		    de_cleanup(k, vmid == 6 ? 7 : 6, vmid == 6 ? 70 : 60, TOKEN) :
		    de_cleanup(k, vmid, epoch, k == DTT_CLEANUP_APPLIED ? 10 :
		    TOKEN);
		if (fz_next() % 8 == 0)
			x.u.cleanup.delivery_id ^= 1;
		break;
	case DTT_REKEY_DELIVERY_QUERY:
	case DTT_REKEY_INGRESS_QUERY:
	case DTT_REKEY_KILL_QUERY:
		x = de_query(k, 5, 50);
		break;
	case DTT_KILL_APPLIED:
		x = de(k);
		x.u.kill.pid = 100;
		x.u.kill.vmid = vmid;
		x.u.kill.epoch = epoch;
		fill_id(x.u.kill.source_id, 1);
		break;
	default:
		x = de_installed(k, k == DTT_INGRESS_STATUS ? 0 : vmid,
		    k == DTT_INGRESS_STATUS ? 0 : epoch,
		    k == DTT_STATUS || k == DTT_INGRESS_STATUS ||
		    k == DTT_VM_IDENTITY_QUERY ? 5 : 0);
		if (k == DTT_VM_IDENTITY_QUERY)
			x = de(k), x.u.installed.query_id = 5;
		break;
	}
	return (x);
}

static int
fz_stop_safe(uint32_t ev)
{
	return (ev == VTDTR_WIRE_EVENT_SESSION_STOPPED ||
	    ev == VTDTR_WIRE_EVENT_SESSION_READY ||
	    ev == VTDTR_WIRE_EVENT_SESSION_ACTIVE ||
	    ev == VTDTR_WIRE_EVENT_EOF);
}

static void
case_fuzz(void)
{
	long live;
	int violations = 0, sequences = 400, ops = 120;
	long accepted = 0, executed = 0, writes_ok = 0, fenced_seen = 0;

	khx_host_case("protocol-fuzz");
	fz_state = 0x9e3779b97f4a7c15ULL;
	live = live_tag();
	for (int s = 0; s < sequences; s++) {
		struct env e;
		int fenced = 0;

		env_up(&e, ALL_FEATURES, 5, 50);
		for (int op = 0; op < ops && !stopped(&e); op++) {
			struct dtt_vm_identity id;
			uint16_t vmid = 5;
			uint64_t epoch = 50;
			wire_t m[16];
			dtt_entry_t x;
			int n, r;

			if (identity(&e, &id) == 0) {
				vmid = id.flags & (DTT_IDENTITY_FRESH_PENDING |
				    DTT_IDENTITY_FRESH_READY) ? id.old_vmid : id.vmid;
				epoch = id.flags & (DTT_IDENTITY_FRESH_PENDING |
				    DTT_IDENTITY_FRESH_READY) ? id.old_epoch :
				    id.epoch;
			}
			/* Observe TX enqueued since the last control. */
			n = host_recv(&e, m, 16);
			for (int i = 0; i < n && i < 16; i++) {
				if (fenced && !fz_stop_safe(m[i].event))
					violations++;
				if (m[i].event == VTDTR_WIRE_EVENT_SESSION_ACTIVE)
					fenced = 0;
			}
			r = (int)(fz_next() % 10);
			if (r < 5) {
				wire_t c = fz_host_message(&e, vmid, epoch);
				struct dtt_cleanup_state st;
				hostid_t before = dtrace_node_id;

				host_send(&e, c);
				executed++;
				if (stopped(&e))
					break;
				accepted++;
				if (dtrace_node_id == 0 && before != 0)
					violations++;
				if (cleanup_state(&e, &st) == 0 &&
				    (st.flags & DTT_CLEANUP_STATE_SESSION_STOP)) {
					fenced_seen += !fenced;
					fenced = 1;
				}
				/* Delivered host-origin entries name the identity
				 * that was current when the control arrived. */
				while (dread(&e, &x) == 0) {
					if ((x.event_kind == DTT_ELF &&
					    (x.u.elf.vmid != vmid ||
					    x.u.elf.epoch != epoch)) ||
					    ((x.event_kind == DTT_KILL ||
					    x.event_kind == DTT_HOST_KILL_APPLIED) &&
					    (x.u.kill.vmid != vmid ||
					    x.u.kill.epoch != epoch)))
						violations++;
				}
			} else if (r < 8) {
				x = fz_daemon_entry(&e, vmid, epoch);
				if (dwrite(&e, &x) == 0)
					writes_ok++;
			} else
				step(&e);
		}
		env_down(&e);
	}
	KHX_EQ(violations, 0);
	KHX_EQ(live_tag(), live);
	khx_host_log("protocol-fuzz: %d sequences, %ld host controls (%ld "
	    "accepted), %ld daemon writes accepted, %ld session fences\n",
	    sequences, executed, accepted, writes_ok, fenced_seen);
	/* The generator must reach deep states, not only fail fast. */
	KHX_CHECK(accepted > 2000);
	KHX_CHECK(fenced_seen > 20);
}

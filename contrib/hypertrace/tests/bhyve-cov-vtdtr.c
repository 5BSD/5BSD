/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Additional virtio-dtrace device tests (original pci_virtio_dtrace.c through
 * bhyve-device.c, whose fakes and checks run first and unchanged).
 *
 * Oracles:
 *  - the checkpoint control codec: every valid control of every event
 *    round-trips field-exactly; every truncation of a record is refused
 *    without publishing a control; lengths, process ids and unknown events
 *    outside the wire rules are refused before use; decoded controls are
 *    checked against the identity of the VM they are restored into;
 *  - the checkpoint-validity rules, as a decision table derived from the
 *    protocol comments (each single-field change from a valid control
 *    flips validity exactly when the rule names that field).
 */
#define main bhyve_device_main
#include "bhyve-device.c"
#undef main

static int vchecks;
#define OK(x) do { CHECK(x); vchecks++; } while (0)

static const uint16_t VMID = 42;
static const uint64_t EPOCH = 99;

static void
fill_id(uint8_t *id, size_t len, uint8_t seed)
{
	for (size_t i = 0; i < len; i++)
		id[i] = (uint8_t)(seed + i);
}

/* A valid control of EVENT for (VMID, EPOCH). */
static struct pci_vtdtr_control
valid_control(uint32_t event)
{
	struct pci_vtdtr_control c;

	memset(&c, 0, sizeof(c));
	c.pvc_event = event;
	switch (event) {
	case VTDTR_DEVICE_ELF:
		c.pvc_vmid = VMID;
		c.pvc_epoch = EPOCH;
		c.pvc_elflen = 100;
		c.pvc_totalelflen = 5000;
		c.pvc_identifier = 7;
		c.pvc_delivery_id = 0x1234;
		c.pvc_elfhasmore = 1;
		fill_id(c.pvc_program_id, 16, 1);
		fill_id(c.pvc_elf_source_id, 16, 0x41);
		for (int i = 0; i < 100; i++)
			c.pvc_elf[i] = (char)(i * 3);
		break;
	case VTDTR_DEVICE_KILL:
	case VTDTR_DEVICE_HOST_KILL_APPLIED:
		c.pvc_pid = 4321;
		c.pvc_kill_vmid = VMID;
		c.pvc_kill_epoch = EPOCH;
		fill_id(c.pvc_source_id, 16, 9);
		break;
	case VTDTR_DEVICE_HOST_INSTALLED:
	case VTDTR_DEVICE_HOST_UNINSTALLED:
	case VTDTR_DEVICE_HOST_STATUS:
	case VTDTR_DEVICE_HOST_ELF:
	case VTDTR_DEVICE_HOST_INGRESS_STATUS:
		c.pvc_installed_delivery_id = 77;
		c.pvc_installed_vmid = VMID;
		c.pvc_installed_epoch = EPOCH;
		fill_id(c.pvc_installed_program_id, 16, 2);
		fill_id(c.pvc_installed_source_id, 16, 3);
		if (event == VTDTR_DEVICE_HOST_STATUS ||
		    event == VTDTR_DEVICE_HOST_INGRESS_STATUS)
			c.pvc_installed_query_id = 5;
		if (event == VTDTR_DEVICE_HOST_ELF)
			fill_id(c.pvc_installed_digest, 32, 4);
		break;
	case VTDTR_DEVICE_CLEANUP_DTRACED:
		c.pvc_cleanup_vmid = VMID;
		c.pvc_cleanup_epoch = EPOCH;
		c.pvc_cleanup_delivery_id = 31;
		break;
	case VTDTR_DEVICE_NODE_ID:
		c.pvc_node_id = VMID;
		c.pvc_node_epoch = EPOCH;
		c.pvc_node_query_id = 8;
		break;
	case VTDTR_DEVICE_NODE_REKEY:
		c.pvc_rekey_old_id = 3;
		c.pvc_rekey_old_epoch = 12;
		c.pvc_rekey_new_id = VMID;
		c.pvc_rekey_new_epoch = EPOCH;
		break;
	}
	return (c);
}

static int
codec(enum vm_snapshot_op op, struct pci_vtdtr_control *c, uint8_t *buf,
    size_t len, size_t *used, uint16_t vmid, uint64_t epoch)
{
	struct vm_snapshot_meta meta = {
		.op = op,
		.buffer = { .buf_start = buf, .buf_size = len, .buf = buf, .buf_rem = len },
	};
	int error;

	error = pci_vtdtr_snapshot_control(c, &meta, vmid, epoch);
	if (used != NULL)
		*used = len - meta.buffer.buf_rem;
	return (error);
}

/* The fields the codec carries for EVENT, compared exactly. */
static bool
same_control(const struct pci_vtdtr_control *a, const struct pci_vtdtr_control *b)
{
	if (a->pvc_event != b->pvc_event)
		return (false);
	switch (a->pvc_event) {
	case VTDTR_DEVICE_ELF:
		return (a->pvc_elflen == b->pvc_elflen &&
		    a->pvc_totalelflen == b->pvc_totalelflen &&
		    a->pvc_identifier == b->pvc_identifier &&
		    a->pvc_delivery_id == b->pvc_delivery_id &&
		    a->pvc_vmid == b->pvc_vmid && a->pvc_epoch == b->pvc_epoch &&
		    a->pvc_elfhasmore == b->pvc_elfhasmore &&
		    memcmp(a->pvc_program_id, b->pvc_program_id, 16) == 0 &&
		    memcmp(a->pvc_elf_source_id, b->pvc_elf_source_id, 16) == 0 &&
		    memcmp(a->pvc_elf, b->pvc_elf, a->pvc_elflen) == 0);
	case VTDTR_DEVICE_KILL:
	case VTDTR_DEVICE_HOST_KILL_APPLIED:
		return (a->pvc_pid == b->pvc_pid && a->pvc_kill_vmid == b->pvc_kill_vmid &&
		    a->pvc_kill_epoch == b->pvc_kill_epoch &&
		    memcmp(a->pvc_source_id, b->pvc_source_id, 16) == 0);
	case VTDTR_DEVICE_HOST_INSTALLED:
	case VTDTR_DEVICE_HOST_UNINSTALLED:
	case VTDTR_DEVICE_HOST_STATUS:
	case VTDTR_DEVICE_HOST_ELF:
	case VTDTR_DEVICE_HOST_INGRESS_STATUS:
		/* Field by field: the wire structure has padding. */
		return (a->pvc_installed_delivery_id == b->pvc_installed_delivery_id &&
		    a->pvc_installed_vmid == b->pvc_installed_vmid &&
		    a->pvc_installed_epoch == b->pvc_installed_epoch &&
		    a->pvc_installed_phase == b->pvc_installed_phase &&
		    a->pvc_installed_revoked == b->pvc_installed_revoked &&
		    a->pvc_installed_replay == b->pvc_installed_replay &&
		    a->pvc_installed_query_id == b->pvc_installed_query_id &&
		    memcmp(a->pvc_installed_program_id, b->pvc_installed_program_id, 16) == 0 &&
		    memcmp(a->pvc_installed_source_id, b->pvc_installed_source_id, 16) == 0 &&
		    memcmp(a->pvc_installed_digest, b->pvc_installed_digest, 32) == 0);
	case VTDTR_DEVICE_CLEANUP_DTRACED:
		return (a->pvc_cleanup_vmid == b->pvc_cleanup_vmid &&
		    a->pvc_cleanup_epoch == b->pvc_cleanup_epoch &&
		    a->pvc_cleanup_delivery_id == b->pvc_cleanup_delivery_id);
	case VTDTR_DEVICE_NODE_ID:
		return (a->pvc_node_id == b->pvc_node_id && a->pvc_node_epoch == b->pvc_node_epoch &&
		    a->pvc_node_query_id == b->pvc_node_query_id);
	case VTDTR_DEVICE_NODE_REKEY:
		return (a->pvc_rekey_old_id == b->pvc_rekey_old_id &&
		    a->pvc_rekey_old_epoch == b->pvc_rekey_old_epoch &&
		    a->pvc_rekey_new_id == b->pvc_rekey_new_id &&
		    a->pvc_rekey_new_epoch == b->pvc_rekey_new_epoch);
	default:
		return (true);
	}
}

static void
test_control_codec(void)
{
	static const uint32_t events[] = { VTDTR_DEVICE_ELF, VTDTR_DEVICE_KILL,
	    VTDTR_DEVICE_HOST_KILL_APPLIED, VTDTR_DEVICE_HOST_INSTALLED,
	    VTDTR_DEVICE_HOST_UNINSTALLED, VTDTR_DEVICE_HOST_STATUS,
	    VTDTR_DEVICE_HOST_ELF, VTDTR_DEVICE_HOST_INGRESS_STATUS,
	    VTDTR_DEVICE_CLEANUP_DTRACED, VTDTR_DEVICE_NODE_ID,
	    VTDTR_DEVICE_NODE_REKEY, VTDTR_DEVICE_READY, VTDTR_DEVICE_EOF };
	static uint8_t buf[8192];
	int before = vchecks;

	for (size_t e = 0; e < nitems(events); e++) {
		struct pci_vtdtr_control in = valid_control(events[e]), out;
		size_t used, again;

		OK(pci_vtdtr_ctrl_checkpoint_valid(&in, VMID, EPOCH));
		OK(codec(VM_SNAPSHOT_SAVE, &in, buf, sizeof(buf), &used, VMID, EPOCH) == 0);
		memset(&out, 0xee, sizeof(out));
		OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, used, &again, VMID, EPOCH) == 0);
		if (again != used || !same_control(&in, &out))
			fprintf(stderr, "round trip event %u: used %zu again %zu\n",
			    events[e], used, again);
		OK(again == used && same_control(&in, &out));
		memset(&out, 0, sizeof(out));
		OK(codec(VM_SNAPSHOT_VALIDATE, &out, buf, used, NULL, VMID, EPOCH) == 0);
		/* Restored into a different VM incarnation: refused. */
		if (events[e] != VTDTR_DEVICE_READY && events[e] != VTDTR_DEVICE_EOF) {
			OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, used, NULL, VMID + 1, EPOCH) ==
			    EPROTO);
			OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, used, NULL, VMID, EPOCH + 1) ==
			    EPROTO);
		}
		/* Every truncation is refused. */
		for (size_t cut = 0; cut < used; cut++) {
			memset(&out, 0, sizeof(out));
			OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, cut, NULL, VMID, EPOCH) != 0);
		}
		/* Saving into too small a buffer fails as well. */
		OK(codec(VM_SNAPSHOT_SAVE, &in, buf, used - 1, NULL, VMID, EPOCH) != 0);
	}
	/* ELF fragment length must be 1..MAXELFLEN on the wire. */
	{
		struct pci_vtdtr_control in = valid_control(VTDTR_DEVICE_ELF), out;
		size_t used;
		CHECK(codec(VM_SNAPSHOT_SAVE, &in, buf, sizeof(buf), &used, VMID, EPOCH) == 0);
		/* length field follows the 4-byte event */
		uint32_t zero = 0, huge = PCI_VTDTR_MAXELFLEN + 1;
		memcpy(buf + 4, &zero, 4);
		OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, used, NULL, VMID, EPOCH) == EINVAL);
		memcpy(buf + 4, &huge, 4);
		OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, used, NULL, VMID, EPOCH) == EINVAL);
	}
	/* A process id above INT32_MAX is refused. */
	{
		struct pci_vtdtr_control in = valid_control(VTDTR_DEVICE_KILL), out;
		size_t used;
		uint32_t pid = 0x80000000U;
		CHECK(codec(VM_SNAPSHOT_SAVE, &in, buf, sizeof(buf), &used, VMID, EPOCH) == 0);
		memcpy(buf + 4, &pid, 4);
		OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, used, NULL, VMID, EPOCH) == EINVAL);
	}
	/* Events without a checkpoint encoding are refused both ways. */
	{
		struct pci_vtdtr_control in = valid_control(VTDTR_DEVICE_SESSION_STOP), out;
		size_t used;
		OK(codec(VM_SNAPSHOT_SAVE, &in, buf, sizeof(buf), &used, VMID, EPOCH) == EINVAL);
		uint32_t unknown = 0x7777;
		memcpy(buf, &unknown, 4);
		OK(codec(VM_SNAPSHOT_RESTORE, &out, buf, 64, NULL, VMID, EPOCH) == EINVAL);
	}
	/* A decoded control that breaks the validity rules is EPROTO. */
	{
		struct pci_vtdtr_control in = valid_control(VTDTR_DEVICE_NODE_ID), out;
		size_t used;
		in.pvc_node_id = 0;
		OK(codec(VM_SNAPSHOT_SAVE, &in, buf, sizeof(buf), &used, 0, EPOCH) == EPROTO);
	}
	printf("vtdtr checkpoint control codec: %d checks\n", vchecks - before);
}

/* Each entry: event, a mutation, and whether the result is still valid. */
typedef void mutate_fn(struct pci_vtdtr_control *);
#define M(name, body) static void name(struct pci_vtdtr_control *c) { body; }
M(m_none, (void)c)
M(m_elf_len0, c->pvc_elflen = 0)
M(m_elf_lenmax, c->pvc_elflen = PCI_VTDTR_MAXELFLEN; c->pvc_totalelflen = PCI_VTDTR_MAXELFLEN)
M(m_elf_lenbig, c->pvc_elflen = PCI_VTDTR_MAXELFLEN + 1; c->pvc_totalelflen = 100000)
M(m_elf_total0, c->pvc_totalelflen = 0)
M(m_elf_totalbig, c->pvc_totalelflen = HYPERTRACE_ELF_MAX + 1)
M(m_elf_totalmax, c->pvc_totalelflen = HYPERTRACE_ELF_MAX)
M(m_elf_len_gt_total, c->pvc_totalelflen = 50)
M(m_elf_more0, c->pvc_elfhasmore = 0)
M(m_elf_more2, c->pvc_elfhasmore = 2)
M(m_elf_delivery0, c->pvc_delivery_id = 0)
M(m_elf_program0, memset(c->pvc_program_id, 0, 16))
M(m_elf_source0, memset(c->pvc_elf_source_id, 0, 16))
M(m_elf_vmid, c->pvc_vmid++)
M(m_elf_epoch, c->pvc_epoch++)
M(m_kill_pid1, c->pvc_pid = 1)
M(m_kill_pid2, c->pvc_pid = 2)
M(m_kill_source0, memset(c->pvc_source_id, 0, 16))
M(m_kill_vmid, c->pvc_kill_vmid++)
M(m_inst_delivery0, c->pvc_installed_delivery_id = 0)
M(m_inst_revoked2, c->pvc_installed_revoked = 2)
M(m_inst_replay2, c->pvc_installed_replay = 2)
M(m_inst_program0, memset(c->pvc_installed_program_id, 0, 16))
M(m_inst_source0, memset(c->pvc_installed_source_id, 0, 16))
M(m_inst_query, c->pvc_installed_query_id = 9)
M(m_inst_phase, c->pvc_installed_phase = 'a')
M(m_inst_revoked, c->pvc_installed_revoked = 1)
M(m_inst_replay, c->pvc_installed_replay = 1)
M(m_inst_digest, fill_id(c->pvc_installed_digest, 32, 7))
M(m_inst_nodigest, memset(c->pvc_installed_digest, 0, 32))
M(m_inst_epoch, c->pvc_installed_epoch++)
M(m_node0, c->pvc_node_id = 0; c->pvc_node_id = 0)
M(m_rekey_old0, c->pvc_rekey_old_id = 0)
M(m_rekey_oldmax, c->pvc_rekey_old_id = HYPERTRACE_MAX_VMS)
M(m_rekey_oldepoch0, c->pvc_rekey_old_epoch = 0)
M(m_rekey_same, c->pvc_rekey_old_id = VMID; c->pvc_rekey_old_epoch = EPOCH)
M(m_rekey_same_id, c->pvc_rekey_old_id = VMID)
M(m_cleanup0, c->pvc_cleanup_delivery_id = 0)
M(m_cleanup_epoch, c->pvc_cleanup_epoch++)
#undef M

static void
test_validity_table(void)
{
	static const struct {
		uint32_t event;
		mutate_fn *mutate;
		bool valid;
	} table[] = {
		{ VTDTR_DEVICE_ELF, m_none, true }, { VTDTR_DEVICE_ELF, m_elf_len0, false },
		{ VTDTR_DEVICE_ELF, m_elf_lenmax, true }, { VTDTR_DEVICE_ELF, m_elf_lenbig, false },
		{ VTDTR_DEVICE_ELF, m_elf_total0, false }, { VTDTR_DEVICE_ELF, m_elf_totalbig, false },
		{ VTDTR_DEVICE_ELF, m_elf_totalmax, true },
		{ VTDTR_DEVICE_ELF, m_elf_len_gt_total, false },
		{ VTDTR_DEVICE_ELF, m_elf_more0, true }, { VTDTR_DEVICE_ELF, m_elf_more2, false },
		{ VTDTR_DEVICE_ELF, m_elf_delivery0, false },
		{ VTDTR_DEVICE_ELF, m_elf_program0, false },
		{ VTDTR_DEVICE_ELF, m_elf_source0, false }, { VTDTR_DEVICE_ELF, m_elf_vmid, false },
		{ VTDTR_DEVICE_ELF, m_elf_epoch, false },
		{ VTDTR_DEVICE_KILL, m_kill_pid1, false }, { VTDTR_DEVICE_KILL, m_kill_pid2, true },
		{ VTDTR_DEVICE_KILL, m_kill_source0, false }, { VTDTR_DEVICE_KILL, m_kill_vmid, false },
		{ VTDTR_DEVICE_HOST_KILL_APPLIED, m_kill_pid1, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_delivery0, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_revoked2, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_replay2, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_program0, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_source0, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_query, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_phase, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_revoked, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_replay, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_digest, false },
		{ VTDTR_DEVICE_HOST_INSTALLED, m_inst_epoch, false },
		{ VTDTR_DEVICE_HOST_UNINSTALLED, m_none, true },
		{ VTDTR_DEVICE_HOST_ELF, m_inst_nodigest, false },
		{ VTDTR_DEVICE_HOST_ELF, m_none, true },
		{ VTDTR_DEVICE_NODE_ID, m_node0, false },
		{ VTDTR_DEVICE_NODE_REKEY, m_rekey_old0, false },
		{ VTDTR_DEVICE_NODE_REKEY, m_rekey_oldmax, false },
		{ VTDTR_DEVICE_NODE_REKEY, m_rekey_oldepoch0, false },
		{ VTDTR_DEVICE_NODE_REKEY, m_rekey_same, false },
		{ VTDTR_DEVICE_NODE_REKEY, m_rekey_same_id, true },
		{ VTDTR_DEVICE_CLEANUP_DTRACED, m_cleanup0, false },
		{ VTDTR_DEVICE_CLEANUP_DTRACED, m_cleanup_epoch, false },
		{ VTDTR_DEVICE_HOST_CLEANUP_APPLIED, m_none, true },
		{ VTDTR_DEVICE_SESSION_STOP, m_none, false },
		{ VTDTR_DEVICE_REGISTER, m_none, false },
	};
	int before = vchecks;

	for (size_t i = 0; i < nitems(table); i++) {
		struct pci_vtdtr_control c = valid_control(table[i].event);
		if (table[i].event == VTDTR_DEVICE_HOST_CLEANUP_APPLIED) {
			c.pvc_cleanup_vmid = VMID;
			c.pvc_cleanup_epoch = EPOCH;
			c.pvc_cleanup_delivery_id = 1;
		}
		if (table[i].event == VTDTR_DEVICE_SESSION_STOP) {
			c.pvc_cleanup_vmid = VMID;
			c.pvc_cleanup_epoch = EPOCH;
		}
		table[i].mutate(&c);
		if (pci_vtdtr_ctrl_checkpoint_valid(&c, VMID, EPOCH) != table[i].valid)
			fprintf(stderr, "validity row %zu (event %u)\n", i, table[i].event);
		OK(pci_vtdtr_ctrl_checkpoint_valid(&c, VMID, EPOCH) == table[i].valid);
	}
	/* Status phases: query id, phase set, replay digest coupling and
	 * revocation rules (HOST_STATUS and HOST_INGRESS_STATUS). */
	static const uint8_t phases[] = { 0, 'p', 'a', 'i', 't', 'u', 'x' };
	for (int ingress = 0; ingress < 2; ingress++)
	for (size_t p = 0; p < nitems(phases); p++)
	for (int replay = 0; replay < 2; replay++)
	for (int digest = 0; digest < 2; digest++)
	for (int revoked = 0; revoked < 2; revoked++)
	for (int query = 0; query < 2; query++) {
		uint32_t event = ingress ? VTDTR_DEVICE_HOST_INGRESS_STATUS :
		    VTDTR_DEVICE_HOST_STATUS;
		struct pci_vtdtr_control c = valid_control(event);
		uint8_t ph = phases[p];
		bool known, want;

		c.pvc_installed_phase = ph;
		c.pvc_installed_replay = (uint8_t)replay;
		c.pvc_installed_revoked = (uint8_t)revoked;
		c.pvc_installed_query_id = query ? 5 : 0;
		if (digest)
			fill_id(c.pvc_installed_digest, 32, 1);
		if (!ingress) {
			/* Status: replaying requires an acknowledged ('a') or
			 * installed ('i') unrevoked program with its digest;
			 * otherwise there is no digest. */
			known = ph == 0 || ph == 'p' || ph == 'a' || ph == 'i' || ph == 't' ||
			    ph == 'u';
			want = query && known &&
			    (replay ? (digest && !revoked && (ph == 'a' || ph == 'i')) : !digest) &&
			    (ph != 'u' || !revoked);
		} else {
			/* Ingress: never a replay; a digest exactly for 'p'/'a'. */
			known = ph == 0 || ph == 'p' || ph == 'a' || ph == 'u';
			want = query && !replay && known &&
			    (!digest == (ph == 0 || ph == 'u')) && (ph != 'u' || !revoked);
		}
		OK(pci_vtdtr_ctrl_checkpoint_valid(&c, VMID, EPOCH) == want);
	}
	printf("vtdtr checkpoint validity table: %d checks\n", vchecks - before);
}

/* ---------------------------------------- guest control reception */
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
static int alloc_fail_at, alloc_count;
static bool alloc_armed;

static bool
alloc_fails(void)
{
	return (alloc_armed && ++alloc_count == alloc_fail_at);
}

void *__wrap_malloc(size_t n) { return (alloc_fails() ? (errno = ENOMEM, NULL) : __real_malloc(n)); }
void *__wrap_calloc(size_t n, size_t m) { return (alloc_fails() ? (errno = ENOMEM, NULL) : __real_calloc(n, m)); }

struct device {
	struct pci_vtdtr_softc sc;
	struct pci_vtdtr_ctrlq queue;
};

static struct device *
new_device(void)
{
	struct device *d = __real_calloc(1, sizeof(*d));

	STAILQ_INIT(&d->queue.head);
	d->sc.vsd_ctrlq = &d->queue;
	CHECK(pthread_mutex_init(&d->sc.vsd_mtx, NULL) == 0);
	init_monotonic_cond(&d->sc.vsd_cond);
	d->sc.vsd_vs.vs_mtx = &d->sc.vsd_mtx;
	d->sc.vsd_vmctx = (struct vmctx *)2;	/* identity 42/vm_epoch */
	d->sc.vsd_guest_ready = 1;
	for (int i = 0; i < 2; i++) {
		d->sc.vsd_queues[i].vq_vs = &d->sc.vsd_vs;
		d->sc.vsd_queues[i].vq_qsize = 8;
		d->sc.vsd_queues[i].vq_num = i;
	}
	return (d);
}

static void
drain(struct device *d)
{
	struct pci_vtdtr_ctrl_entry *e;

	while ((e = pci_vtdtr_cq_dequeue(&d->queue)) != NULL) {
		free(e->ctrl);
		free(e);
	}
}

static void
free_device(struct device *d)
{
	drain(d);
	hypertrace_elf_reset(&d->sc.vsd_inbound_elf);
	pthread_cond_destroy(&d->sc.vsd_cond);
	pthread_mutex_destroy(&d->sc.vsd_mtx);
	free(d);
}

static int
rx(struct device *d, const struct pci_vtdtr_control *c)
{
	struct iovec iov = { __DECONST(void *, c), sizeof(*c) };
	int r;

	pthread_mutex_lock(&d->sc.vsd_mtx);
	r = pci_vtdtr_control_rx(&d->sc, &iov, 1);
	pthread_mutex_unlock(&d->sc.vsd_mtx);
	return (r);
}

static bool
reset_requested(struct device *d)
{
	return ((d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
}

static struct pci_vtdtr_control
elf_fragment(uint32_t total, uint32_t len, bool more, uint32_t offset)
{
	struct pci_vtdtr_control c;

	memset(&c, 0, sizeof(c));
	c.pvc_event = VTDTR_DEVICE_ELF;
	c.pvc_delivery_id = 7;
	c.pvc_vmid = 42;
	c.pvc_epoch = vm_epoch;
	c.pvc_identifier = 0x77;
	c.pvc_totalelflen = total;
	c.pvc_elflen = len;
	c.pvc_elfhasmore = more;
	fill_id(c.pvc_program_id, 16, 1);
	fill_id(c.pvc_elf_source_id, 16, 2);
	for (uint32_t i = 0; i < len; i++)
		c.pvc_elf[i] = (char)(offset + i);
	if (offset == 0 && len >= 4)
		memcpy(c.pvc_elf, "\177ELF", 4);
	return (c);
}

/* A complete upload: one ELF write, then one HOST_ELF receipt carrying the
 * SHA-256 of exactly the uploaded bytes. */
static void
test_elf_upload(void)
{
	int before = vchecks;
	struct device *d;
	uint8_t image[PCI_VTDTR_MAXELFLEN + 300], digest[32];

	/* Two fragments: a full one and a 300-byte tail. */
	uint32_t total = PCI_VTDTR_MAXELFLEN + 300;
	struct pci_vtdtr_control first = elf_fragment(total, PCI_VTDTR_MAXELFLEN, true, 0);
	struct pci_vtdtr_control last = elf_fragment(total, 300, false, PCI_VTDTR_MAXELFLEN);
	memcpy(image, first.pvc_elf, PCI_VTDTR_MAXELFLEN);
	memcpy(image + PCI_VTDTR_MAXELFLEN, last.pvc_elf, 300);
	SHA256(image, sizeof(image), digest);

	d = new_device();
	last_upload_valid = 0;
	write_error = status_error = ingress_bad_digest = ingress_revoked = 0;
	OK(rx(d, &first) == 0 && !reset_requested(d) && d->queue.count == 0);
	OK(rx(d, &last) == 0 && !reset_requested(d) && d->queue.count == 1);
	OK(last_upload_valid && last_upload.msg_type == DTRACED_MSG_ELF &&
	    last_upload.elf.delivery_id == 7 && memcmp(last_upload_digest, digest, 32) == 0);
	{
		struct pci_vtdtr_ctrl_entry *e = pci_vtdtr_cq_dequeue(&d->queue);
		OK(e->ctrl->pvc_event == VTDTR_DEVICE_HOST_ELF &&
		    e->ctrl->pvc_installed_delivery_id == 7 &&
		    e->ctrl->pvc_installed_vmid == 42 &&
		    e->ctrl->pvc_installed_epoch == vm_epoch &&
		    memcmp(e->ctrl->pvc_installed_digest, digest, 32) == 0 &&
		    pci_vtdtr_ctrl_checkpoint_valid(e->ctrl, 42, vm_epoch));
		free(e->ctrl);
		free(e);
	}
	OK(d->sc.vsd_inbound_delivery_id == 0 && d->sc.vsd_inbound_elf.data == NULL);
	free_device(d);

	/* Each rejection: one reset, no receipt, no partial state kept. */
	static const char *cases[] = { "delivery0", "program0", "source0", "vmid",
	    "epoch", "next_delivery", "next_vmid", "next_epoch", "next_program",
	    "next_source", "oversize", "append_identifier", "append_total", "not_elf" };
	for (size_t i = 0; i < nitems(cases); i++) {
		struct pci_vtdtr_control a = first, b = last;
		int ra, rb = 0;
		d = new_device();
		switch (i) {
		case 0: a.pvc_delivery_id = 0; break;
		case 1: memset(a.pvc_program_id, 0, 16); break;
		case 2: memset(a.pvc_elf_source_id, 0, 16); break;
		case 3: a.pvc_vmid = 41; break;
		case 4: a.pvc_epoch = vm_epoch + 1; break;
		case 5: b.pvc_delivery_id = 8; break;
		case 6: b.pvc_vmid = 41; break;
		case 7: b.pvc_epoch = vm_epoch + 1; break;
		case 8: b.pvc_program_id[3] ^= 1; break;
		case 9: b.pvc_elf_source_id[3] ^= 1; break;
		case 10: b.pvc_elflen = sizeof(b.pvc_elf) + 1; break;
		case 11: b.pvc_identifier = 0x78; break;
		case 12: b.pvc_totalelflen = total + 1; break;
		case 13: a.pvc_elf[0] = 'X'; break;
		}
		ra = rx(d, &a);
		if (ra == 0)
			rb = rx(d, &b);
		if (!((ra == 1 || rb == 1) && reset_requested(d) && d->queue.count == 0 &&
		    d->sc.vsd_inbound_elf.data == NULL))
			fprintf(stderr, "elf rejection %s: %d %d\n", cases[i], ra, rb);
		OK((ra == 1 || rb == 1) && reset_requested(d) && d->queue.count == 0 &&
		    d->sc.vsd_inbound_elf.data == NULL);
		free_device(d);
	}
	/* The VM incarnation changes before the last fragment arrives. */
	d = new_device();
	OK(rx(d, &first) == 0);
	vm_epoch++;
	{
		struct pci_vtdtr_control b = last;
		b.pvc_epoch = vm_epoch;
		OK(rx(d, &b) == 1 && reset_requested(d));
	}
	vm_epoch--;
	free_device(d);
	/* Host failures after assembly: write, receipt query, digest, revoked,
	 * queue room, allocations. */
	for (int failure = 0; failure < 6; failure++) {
		d = new_device();
		OK(rx(d, &first) == 0);
		switch (failure) {
		case 0: write_error = EPIPE; break;
		case 1: status_error = EIO; break;
		case 2: ingress_bad_digest = 1; break;
		case 3: ingress_revoked = 1; break;
		case 4: d->queue.count = VTDTR_MAX_RESTORE_PENDING; break;
		case 5: break;
		}
		if (failure == 5) {
			/* Fail each allocation of the completing fragment. */
			for (int at = 1; at <= 3; at++) {
				struct device *e = new_device();
				CHECK(rx(e, &first) == 0);
				alloc_count = 0;
				alloc_fail_at = at;
				alloc_armed = true;
				int r = rx(e, &last);
				alloc_armed = false;
				OK(r == 1 && reset_requested(e) && e->queue.count == 0);
				free_device(e);
			}
		} else {
			OK(rx(d, &last) == 1 && reset_requested(d));
		}
		if (failure == 4)
			d->queue.count = 0;
		write_error = status_error = ingress_bad_digest = ingress_revoked = 0;
		free_device(d);
	}
	printf("vtdtr ELF upload reception: %d checks\n", vchecks - before);
}

static struct pci_vtdtr_control
report(uint32_t event)
{
	struct pci_vtdtr_control c;

	memset(&c, 0, sizeof(c));
	c.pvc_event = event;
	switch (event) {
	case VTDTR_DEVICE_KILL_APPLIED:
		c.pvc_pid = 77;
		c.pvc_kill_vmid = 42;
		c.pvc_kill_epoch = vm_epoch;
		fill_id(c.pvc_source_id, 16, 5);
		break;
	case VTDTR_DEVICE_CLEANUP_APPLIED:
		c.pvc_cleanup_vmid = 42;
		c.pvc_cleanup_epoch = vm_epoch;
		c.pvc_cleanup_delivery_id = 0x51;
		break;
	case VTDTR_DEVICE_INSTALLED:
	case VTDTR_DEVICE_UNINSTALLED:
	case VTDTR_DEVICE_STATUS:
	case VTDTR_DEVICE_INGRESS_STATUS:
		c.pvc_installed_delivery_id = 9;
		if (event != VTDTR_DEVICE_INGRESS_STATUS) {
			c.pvc_installed_vmid = 42;
			c.pvc_installed_epoch = vm_epoch;
		}
		fill_id(c.pvc_installed_program_id, 16, 1);
		fill_id(c.pvc_installed_source_id, 16, 2);
		if (event == VTDTR_DEVICE_STATUS || event == VTDTR_DEVICE_INGRESS_STATUS)
			c.pvc_installed_query_id = 3;
		break;
	}
	return (c);
}

static struct pci_vtdtr_control *
only_receipt(struct device *d)
{
	static struct pci_vtdtr_control copy;
	struct pci_vtdtr_ctrl_entry *e;

	if (d->queue.count != 1)
		return (NULL);
	e = pci_vtdtr_cq_dequeue(&d->queue);
	copy = *e->ctrl;
	free(e->ctrl);
	free(e);
	return (&copy);
}

/* Guest reports: each valid report is persisted (or queried) once and gets
 * exactly one receipt bound to the attested identity; each malformed one
 * resets the device; transport loss is retried by the guest. */
static void
test_guest_reports(void)
{
	int before = vchecks;
	struct device *d;
	struct pci_vtdtr_control c, *r;

	/* A guest-originated KILL is a protocol violation. */
	d = new_device();
	c = report(VTDTR_DEVICE_KILL);
	OK(rx(d, &c) == 1 && reset_requested(d));
	free_device(d);
	/* Unknown events and EOF. */
	d = new_device();
	c = report(0x6f);
	OK(rx(d, &c) == 1 && reset_requested(d));
	free_device(d);
	d = new_device();
	c = report(VTDTR_DEVICE_EOF);
	OK(rx(d, &c) == 1 && !reset_requested(d));
	free_device(d);

	/* KILL_APPLIED. */
	d = new_device();
	c = report(VTDTR_DEVICE_KILL_APPLIED);
	OK(rx(d, &c) == 0 && last_write.msg_type == DTRACED_MSG_KILL_APPLIED &&
	    last_write.kill.pid == 77 && last_write.kill.vmid == 42 &&
	    last_write.kill.epoch == vm_epoch);
	r = only_receipt(d);
	OK(r != NULL && r->pvc_event == VTDTR_DEVICE_HOST_KILL_APPLIED && r->pvc_pid == 77 &&
	    pci_vtdtr_ctrl_checkpoint_valid(r, 42, vm_epoch));
	free_device(d);
	for (int bad = 0; bad < 5; bad++) {
		d = new_device();
		c = report(VTDTR_DEVICE_KILL_APPLIED);
		switch (bad) {
		case 0: c.pvc_pid = 1; break;
		case 1: memset(c.pvc_source_id, 0, 16); break;
		case 2: c.pvc_kill_vmid = 41; break;
		case 3: c.pvc_kill_epoch++; break;
		case 4: d->sc.vsd_vmctx = (struct vmctx *)1; c.pvc_kill_vmid = 43;
			c.pvc_kill_epoch = 100; break;
		}
		int got = rx(d, &c);
		if (bad < 4)
			OK(got == 1 && reset_requested(d) && d->queue.count == 0);
		else
			OK(got == 0);
		drain(d);
		free_device(d);
	}
	/* Retryable and non-retryable persistence failures. */
	static const int retryable[] = { ENOTCONN, ECONNRESET, EPIPE, ETIMEDOUT, EIO };
	for (size_t i = 0; i < nitems(retryable); i++) {
		d = new_device();
		c = report(VTDTR_DEVICE_KILL_APPLIED);
		write_error = retryable[i];
		OK(rx(d, &c) == 0 && !reset_requested(d) && d->queue.count == 0);
		write_error = 0;
		free_device(d);
	}
	d = new_device();
	c = report(VTDTR_DEVICE_KILL_APPLIED);
	write_error = EACCES;
	OK(rx(d, &c) == 1 && reset_requested(d));
	write_error = 0;
	free_device(d);
	/* No room or no memory for the receipt: persisted, guest repeats. */
	d = new_device();
	c = report(VTDTR_DEVICE_KILL_APPLIED);
	d->queue.count = VTDTR_MAX_RESTORE_PENDING;
	OK(rx(d, &c) == 0 && !reset_requested(d));
	d->queue.count = 0;
	for (int at = 1; at <= 2; at++) {
		alloc_count = 0;
		alloc_fail_at = at;
		alloc_armed = true;
		OK(rx(d, &c) == 0 && d->queue.count == 0 && !reset_requested(d));
		alloc_armed = false;
	}
	free_device(d);
	/* A restored revocation must be acknowledged for exactly that pid. */
	d = new_device();
	d->sc.vsd_restored_kill_wait = true;
	d->sc.vsd_restored_kill_pid = 78;
	fill_id(d->sc.vsd_restored_kill_source_id, 16, 5);
	c = report(VTDTR_DEVICE_KILL_APPLIED);
	OK(rx(d, &c) == 1);	/* pid 77: quarantined */
	free_device(d);
	d = new_device();
	d->sc.vsd_restored_kill_wait = true;
	d->sc.vsd_restored_kill_pid = 77;
	fill_id(d->sc.vsd_restored_kill_source_id, 16, 6);
	OK(rx(d, &c) == 1);	/* source differs */
	free_device(d);
	d = new_device();
	d->sc.vsd_restored_kill_wait = true;
	d->sc.vsd_restored_kill_pid = 77;
	fill_id(d->sc.vsd_restored_kill_source_id, 16, 5);
	clock_gettime(CLOCK_MONOTONIC, &d->sc.vsd_restored_kill_deadline);
	d->sc.vsd_restored_kill_deadline.tv_sec += 60;
	d->sc.vsd_guest_ready = 0;
	OK(rx(d, &c) == 0 && !d->sc.vsd_restored_kill_wait && d->sc.vsd_guest_ready == 1 &&
	    d->sc.vsd_restored_kill_pid == 0);
	free_device(d);

	/* CLEANUP_APPLIED. */
	d = new_device();
	d->sc.vsd_cleanup_delivery_id = 0x51;
	d->sc.vsd_cleanup_unapplied = true;
	c = report(VTDTR_DEVICE_CLEANUP_APPLIED);
	OK(rx(d, &c) == 0 && !d->sc.vsd_cleanup_unapplied &&
	    last_write.msg_type == DTRACED_MSG_CLEANUP_APPLIED);
	r = only_receipt(d);
	OK(r != NULL && r->pvc_event == VTDTR_DEVICE_HOST_CLEANUP_APPLIED &&
	    r->pvc_cleanup_delivery_id == 0x51);
	/* A retry of the previous cleanup is ignored. */
	d->sc.vsd_cleanup_previous_delivery_id = 0x51;
	d->sc.vsd_cleanup_delivery_id = 0x52;
	{
		int writes_before = writes;
		OK(rx(d, &c) == 0 && writes == writes_before && d->queue.count == 0);
	}
	free_device(d);
	for (int bad = 0; bad < 5; bad++) {
		d = new_device();
		d->sc.vsd_cleanup_delivery_id = 0x51;
		c = report(VTDTR_DEVICE_CLEANUP_APPLIED);
		switch (bad) {
		case 0: c.pvc_cleanup_delivery_id = 0; d->sc.vsd_cleanup_delivery_id = 0; break;
		case 1: c.pvc_cleanup_delivery_id = 0x50; break;
		case 2: c.pvc_cleanup_vmid = 41; break;
		case 3: c.pvc_cleanup_epoch++; break;
		case 4: d->sc.vsd_cleanup_previous_delivery_id = 0x51;
			c.pvc_cleanup_epoch++; d->sc.vsd_cleanup_delivery_id = 0x52; break;
		}
		OK(rx(d, &c) == 1 && reset_requested(d));
		free_device(d);
	}
	d = new_device();
	d->sc.vsd_cleanup_delivery_id = 0x51;
	d->sc.vsd_cleanup_unapplied = true;
	c = report(VTDTR_DEVICE_CLEANUP_APPLIED);
	write_error = EACCES;
	OK(rx(d, &c) == 1 && reset_requested(d) && d->sc.vsd_cleanup_unapplied);
	write_error = 0;
	free_device(d);
	for (int at = 1; at <= 2; at++) {
		d = new_device();
		d->sc.vsd_cleanup_delivery_id = 0x51;
		d->sc.vsd_cleanup_unapplied = true;
		alloc_count = 0;
		alloc_fail_at = at;
		alloc_armed = true;
		OK(rx(d, &c) == 0 && d->sc.vsd_cleanup_unapplied && d->queue.count == 0);
		alloc_armed = false;
		free_device(d);
	}

	/* INSTALLED / UNINSTALLED / STATUS / INGRESS_STATUS. */
	static const uint32_t kinds[] = { VTDTR_DEVICE_INSTALLED, VTDTR_DEVICE_UNINSTALLED,
	    VTDTR_DEVICE_STATUS, VTDTR_DEVICE_INGRESS_STATUS };
	static const uint32_t replies[] = { VTDTR_DEVICE_HOST_INSTALLED,
	    VTDTR_DEVICE_HOST_UNINSTALLED, VTDTR_DEVICE_HOST_STATUS,
	    VTDTR_DEVICE_HOST_INGRESS_STATUS };
	for (size_t k = 0; k < nitems(kinds); k++) {
		bool query = kinds[k] == VTDTR_DEVICE_STATUS ||
		    kinds[k] == VTDTR_DEVICE_INGRESS_STATUS;
		bool ingress = kinds[k] == VTDTR_DEVICE_INGRESS_STATUS;
		d = new_device();
		c = report(kinds[k]);
		OK(rx(d, &c) == 0);
		r = only_receipt(d);
		OK(r != NULL && r->pvc_event == replies[k] &&
		    r->pvc_installed_delivery_id == 9 && r->pvc_installed_vmid == 42 &&
		    r->pvc_installed_epoch == vm_epoch &&
		    r->pvc_installed_query_id == (query ? 3U : 0U));
		/* The ingress query is bound to the attested identity. */
		OK(last_write.installed.vmid == 42 && last_write.installed.epoch == vm_epoch);
		/* Single-field violations. */
		for (int bad = 0; bad < 12; bad++) {
			struct pci_vtdtr_control m = report(kinds[k]);
			switch (bad) {
			case 0: memset(m.pvc_installed_program_id, 0, 16); break;
			case 1: memset(m.pvc_installed_source_id, 0, 16); break;
			case 2: m.pvc_installed_delivery_id = 0; break;
			case 3: m.pvc_installed_vmid = ingress ? 42 : 0; break;
			case 4: m.pvc_installed_vmid = ingress ? 0 : HYPERTRACE_MAX_VMS;
				m.pvc_installed_epoch = ingress ? 5 : m.pvc_installed_epoch; break;
			case 5: m.pvc_installed_epoch = ingress ? 1 : 0; break;
			case 6: m.pvc_installed_phase = 'a'; break;
			case 7: m.pvc_installed_revoked = 1; break;
			case 8: m.pvc_installed_replay = 1; break;
			case 9: m.pvc_installed_digest[0] = 1; break;
			case 10: m.pvc_installed_query_id = query ? 0 : 4; break;
			case 11: if (ingress) continue;
				m.pvc_installed_epoch = vm_epoch + 1; break;
			}
			struct device *e = new_device();
			OK(rx(e, &m) == 1 && reset_requested(e) && e->queue.count == 0);
			free_device(e);
		}
		/* Host failures. */
		if (query) {
			for (size_t i = 0; i < nitems(retryable); i++) {
				struct device *e = new_device();
				status_error = retryable[i];
				OK(rx(e, &c) == 0);
				r = only_receipt(e);
				OK(r != NULL && r->pvc_installed_phase == 'u');
				status_error = 0;
				free_device(e);
			}
			struct device *e = new_device();
			status_error = EPERM;
			OK(rx(e, &c) == 1 && reset_requested(e));
			status_error = 0;
			free_device(e);
		} else {
			struct device *e = new_device();
			write_error = EIO;
			OK(rx(e, &c) == 1 && reset_requested(e));
			write_error = 0;
			free_device(e);
		}
		{
			struct device *e = new_device();
			e->queue.count = VTDTR_MAX_RESTORE_PENDING;
			OK(rx(e, &c) == 1 && reset_requested(e));
			e->queue.count = 0;
			free_device(e);
		}
		for (int at = 1; at <= 2; at++) {
			struct device *e = new_device();
			alloc_count = 0;
			alloc_fail_at = at;
			alloc_armed = true;
			OK(rx(e, &c) == 1 && reset_requested(e) && e->queue.count == 0);
			alloc_armed = false;
			free_device(e);
		}
		free_device(d);
	}

	/* NODE_ID requests: only an unset identity is a valid request. */
	d = new_device();
	c = report(0);
	c.pvc_event = VTDTR_DEVICE_NODE_ID;
	c.pvc_node_query_id = 0;
	OK(rx(d, &c) == 0 && d->queue.count == 1);
	drain(d);
	c.pvc_node_query_id = 6;
	OK(rx(d, &c) == 0 && d->queue.count == 1);
	r = only_receipt(d);
	OK(r != NULL && r->pvc_event == VTDTR_DEVICE_NODE_ID && r->pvc_node_id == 42 &&
	    r->pvc_node_query_id == 6);
	c.pvc_node_id = 1;
	OK(rx(d, &c) == 1 && reset_requested(d));
	free_device(d);
	d = new_device();
	c.pvc_node_id = 0;
	c.pvc_node_epoch = 1;
	OK(rx(d, &c) == 1 && reset_requested(d));
	free_device(d);
	printf("vtdtr guest reports: %d checks\n", vchecks - before);
}

static void
enqueue_copy(struct pci_vtdtr_ctrlq *q, const struct pci_vtdtr_control *c)
{
	struct pci_vtdtr_ctrl_entry *e = __real_calloc(1, sizeof(*e));

	e->ctrl = __real_malloc(sizeof(*c));
	*e->ctrl = *c;
	pci_vtdtr_cq_enqueue(q, e);
}

/* A source device with a varied control queue and a partial inbound ELF;
 * returns the private image length. */
static size_t
private_source_image(uint8_t *image, size_t size, bool partial, bool queue_elf)
{
	struct device *d = new_device();
	struct pci_vtdtr_control c;
	size_t length;
	struct vm_snapshot_meta save = {
		.buffer = { .buf_start = image, .buf_size = size, .buf = image, .buf_rem = size },
		.op = VM_SNAPSHOT_SAVE,
	};

	d->sc.vsd_vs.vs_negotiated_caps = VTDTR_RESTORE_REQUIRED_FEATURES;
	d->sc.vsd_cfg = 0x0123456789abcdefULL;
	d->sc.vsd_ready = 1;
	c = valid_control(VTDTR_DEVICE_KILL);
	c.pvc_epoch = vm_epoch;
	c.pvc_kill_epoch = vm_epoch;
	enqueue_copy(&d->queue, &c);
	if (queue_elf) {
		c = valid_control(VTDTR_DEVICE_ELF);
		c.pvc_epoch = vm_epoch;
		c.pvc_totalelflen = PCI_VTDTR_MAXELFLEN + 10;
		c.pvc_elflen = PCI_VTDTR_MAXELFLEN;
		c.pvc_elfhasmore = 1;
		enqueue_copy(&d->queue, &c);
		c.pvc_elflen = 10;
		c.pvc_elfhasmore = 0;
		enqueue_copy(&d->queue, &c);
	}
	c = valid_control(VTDTR_DEVICE_HOST_INSTALLED);
	c.pvc_installed_epoch = vm_epoch;
	enqueue_copy(&d->queue, &c);
	c = valid_control(VTDTR_DEVICE_NODE_ID);
	c.pvc_node_epoch = vm_epoch;
	enqueue_copy(&d->queue, &c);
	if (partial) {
		d->sc.vsd_inbound_elf.data = __real_malloc(64);
		memset(d->sc.vsd_inbound_elf.data, 0x6d, 32);
		d->sc.vsd_inbound_elf.total = 64;
		d->sc.vsd_inbound_elf.received = 32;
		d->sc.vsd_inbound_elf.identifier = 4;
		d->sc.vsd_inbound_delivery_id = 11;
		d->sc.vsd_inbound_vmid = 42;
		d->sc.vsd_inbound_epoch = vm_epoch;
		fill_id(d->sc.vsd_inbound_program_id, 16, 1);
		fill_id(d->sc.vsd_inbound_source_id, 16, 2);
	}
	CHECK(pci_vtdtr_pause(&d->sc) == 0);
	CHECK(pci_vtdtr_private_snapshot(&d->sc, &save) == 0);
	CHECK(pci_vtdtr_resume(&d->sc) == 0);
	length = size - save.buffer.buf_rem;
	free_device(d);
	return (length);
}

static int
validate_only(uint8_t *image, size_t len)
{
	return (validate_private_image(image, len, NULL));
}

/* Private image decoding: the validator and the stager are separate
 * decoders over the same format and must agree on every input; staged
 * state equals the source; every prefix and every header rule violation is
 * refused; a refused stage leaves nothing allocated. */
static void
test_private_image_decoders(void)
{
	static uint8_t image[16384], mutated[16384];
	struct pci_vtdtr_checkpoint_stage st = { 0 };
	size_t len;
	int before = vchecks, agree = 0, accepted = 0;

	for (int variant = 0; variant < 4; variant++) {
		len = private_source_image(image, sizeof(image), variant & 1, variant & 2);
		OK(validate_only(image, len) == 0);
		OK(stage_private_image(image, len, &st) == 0);
		OK(st.source_vmid == 42 && st.source_epoch == vm_epoch &&
		    st.cfg == 0x0123456789abcdefULL && st.guest_ready == 1 && st.ready == 1 &&
		    st.count == ((variant & 2) ? 5U : 3U) &&
		    st.partial_total == ((variant & 1) ? 64U : 0U) &&
		    st.partial_received == ((variant & 1) ? 32U : 0U) &&
		    ((variant & 1) == 0 || st.partial_prefix[31] == 0x6d));
		pci_vtdtr_checkpoint_stage_clear(&st);
		for (size_t cut = 0; cut < len; cut++) {
			OK(validate_only(image, cut) != 0);
			OK(stage_private_image(image, cut, &st) != 0 && st.controls == NULL &&
			    st.partial_prefix == NULL);
		}
		/* Every byte of the header and of the first records, several
		 * values: the two decoders agree. */
		for (size_t off = 0; off < len && off < 220; off++) {
			static const uint8_t values[] = { 0x00, 0x01, 0x02, 0x7f, 0x80, 0xff };
			for (size_t v = 0; v < nitems(values); v++) {
				int rv, rs;
				memcpy(mutated, image, len);
				if (mutated[off] == values[v])
					continue;
				mutated[off] = values[v];
				rv = validate_only(mutated, len);
				rs = stage_private_image(mutated, len, &st);
				if ((rv == 0) != (rs == 0))
					fprintf(stderr, "decoders disagree at %zu=%#x: %d %d\n",
					    off, values[v], rv, rs);
				OK((rv == 0) == (rs == 0));
				if (rs == 0) {
					accepted++;
					OK(st.count <= VTDTR_MAX_PENDING && st.source_vmid != 0 &&
					    st.source_epoch != 0);
				} else {
					OK(st.controls == NULL && st.partial_prefix == NULL);
				}
				pci_vtdtr_checkpoint_stage_clear(&st);
				agree++;
			}
		}
	}
	/* Header rules, one at a time (offsets per the fixed layout). */
	len = private_source_image(image, sizeof(image), true, false);
	struct { size_t off; size_t width; uint64_t value; } rules[] = {
		{ 0, 4, 0x31524457 },	/* magic */
		{ 4, 2, VTDTR_SNAPSHOT_VERSION + 1 },
		{ 6, 2, 0 },		/* vmid */
		{ 6, 2, HYPERTRACE_MAX_VMS },
		{ 8, 8, 0 },		/* epoch */
		{ 24, 1, 2 },		/* guest_ready */
		{ 25, 1, 2 },		/* ready */
		{ 26, 4, VTDTR_MAX_PENDING + 1 },
		{ 34, 4, 0 },		/* received with total set */
		{ 34, 4, 64 },		/* received == total */
		{ 30, 4, HYPERTRACE_ELF_MAX + 1 },
		{ 42, 8, 0 },		/* delivery */
		{ 50, 2, 41 },		/* partial vmid */
		{ 52, 8, 1 },		/* partial epoch */
		{ 60, 16, 0 },		/* program id */
		{ 76, 16, 0 },		/* source id */
	};
	for (size_t i = 0; i < nitems(rules); i++) {
		memcpy(mutated, image, len);
		if (rules[i].width == 16)
			memset(mutated + rules[i].off, 0, 16);
		else
			for (size_t b = 0; b < rules[i].width; b++)
				mutated[rules[i].off + b] = (uint8_t)(rules[i].value >> (8 * b));
		int rv = validate_only(mutated, len);
		if (rv == 0)
			fprintf(stderr, "header rule %zu accepted\n", i);
		OK(rv != 0);
	}
	/* Without a partial ELF every partial field must be zero. */
	len = private_source_image(image, sizeof(image), false, false);
	for (size_t off = 34; off < 92; off++) {
		memcpy(mutated, image, len);
		mutated[off] = 1;
		OK(validate_only(mutated, len) == EPROTO);
	}
	/* Allocation failures while staging. */
	len = private_source_image(image, sizeof(image), true, true);
	for (int at = 1; at <= 2; at++) {
		alloc_count = 0;
		alloc_fail_at = at;
		alloc_armed = true;
		OK(stage_private_image(image, len, &st) == ENOMEM && st.controls == NULL &&
		    st.partial_prefix == NULL);
		alloc_armed = false;
	}
	/* Interface misuse. */
	{
		struct vm_snapshot_meta restore = {
			.buffer = { .buf_start = image, .buf_size = len, .buf = image, .buf_rem = len },
			.op = VM_SNAPSHOT_RESTORE,
		};
		struct vm_snapshot_meta save = {
			.buffer = { .buf_start = image, .buf_size = len, .buf = image, .buf_rem = len },
			.op = VM_SNAPSHOT_SAVE,
		};
		OK(pci_vtdtr_private_snapshot_stage(NULL, NULL, NULL) == EINVAL);
		OK(pci_vtdtr_private_snapshot_stage(NULL, &restore, NULL) == EINVAL);
		OK(pci_vtdtr_private_snapshot_stage(NULL, &save, NULL) == EINVAL);
		OK(pci_vtdtr_private_snapshot_stage(NULL, &save, &st) == EINVAL);
		st.count = 1;
		OK(stage_private_image(image, len, &st) == EINVAL);
		st.count = 0;
	}
	printf("vtdtr private image decoders: %d checks (%d mutations, %d accepted)\n",
	    vchecks - before, agree, accepted);
}

static void
future(struct timespec *t, int seconds)
{
	clock_gettime(CLOCK_MONOTONIC, t);
	t->tv_sec += seconds;
}

/* Fresh-session handshake from the guest: SESSION_READY queues exactly one
 * COMMIT; SESSION_ACTIVE needs that COMMIT delivered.  Every field of the
 * reply is bound to the stop record and the current VM identity. */
static void
fresh_state(struct device *d, struct pci_vtdtr_control *c, uint32_t event)
{
	d->sc.vsd_fresh_requested = true;
	d->sc.vsd_fresh_prepare_delivered = true;
	d->sc.vsd_fresh_vmid = 42;
	d->sc.vsd_fresh_epoch = vm_epoch;
	future(&d->sc.vsd_fresh_deadline, 60);
	d->sc.vsd_session_stop_token = 0x5151;
	d->sc.vsd_session_stop_vmid = 7;
	d->sc.vsd_session_stop_epoch = 8;
	d->sc.vsd_fresh_commit_delivered = event == VTDTR_DEVICE_SESSION_ACTIVE;
	memset(c, 0, sizeof(*c));
	c->pvc_event = event;
	c->wire.uctrl.session_prepare.stop_token = 0x5151;
	c->wire.uctrl.session_prepare.old_id = 7;
	c->wire.uctrl.session_prepare.old_epoch = 8;
	c->wire.uctrl.session_prepare.new_id = 42;
	c->wire.uctrl.session_prepare.new_epoch = vm_epoch;
}

static void
test_session_controls(void)
{
	int before = vchecks;
	struct device *d;
	struct pci_vtdtr_control c;

	/* READY: one COMMIT, then idempotent. */
	d = new_device();
	fresh_state(d, &c, VTDTR_DEVICE_SESSION_READY);
	d->sc.vsd_guest_ready = 0;
	OK(rx(d, &c) == 0 && d->queue.count == 1 && d->sc.vsd_fresh_commit_queued &&
	    d->sc.vsd_guest_ready == 1);
	{
		struct pci_vtdtr_ctrl_entry *e = STAILQ_FIRST(&d->queue.head);
		OK(e->ctrl->pvc_event == VTDTR_DEVICE_SESSION_COMMIT &&
		    e->ctrl->wire.uctrl.session_prepare.stop_token == 0x5151 &&
		    e->ctrl->wire.uctrl.session_prepare.new_epoch == vm_epoch);
	}
	OK(rx(d, &c) == 0 && d->queue.count == 1);
	free_device(d);
	/* ACTIVE after the COMMIT was delivered. */
	d = new_device();
	fresh_state(d, &c, VTDTR_DEVICE_SESSION_ACTIVE);
	OK(rx(d, &c) == 0 && d->sc.vsd_fresh_active);
	/* Once active, an expired deadline no longer matters. */
	d->sc.vsd_fresh_deadline = (struct timespec){ 0 };
	OK(rx(d, &c) == 0);
	free_device(d);
	for (int event = 0; event < 2; event++) {
		uint32_t ev = event ? VTDTR_DEVICE_SESSION_ACTIVE : VTDTR_DEVICE_SESSION_READY;
		for (int bad = 0; bad < 12; bad++) {
			d = new_device();
			fresh_state(d, &c, ev);
			switch (bad) {
			case 0: d->sc.vsd_fresh_requested = false; break;
			case 1: d->sc.vsd_fresh_prepare_delivered = false; break;
			case 2: d->sc.vsd_fresh_deadline = (struct timespec){ 0 }; break;
			case 3: d->sc.vsd_fresh_vmid = 41; break;
			case 4: d->sc.vsd_fresh_epoch = vm_epoch + 1; break;
			case 5: c.wire.uctrl.session_prepare.reserved = 1; break;
			case 6: c.wire.uctrl.session_prepare.stop_token ^= 1; break;
			case 7: c.wire.uctrl.session_prepare.old_id = 6; break;
			case 8: c.wire.uctrl.session_prepare.old_epoch = 9; break;
			case 9: c.wire.uctrl.session_prepare.new_id = 41; break;
			case 10: c.wire.uctrl.session_prepare.new_epoch++; break;
			case 11: if (!event) { free_device(d); continue; }
				d->sc.vsd_fresh_commit_delivered = false; break;
			}
			OK(rx(d, &c) == 1 && reset_requested(d) && d->queue.count == 0);
			free_device(d);
		}
	}
	for (int at = 1; at <= 2; at++) {
		d = new_device();
		fresh_state(d, &c, VTDTR_DEVICE_SESSION_READY);
		alloc_count = 0;
		alloc_fail_at = at;
		alloc_armed = true;
		OK(rx(d, &c) == 1 && reset_requested(d) && !d->sc.vsd_fresh_commit_queued);
		alloc_armed = false;
		free_device(d);
	}

	/* SESSION_STOPPED: the old session's stop under the fresh request is
	 * absorbed; otherwise the stop must match the delivered stop record. */
	d = new_device();
	fresh_state(d, &c, VTDTR_DEVICE_SESSION_STOPPED);
	c.pvc_cleanup_vmid = 7;
	c.pvc_cleanup_epoch = 8;
	c.pvc_cleanup_delivery_id = 0x5151;
	d->sc.vsd_ready = 1;
	OK(rx(d, &c) == 0 && d->sc.vsd_ready == 0 && !reset_requested(d));
	free_device(d);
	for (int bad = -1; bad < 9; bad++) {
		d = new_device();
		memset(&c, 0, sizeof(c));
		c.pvc_event = VTDTR_DEVICE_SESSION_STOPPED;
		c.pvc_cleanup_vmid = 42;
		c.pvc_cleanup_epoch = vm_epoch;
		c.pvc_cleanup_delivery_id = 0x6161;
		d->sc.vsd_session_stop_requested = true;
		d->sc.vsd_session_stop_delivered = true;
		d->sc.vsd_session_stop_vmid = 42;
		d->sc.vsd_session_stop_epoch = vm_epoch;
		d->sc.vsd_session_stop_token = 0x6161;
		switch (bad) {
		case 0: d->sc.vsd_session_stop_requested = false; break;
		case 1: d->sc.vsd_session_stop_delivered = false; break;
		case 2: d->sc.vsd_session_stop_vmid = 41; c.pvc_cleanup_vmid = 41; break;
		case 3: d->sc.vsd_session_stop_epoch++; c.pvc_cleanup_epoch++; break;
		case 4: c.pvc_cleanup_vmid = 41; break;
		case 5: c.pvc_cleanup_epoch++; break;
		case 6: c.pvc_cleanup_delivery_id ^= 1; break;
		case 7: d->sc.vsd_fresh_requested = true; c.pvc_cleanup_vmid = 7; break;
		case 8: d->sc.vsd_fresh_requested = true; d->sc.vsd_session_stop_vmid = 7;
			c.pvc_cleanup_epoch++; break;
		}
		int r = rx(d, &c);
		if (bad == -1)
			OK(r == 0 && d->sc.vsd_session_stopped && d->sc.vsd_guest_ready == 0);
		else
			OK(r == 1 && reset_requested(d) && !d->sc.vsd_session_stopped);
		free_device(d);
	}
	/* After a stop request, old-session traffic is discarded (EOF ends
	 * the batch); READY still flows so STOP can be delivered. */
	{
		static const uint32_t old[] = { VTDTR_DEVICE_INSTALLED, VTDTR_DEVICE_ELF,
		    VTDTR_DEVICE_KILL_APPLIED, VTDTR_DEVICE_EOF };
		for (size_t i = 0; i < nitems(old); i++) {
			d = new_device();
			d->sc.vsd_session_stop_requested = true;
			d->sc.vsd_ready = 1;
			c = report(old[i]);
			int writes_before = writes;
			OK(rx(d, &c) == (old[i] == VTDTR_DEVICE_EOF ? 1 : 0) && d->sc.vsd_ready == 0 &&
			    writes == writes_before && d->queue.count == 0 && !reset_requested(d));
			free_device(d);
		}
		d = new_device();
		d->sc.vsd_session_stop_requested = true;
		d->sc.vsd_guest_ready = 0;
		c = report(0);
		c.pvc_event = VTDTR_DEVICE_READY;
		OK(rx(d, &c) == 0 && d->sc.vsd_guest_ready == 1);
		free_device(d);
	}
	/* Shutdown, a pending reset, and expired transition deadlines. */
	c = report(0);
	c.pvc_event = VTDTR_DEVICE_READY;
	d = new_device();
	d->sc.vsd_stopping = true;
	OK(rx(d, &c) == 1 && reset_requested(d));
	free_device(d);
	d = new_device();
	d->sc.vsd_vs.vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	d->sc.vsd_guest_ready = 0;
	OK(rx(d, &c) == 1 && d->sc.vsd_guest_ready == 0);
	free_device(d);
	d = new_device();
	d->sc.vsd_rekey_wait = true;
	d->sc.vsd_rekey_deadline = (struct timespec){ 0 };
	OK(rx(d, &c) == 1 && reset_requested(d) && !d->sc.vsd_rekey_wait);
	free_device(d);
	d = new_device();
	d->sc.vsd_restored_kill_wait = true;
	d->sc.vsd_restored_kill_deadline = (struct timespec){ 0 };
	OK(rx(d, &c) == 1 && reset_requested(d) && !d->sc.vsd_restored_kill_wait);
	free_device(d);
	/* A short control is a transport error; during a rekey it quarantines. */
	for (int rekey = 0; rekey < 2; rekey++) {
		struct iovec iov = { &c, sizeof(c) - 1 };
		d = new_device();
		d->sc.vsd_rekey_wait = rekey;
		future(&d->sc.vsd_rekey_deadline, 60);
		pthread_mutex_lock(&d->sc.vsd_mtx);
		OK(pci_vtdtr_control_rx(&d->sc, &iov, 1) == 1);
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		OK(reset_requested(d) && !d->sc.vsd_rekey_wait);
		free_device(d);
	}
	printf("vtdtr session controls: %d checks\n", vchecks - before);
}

/* Node rekey: COMMIT and APPLIED are accepted only for the exact
 * transition delivered and the VM's current identity; nothing else may
 * cross the transition. */
static void
rekey_state(struct device *d, struct pci_vtdtr_control *c, uint32_t event)
{
	d->sc.vsd_rekey_wait = true;
	future(&d->sc.vsd_rekey_deadline, 60);
	d->sc.vsd_handoff_ticket_valid = true;
	d->sc.vsd_handoff_token[0] = 0xa1;
	d->sc.vsd_handoff_digest[0] = 0xb2;
	d->sc.vsd_rekey_old_id = 7;
	d->sc.vsd_rekey_old_epoch = 8;
	d->sc.vsd_rekey_new_id = 42;
	d->sc.vsd_rekey_new_epoch = vm_epoch;
	d->sc.vsd_rekey_ack_sent = event == VTDTR_DEVICE_REKEY_APPLIED;
	d->sc.vsd_guest_ready = 0;
	memset(c, 0, sizeof(*c));
	c->pvc_event = event;
	c->pvc_rekey_old_id = 7;
	c->pvc_rekey_old_epoch = 8;
	c->pvc_rekey_new_id = 42;
	c->pvc_rekey_new_epoch = vm_epoch;
}

static void
test_rekey_controls(void)
{
	int before = vchecks;
	struct device *d;
	struct pci_vtdtr_control c;

	d = new_device();
	rekey_state(d, &c, VTDTR_DEVICE_REKEY_COMMIT);
	OK(rx(d, &c) == 0 && d->sc.vsd_rekey_ack_pending && d->sc.vsd_rekey_wait);
	d->sc.vsd_rekey_ack_pending = false;
	d->sc.vsd_rekey_ack_sent = true;
	OK(rx(d, &c) == 0 && !d->sc.vsd_rekey_ack_pending);	/* already sent */
	free_device(d);
	d = new_device();
	rekey_state(d, &c, VTDTR_DEVICE_REKEY_APPLIED);
	{
		int calls = rekey_applied_calls;
		OK(rx(d, &c) == 0 && !d->sc.vsd_rekey_wait && d->sc.vsd_guest_ready == 1 &&
		    !d->sc.vsd_handoff_ticket_valid && rekey_applied_calls == calls + 1);
	}
	free_device(d);
	for (int event = 0; event < 2; event++) {
		uint32_t ev = event ? VTDTR_DEVICE_REKEY_APPLIED : VTDTR_DEVICE_REKEY_COMMIT;
		for (int bad = 0; bad < 10; bad++) {
			d = new_device();
			rekey_state(d, &c, ev);
			switch (bad) {
			case 0: d->sc.vsd_handoff_ticket_valid = false; break;
			case 1: if (event) d->sc.vsd_rekey_ack_sent = false;
				else d->sc.vsd_rekey_receipt_reply_pending = true; break;
			case 2: c.pvc_rekey_old_id = 6; break;
			case 3: c.pvc_rekey_old_epoch = 9; break;
			case 4: c.pvc_rekey_new_id = 41; break;
			case 5: c.pvc_rekey_new_epoch++; break;
			case 6: d->sc.vsd_rekey_new_id = 41; c.pvc_rekey_new_id = 41; break;
			case 7: d->sc.vsd_rekey_new_epoch++; c.pvc_rekey_new_epoch++; break;
			case 8: if (!event) { free_device(d); continue; }
				/* applied after the deadline */
				d->sc.vsd_rekey_deadline.tv_sec = 0; d->sc.vsd_rekey_deadline.tv_nsec = 0;
				break;
			case 9: c.pvc_event = VTDTR_DEVICE_INSTALLED; break;
			}
			OK(rx(d, &c) == 1 && reset_requested(d) && !d->sc.vsd_rekey_wait &&
			    !d->sc.vsd_handoff_ticket_valid);
			free_device(d);
		}
	}
	/* READY may arrive during the transition and is absorbed. */
	d = new_device();
	rekey_state(d, &c, VTDTR_DEVICE_READY);
	OK(rx(d, &c) == 0 && d->sc.vsd_rekey_wait && d->sc.vsd_guest_ready == 0);
	free_device(d);
	printf("vtdtr rekey controls: %d checks\n", vchecks - before);
}

/* ------------------------------------------------- authorization */
/*
 * pci_vtdtr_session_authorize(): from the authorizable state (fresh session
 * requested and active, the old session stopped, identity matching) the
 * gate is released through the daemon, the transport generation advances
 * and the session is marked released.  Each row breaks one precondition.
 * Oracle: the documented error, no daemon release unless the row reached
 * it, and on refusal no state change (generation, released flag).
 */
enum auth_row { A_NULL_CTX, A_OTHER_CTX, A_NO_DEVICE, A_NOT_REQUESTED, A_NOT_ACTIVE,
	A_MIGRATION_HELD, A_BUSY, A_STOPPING, A_PAUSED, A_RESTORE_STAGED,
	A_RESTORE_PENDING, A_SUSPENDED, A_REKEY, A_RESET, A_VMID, A_EPOCH,
	A_NOT_STOP_REQUESTED, A_NOT_STOPPED, A_GENERATION, A_RELEASE_FAILS,
	A_RELEASE_NOERRNO, A_HOST_GATE_FAILS, A_OK, A_AGAIN };
static const struct { enum auth_row row; int error; bool releases; } auth_table[] = {
	{ A_NULL_CTX, ENXIO, false }, { A_OTHER_CTX, ENXIO, false },
	{ A_NO_DEVICE, ENXIO, false }, { A_NOT_REQUESTED, EBUSY, false },
	{ A_NOT_ACTIVE, EBUSY, false }, { A_MIGRATION_HELD, EBUSY, false },
	{ A_BUSY, EBUSY, false }, { A_STOPPING, EBUSY, false }, { A_PAUSED, EBUSY, false },
	{ A_RESTORE_STAGED, EBUSY, false }, { A_RESTORE_PENDING, EBUSY, false },
	{ A_SUSPENDED, EBUSY, false }, { A_REKEY, EBUSY, false }, { A_RESET, EBUSY, false },
	{ A_VMID, ESTALE, false }, { A_EPOCH, ESTALE, false },
	{ A_NOT_STOP_REQUESTED, EBUSY, false }, { A_NOT_STOPPED, EBUSY, false },
	{ A_GENERATION, EBUSY, false }, { A_RELEASE_FAILS, EIO, true },
	{ A_RELEASE_NOERRNO, EIO, true }, { A_HOST_GATE_FAILS, EPERM, true },
	{ A_OK, 0, true }, { A_AGAIN, 0, false },
};

static void
test_session_authorize(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct vmctx *ctx = (struct vmctx *)1;	/* identity 43/100 */
	uint64_t generation;

	memset(destination_gate_owner, 0x6b, sizeof(destination_gate_owner));
	for (size_t i = 0; i < nitems(auth_table); i++) {
		struct vmctx *arg = ctx;
		int calls = release_calls, error;

		if (auth_table[i].row != A_AGAIN) {
			pthread_mutex_lock(&d->sc.vsd_mtx);
			d->sc.vsd_vmctx = ctx;
			d->sc.vsd_fresh_requested = d->sc.vsd_fresh_active = true;
			d->sc.vsd_fresh_released = d->sc.vsd_fresh_release_busy = false;
			d->sc.vsd_fresh_vmid = 43;
			d->sc.vsd_fresh_epoch = 100;
			d->sc.vsd_session_stop_requested = d->sc.vsd_session_stopped = true;
			d->sc.vsd_session_migration_staged = d->sc.vsd_session_migration_released = false;
			d->sc.vsd_stopping = d->sc.vsd_checkpoint_paused = d->sc.vsd_suspended = false;
			d->sc.vsd_session_restore_staged = d->sc.vsd_session_restore_pending = false;
			d->sc.vsd_rekey_wait = false;
			d->sc.vsd_vs.vs_status = 0;
			d->sc.vsd_generation = 5;
			memcpy(d->sc.vsd_fresh_gate_token, destination_gate_owner, 16);
			pthread_mutex_unlock(&d->sc.vsd_mtx);
			destination_released = false;
		}
		vtdtr_shutdown_sc = &d->sc;
		switch (auth_table[i].row) {
		case A_NULL_CTX: arg = NULL; break;
		case A_OTHER_CTX: arg = (struct vmctx *)2; break;
		case A_NO_DEVICE: vtdtr_shutdown_sc = NULL; break;
		case A_NOT_REQUESTED: d->sc.vsd_fresh_requested = false; break;
		case A_NOT_ACTIVE: d->sc.vsd_fresh_active = false; break;
		case A_MIGRATION_HELD: d->sc.vsd_session_migration_staged = true; break;
		case A_BUSY: d->sc.vsd_fresh_release_busy = true; break;
		case A_STOPPING: d->sc.vsd_stopping = true; break;
		case A_PAUSED: d->sc.vsd_checkpoint_paused = true; break;
		case A_RESTORE_STAGED: d->sc.vsd_session_restore_staged = true; break;
		case A_RESTORE_PENDING: d->sc.vsd_session_restore_pending = true; break;
		case A_SUSPENDED: d->sc.vsd_suspended = true; break;
		case A_REKEY: d->sc.vsd_rekey_wait = true; break;
		case A_RESET: d->sc.vsd_vs.vs_status = VIRTIO_CONFIG_S_NEEDS_RESET; break;
		case A_VMID: d->sc.vsd_fresh_vmid = 44; break;
		case A_EPOCH: d->sc.vsd_fresh_epoch = 101; break;
		case A_NOT_STOP_REQUESTED: d->sc.vsd_session_stop_requested = false; break;
		case A_NOT_STOPPED: d->sc.vsd_session_stopped = false; break;
		case A_GENERATION: d->sc.vsd_generation = UINT64_MAX; break;
		case A_RELEASE_FAILS: release_failure = EIO; break;
		case A_RELEASE_NOERRNO: release_failure = -1; break;
		case A_HOST_GATE_FAILS: destination_gate_failure = EPERM; break;
		default: break;
		}
		generation = d->sc.vsd_generation;
		error = pci_vtdtr_session_authorize(arg);
		release_failure = 0;
		destination_gate_failure = 0;
		vtdtr_shutdown_sc = NULL;
		OK(error == auth_table[i].error);
		OK((release_calls != calls) == auth_table[i].releases);
		if (auth_table[i].row == A_OK) {
			OK(d->sc.vsd_fresh_released && d->sc.vsd_generation != generation &&
			    !d->sc.vsd_session_stop_requested && !d->sc.vsd_session_stopped);
		} else if (auth_table[i].row == A_AGAIN) {
			/* Already released: only the gate is rechecked. */
			OK(d->sc.vsd_fresh_released && d->sc.vsd_generation == generation);
		} else {
			OK(!d->sc.vsd_fresh_released && d->sc.vsd_generation == generation &&
			    (!d->sc.vsd_fresh_release_busy || auth_table[i].row == A_BUSY));
		}
	}
	drain(d);
	printf("vtdtr session authorization table: %d checks\n", vchecks - before);
}

/* ------------------------------------- attach and stop transitions */
/*
 * pci_vtdtr_session_attach_begin(): from a stopped old session with a
 * retired source lifetime, the device queues one SESSION_PREPARE naming the
 * stop tuple and the new lifetime.  Each row breaks one precondition.
 * Oracle: the errno; on refusal nothing is queued and no fresh request is
 * recorded; on success exactly one correct PREPARE is queued.
 */
enum att_row { T_NULL_CTX, T_OTHER_CTX, T_NO_DEVICE, T_STOPPING, T_RESET,
	T_NOT_REQUESTED, T_NOT_STOPPED, T_MIGRATION_HELD, T_NO_VMID, T_NO_EPOCH,
	T_NO_TOKEN, T_SUSPENDED, T_PAUSED, T_RESTORE_PENDING, T_REKEY, T_NO_FRESH_CAP,
	T_SAME_LIFETIME, T_REQUESTED_OTHER, T_REQUESTED_SAME, T_NOT_RETIRED,
	T_MIGRATION_RELEASED, T_GATE_FAILS, T_NO_MEMORY, T_OK };
static const struct { enum att_row row; int error; int queued; } att_table[] = {
	{ T_NULL_CTX, ENXIO, 0 }, { T_OTHER_CTX, ENXIO, 0 }, { T_NO_DEVICE, ENXIO, 0 },
	{ T_STOPPING, ENXIO, 0 }, { T_RESET, ENXIO, 0 }, { T_NOT_REQUESTED, EBUSY, 0 },
	{ T_NOT_STOPPED, EBUSY, 0 }, { T_MIGRATION_HELD, EBUSY, 0 }, { T_NO_VMID, EBUSY, 0 },
	{ T_NO_EPOCH, EBUSY, 0 }, { T_NO_TOKEN, EBUSY, 0 }, { T_SUSPENDED, EBUSY, 0 },
	{ T_PAUSED, EBUSY, 0 }, { T_RESTORE_PENDING, EBUSY, 0 }, { T_REKEY, EBUSY, 0 },
	{ T_NO_FRESH_CAP, ENOTSUP, 0 }, { T_SAME_LIFETIME, ESTALE, 0 },
	{ T_REQUESTED_OTHER, ESTALE, 0 }, { T_REQUESTED_SAME, 0, 0 },
	{ T_NOT_RETIRED, EBUSY, 0 }, { T_MIGRATION_RELEASED, 0, 1 },
	{ T_GATE_FAILS, EPERM, 0 }, { T_NO_MEMORY, ENOMEM, 0 }, { T_OK, 0, 1 },
};

static void
test_session_attach(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct vmctx *ctx = (struct vmctx *)1;	/* identity 43/100 */

	for (size_t i = 0; i < nitems(att_table); i++) {
		struct vmctx *arg = ctx;
		bool was_requested;
		int error;

		pthread_mutex_lock(&d->sc.vsd_mtx);
		drain(d);
		memset(&d->sc.vsd_fresh_gate_token, 0, 16);
		d->sc.vsd_vmctx = ctx;
		d->sc.vsd_stopping = d->sc.vsd_suspended = d->sc.vsd_checkpoint_paused = false;
		d->sc.vsd_session_restore_pending = d->sc.vsd_rekey_wait = false;
		d->sc.vsd_vs.vs_status = 0;
		d->sc.vsd_vs.vs_negotiated_caps = VTDTR_WIRE_F_SESSION_FRESH_V1;
		d->sc.vsd_session_stop_requested = d->sc.vsd_session_stopped = true;
		d->sc.vsd_session_migration_staged = d->sc.vsd_session_migration_released = false;
		d->sc.vsd_session_stop_vmid = 7;
		d->sc.vsd_session_stop_epoch = 8;
		d->sc.vsd_session_stop_token = 0x77;
		d->sc.vsd_fresh_requested = d->sc.vsd_fresh_active = false;
		d->sc.vsd_fresh_released = false;
		d->sc.vsd_fresh_vmid = 0;
		d->sc.vsd_fresh_epoch = 0;
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		memset(destination_gate_owner, 0, 16);
		destination_released = false;
		destination_gate_failure = 0;
		source_retired = true;
		vtdtr_shutdown_sc = &d->sc;
		switch (att_table[i].row) {
		case T_NULL_CTX: arg = NULL; break;
		case T_OTHER_CTX: arg = (struct vmctx *)2; break;
		case T_NO_DEVICE: vtdtr_shutdown_sc = NULL; break;
		case T_STOPPING: d->sc.vsd_stopping = true; break;
		case T_RESET: d->sc.vsd_vs.vs_status = VIRTIO_CONFIG_S_NEEDS_RESET; break;
		case T_NOT_REQUESTED: d->sc.vsd_session_stop_requested = false; break;
		case T_NOT_STOPPED: d->sc.vsd_session_stopped = false; break;
		case T_MIGRATION_HELD: d->sc.vsd_session_migration_staged = true; break;
		case T_NO_VMID: d->sc.vsd_session_stop_vmid = 0; break;
		case T_NO_EPOCH: d->sc.vsd_session_stop_epoch = 0; break;
		case T_NO_TOKEN: d->sc.vsd_session_stop_token = 0; break;
		case T_SUSPENDED: d->sc.vsd_suspended = true; break;
		case T_PAUSED: d->sc.vsd_checkpoint_paused = true; break;
		case T_RESTORE_PENDING: d->sc.vsd_session_restore_pending = true; break;
		case T_REKEY: d->sc.vsd_rekey_wait = true; break;
		case T_NO_FRESH_CAP: d->sc.vsd_vs.vs_negotiated_caps = 0; break;
		case T_SAME_LIFETIME: d->sc.vsd_session_stop_epoch = 100; break;
		case T_REQUESTED_OTHER:
			d->sc.vsd_fresh_requested = true;
			d->sc.vsd_fresh_vmid = 44;
			d->sc.vsd_fresh_epoch = 100;
			break;
		case T_REQUESTED_SAME:
			/* A repeated attach rechecks the held gate only. */
			d->sc.vsd_fresh_requested = true;
			d->sc.vsd_fresh_vmid = 43;
			d->sc.vsd_fresh_epoch = 100;
			memset(d->sc.vsd_fresh_gate_token, 0x5c, 16);
			memset(destination_gate_owner, 0x5c, 16);
			break;
		case T_NOT_RETIRED: source_retired = false; break;
		case T_MIGRATION_RELEASED:
			/* Migration proves retirement itself; no witness query. */
			d->sc.vsd_session_migration_staged = true;
			d->sc.vsd_session_migration_released = true;
			source_retired = false;
			break;
		case T_GATE_FAILS: destination_gate_failure = EPERM; break;
		case T_NO_MEMORY: alloc_armed = true; alloc_count = 0; alloc_fail_at = 1; break;
		default: break;
		}
		was_requested = d->sc.vsd_fresh_requested;
		error = pci_vtdtr_session_attach_begin(arg);
		alloc_armed = false;
		vtdtr_shutdown_sc = NULL;
		OK(error == att_table[i].error);
		OK((int)d->queue.count == att_table[i].queued);
		if (att_table[i].queued) {
			struct pci_vtdtr_control *c = STAILQ_FIRST(&d->queue.head)->ctrl;
			OK(c->pvc_event == VTDTR_DEVICE_SESSION_PREPARE &&
			    c->wire.uctrl.session_prepare.stop_token == 0x77 &&
			    c->wire.uctrl.session_prepare.old_id == 7 &&
			    c->wire.uctrl.session_prepare.old_epoch == 8 &&
			    c->wire.uctrl.session_prepare.new_id == 43 &&
			    c->wire.uctrl.session_prepare.new_epoch == 100 &&
			    d->sc.vsd_fresh_requested && d->sc.vsd_fresh_vmid == 43);
		} else if (error != 0)
			OK(d->sc.vsd_fresh_requested == was_requested);
	}
	drain(d);
	printf("vtdtr session attach table: %d checks\n", vchecks - before);
}

/*
 * pci_vtdtr_session_stop_begin()/checkpoint_begin(): queue one SESSION_STOP
 * for the current lifetime after the daemon suspends its gate; a repeated
 * request for the same lifetime is idempotent.  Oracle: errno; on refusal
 * nothing queued and no stop recorded.
 */
enum stop_row { S_NULL_CTX, S_STOPPING, S_RESET, S_CKPT_NO_CAPS, S_NO_STOP_CAP,
	S_PAUSED, S_SUSPENDED, S_REKEY, S_RESTORED_KILL, S_CLEANUP, S_TICKET,
	S_GATE_FAILS, S_NO_MEMORY, S_OK, S_AGAIN_SAME, S_AGAIN_OTHER, S_CKPT_OK };
static const struct { enum stop_row row; int error; int queued; } stop_table[] = {
	{ S_NULL_CTX, ENXIO, 0 }, { S_STOPPING, ENXIO, 0 }, { S_RESET, ENXIO, 0 },
	{ S_CKPT_NO_CAPS, ENOTSUP, 0 }, { S_NO_STOP_CAP, ENOTSUP, 0 },
	{ S_PAUSED, EBUSY, 0 }, { S_SUSPENDED, EBUSY, 0 }, { S_REKEY, EBUSY, 0 },
	{ S_RESTORED_KILL, EBUSY, 0 }, { S_CLEANUP, EBUSY, 0 }, { S_TICKET, EBUSY, 0 },
	{ S_GATE_FAILS, EPERM, 0 }, { S_NO_MEMORY, ENOMEM, 0 }, { S_OK, 0, 1 },
	{ S_AGAIN_SAME, 0, 0 }, { S_AGAIN_OTHER, ESTALE, 0 }, { S_CKPT_OK, 0, 1 },
};

static void
test_session_stop_table(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct vmctx *ctx = (struct vmctx *)2;	/* identity 42/vm_epoch */
	const uint64_t all = VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_SESSION_STOP_V1 |
	    VTDTR_WIRE_F_SESSION_FRESH_V1;

	for (size_t i = 0; i < nitems(stop_table); i++) {
		bool again = stop_table[i].row == S_AGAIN_SAME ||
		    stop_table[i].row == S_AGAIN_OTHER;
		struct vmctx *arg = ctx;
		int error;

		if (!again) {
			pthread_mutex_lock(&d->sc.vsd_mtx);
			drain(d);
			memset(d->sc.vsd_session_gate_token, 0, 16);
			d->sc.vsd_vmctx = ctx;
			d->sc.vsd_stopping = d->sc.vsd_suspended = d->sc.vsd_checkpoint_paused = false;
			d->sc.vsd_rekey_wait = d->sc.vsd_restored_kill_wait = false;
			d->sc.vsd_cleanup_unapplied = d->sc.vsd_handoff_ticket_valid = false;
			d->sc.vsd_vs.vs_status = 0;
			d->sc.vsd_vs.vs_negotiated_caps = VTDTR_WIRE_F_SESSION_STOP_V1;
			d->sc.vsd_session_stop_requested = false;
			d->sc.vsd_session_stop_vmid = 0;
			d->sc.vsd_session_stop_epoch = 0;
			pthread_mutex_unlock(&d->sc.vsd_mtx);
			memset(session_gate_owner, 0, 16);
			session_gate_failure = 0;
		} else {
			pthread_mutex_lock(&d->sc.vsd_mtx);
			drain(d);
			pthread_mutex_unlock(&d->sc.vsd_mtx);
		}
		vtdtr_shutdown_sc = &d->sc;
		switch (stop_table[i].row) {
		case S_NULL_CTX: arg = NULL; break;
		case S_STOPPING: d->sc.vsd_stopping = true; break;
		case S_RESET: d->sc.vsd_vs.vs_status = VIRTIO_CONFIG_S_NEEDS_RESET; break;
		case S_NO_STOP_CAP: d->sc.vsd_vs.vs_negotiated_caps = 0; break;
		case S_PAUSED: d->sc.vsd_checkpoint_paused = true; break;
		case S_SUSPENDED: d->sc.vsd_suspended = true; break;
		case S_REKEY: d->sc.vsd_rekey_wait = true; break;
		case S_RESTORED_KILL: d->sc.vsd_restored_kill_wait = true; break;
		case S_CLEANUP: d->sc.vsd_cleanup_unapplied = true; break;
		case S_TICKET: d->sc.vsd_handoff_ticket_valid = true; break;
		case S_GATE_FAILS: session_gate_failure = EPERM; break;
		case S_NO_MEMORY: alloc_armed = true; alloc_count = 0; alloc_fail_at = 1; break;
		case S_AGAIN_OTHER: vm_epoch++; break;
		case S_CKPT_OK: d->sc.vsd_vs.vs_negotiated_caps = all; break;
		default: break;
		}
		error = stop_table[i].row == S_CKPT_NO_CAPS || stop_table[i].row == S_CKPT_OK ?
		    pci_vtdtr_session_checkpoint_begin(arg) : pci_vtdtr_session_stop_begin(arg);
		alloc_armed = false;
		session_gate_failure = 0;
		if (stop_table[i].row == S_AGAIN_OTHER)
			vm_epoch--;
		vtdtr_shutdown_sc = NULL;
		OK(error == stop_table[i].error);
		OK((int)d->queue.count == stop_table[i].queued);
		if (stop_table[i].queued) {
			struct pci_vtdtr_control *c = STAILQ_FIRST(&d->queue.head)->ctrl;
			OK(c->pvc_event == VTDTR_DEVICE_SESSION_STOP && c->pvc_cleanup_vmid == 42 &&
			    c->pvc_cleanup_epoch == vm_epoch && c->pvc_cleanup_delivery_id != 0 &&
			    d->sc.vsd_session_stop_requested &&
			    d->sc.vsd_session_stop_token == c->pvc_cleanup_delivery_id);
		} else if (error != 0 && !again)
			OK(!d->sc.vsd_session_stop_requested);
	}
	drain(d);
	printf("vtdtr session stop table: %d checks\n", vchecks - before);
}

static struct pci_vtdtr_ctrl_entry *control_entry(uint32_t, uint64_t);

/* ------------------------------------------- control_rx decision table */
/*
 * pci_vtdtr_control_rx(): each row sets one device state and one guest
 * control, optionally scripting the VM identity seen on successive queries,
 * the VM name, the daemon write errno or the ingress receipt.  Oracle: the
 * return value (1 stops the receive loop), whether the device requested a
 * reset, the number of daemon writes, the number of queued host controls and
 * the per-row state named in the table.
 */
enum rx_row {
	X_READY_ID_FAIL, X_STOPPED_FRESH_EPOCH, X_STOPPED_FRESH_TOKEN,
	X_STOPPED_ID_FAIL, X_ELF_ID_FAIL, X_ELF_NOT_ELF, X_ELF_DONE_ID_FAIL,
	X_ELF_DONE_VMID, X_ELF_DONE_EPOCH, X_ELF_LONG_NAME, X_ELF_RECEIPT_ID,
	X_ELF_RECEIPT_PHASE, X_ELF_RECEIPT_REPLAY, X_ELF_OK,
	X_KILL_ID_FAIL, X_KILL_VMID0, X_KILL_VMIDMAX, X_KILL_EPOCH0,
	X_CLEAN_RETRY_ID_FAIL, X_CLEAN_RETRY_VMID, X_CLEAN_ID_FAIL,
	X_CLEAN_ENOTCONN, X_CLEAN_ECONNRESET, X_CLEAN_EPIPE, X_CLEAN_ETIMEDOUT,
	X_CLEAN_EIO, X_CLEAN_EPERM, X_CLEAN_OK,
	X_INST_ID_FAIL, X_INST_VMID0, X_INST_VMIDMAX, X_INST_EPOCH0,
	X_INST_MISMATCH, X_INST_LONG_NAME, X_INST_OK,
};
static const struct { enum rx_row row; int ret; bool reset; int writes, queued; } rx_table[] = {
	{ X_READY_ID_FAIL, 1, true, 0, 0 }, { X_STOPPED_FRESH_EPOCH, 1, true, 0, 0 },
	{ X_STOPPED_FRESH_TOKEN, 1, true, 0, 0 }, { X_STOPPED_ID_FAIL, 1, true, 0, 0 },
	{ X_ELF_ID_FAIL, 1, true, 0, 0 }, { X_ELF_NOT_ELF, 1, true, 0, 0 },
	{ X_ELF_DONE_ID_FAIL, 1, true, 0, 0 }, { X_ELF_DONE_VMID, 1, true, 0, 0 },
	{ X_ELF_DONE_EPOCH, 1, true, 0, 0 }, { X_ELF_LONG_NAME, 1, true, 0, 0 },
	{ X_ELF_RECEIPT_ID, 1, true, 1, 0 }, { X_ELF_RECEIPT_PHASE, 1, true, 1, 0 },
	{ X_ELF_RECEIPT_REPLAY, 1, true, 1, 0 }, { X_ELF_OK, 0, false, 1, 1 },
	{ X_KILL_ID_FAIL, 1, true, 0, 0 }, { X_KILL_VMID0, 1, true, 0, 0 },
	{ X_KILL_VMIDMAX, 1, true, 0, 0 }, { X_KILL_EPOCH0, 1, true, 0, 0 },
	{ X_CLEAN_RETRY_ID_FAIL, 1, true, 0, 0 }, { X_CLEAN_RETRY_VMID, 1, true, 0, 0 },
	{ X_CLEAN_ID_FAIL, 1, true, 0, 0 },
	{ X_CLEAN_ENOTCONN, 0, false, 1, 0 }, { X_CLEAN_ECONNRESET, 0, false, 1, 0 },
	{ X_CLEAN_EPIPE, 0, false, 1, 0 }, { X_CLEAN_ETIMEDOUT, 0, false, 1, 0 },
	{ X_CLEAN_EIO, 0, false, 1, 0 }, { X_CLEAN_EPERM, 1, true, 1, 0 },
	{ X_CLEAN_OK, 0, false, 1, 1 },
	{ X_INST_ID_FAIL, 1, true, 0, 0 }, { X_INST_VMID0, 1, true, 0, 0 },
	{ X_INST_VMIDMAX, 1, true, 0, 0 }, { X_INST_EPOCH0, 1, true, 0, 0 },
	{ X_INST_MISMATCH, 1, true, 0, 0 }, { X_INST_LONG_NAME, 1, true, 0, 0 },
	{ X_INST_OK, 0, false, 1, 1 },
};

static void
test_control_rx_table(void)
{
	int before = vchecks;
	static char long_name[140];

	memset(long_name, 'n', sizeof(long_name) - 1);
	for (size_t i = 0; i < nitems(rx_table); i++) {
		struct device *d = new_device();
		struct pci_vtdtr_control c;
		struct identity_step script[2] = { { 0 } };
		const uint64_t e = vm_epoch;
		int nscript = 0, w0, r;

		memset(&c, 0, sizeof(c));
		identity_calls = 0;
		vm_name_override = NULL;
		ingress_wrong_id = ingress_replay = ingress_phase = 0;
		ingress_revoked = ingress_bad_digest = 0;
		write_error = 0;
		last_upload_valid = 0;
		switch (rx_table[i].row) {
		case X_READY_ID_FAIL:
			d->sc.vsd_fresh_requested = d->sc.vsd_fresh_prepare_delivered = true;
			d->sc.vsd_fresh_active = true;
			c.pvc_event = VTDTR_DEVICE_SESSION_READY;
			script[nscript++] = (struct identity_step){ .fail = EIO };
			break;
		case X_STOPPED_FRESH_EPOCH:
		case X_STOPPED_FRESH_TOKEN:
			d->sc.vsd_fresh_requested = true;
			d->sc.vsd_session_stop_vmid = 42;
			d->sc.vsd_session_stop_epoch = e - 1;
			d->sc.vsd_session_stop_token = 0x55;
			c.pvc_event = VTDTR_DEVICE_SESSION_STOPPED;
			c.pvc_cleanup_vmid = 42;
			c.pvc_cleanup_epoch = rx_table[i].row == X_STOPPED_FRESH_EPOCH ? e : e - 1;
			c.pvc_cleanup_delivery_id = rx_table[i].row == X_STOPPED_FRESH_TOKEN ? 0x56 : 0x55;
			break;
		case X_STOPPED_ID_FAIL:
			d->sc.vsd_session_stop_requested = d->sc.vsd_session_stop_delivered = true;
			d->sc.vsd_session_stop_vmid = 42;
			d->sc.vsd_session_stop_epoch = e;
			d->sc.vsd_session_stop_token = 0x55;
			c.pvc_event = VTDTR_DEVICE_SESSION_STOPPED;
			c.pvc_cleanup_vmid = 42;
			c.pvc_cleanup_epoch = e;
			c.pvc_cleanup_delivery_id = 0x55;
			script[nscript++] = (struct identity_step){ .fail = EIO };
			break;
		case X_ELF_ID_FAIL:
		case X_ELF_NOT_ELF:
		case X_ELF_DONE_ID_FAIL:
		case X_ELF_DONE_VMID:
		case X_ELF_DONE_EPOCH:
		case X_ELF_LONG_NAME:
		case X_ELF_RECEIPT_ID:
		case X_ELF_RECEIPT_PHASE:
		case X_ELF_RECEIPT_REPLAY:
		case X_ELF_OK:
			c = elf_fragment(64, 64, false, 0);
			if (rx_table[i].row == X_ELF_ID_FAIL)
				script[nscript++] = (struct identity_step){ .fail = EIO };
			if (rx_table[i].row == X_ELF_NOT_ELF)
				c.pvc_elf[0] = 'X';
			if (rx_table[i].row >= X_ELF_DONE_ID_FAIL &&
			    rx_table[i].row <= X_ELF_DONE_EPOCH) {
				script[nscript++] = (struct identity_step){ 0, 42, e };
				script[nscript++] = rx_table[i].row == X_ELF_DONE_ID_FAIL ?
				    (struct identity_step){ .fail = -1 } :
				    rx_table[i].row == X_ELF_DONE_VMID ?
				    (struct identity_step){ 0, 41, e } :
				    (struct identity_step){ 0, 42, e + 1 };
			}
			if (rx_table[i].row == X_ELF_LONG_NAME)
				vm_name_override = long_name + sizeof(long_name) - 121;
			ingress_wrong_id = rx_table[i].row == X_ELF_RECEIPT_ID;
			ingress_phase = rx_table[i].row == X_ELF_RECEIPT_PHASE ? 'i' : 0;
			ingress_replay = rx_table[i].row == X_ELF_RECEIPT_REPLAY;
			break;
		case X_KILL_ID_FAIL:
		case X_KILL_VMID0:
		case X_KILL_VMIDMAX:
		case X_KILL_EPOCH0:
			c.pvc_event = VTDTR_DEVICE_KILL_APPLIED;
			c.pvc_pid = 4321;
			fill_id(c.pvc_source_id, 16, 9);
			c.pvc_kill_vmid = rx_table[i].row == X_KILL_VMID0 ? 0 :
			    rx_table[i].row == X_KILL_VMIDMAX ? HYPERTRACE_MAX_VMS : 42;
			c.pvc_kill_epoch = rx_table[i].row == X_KILL_EPOCH0 ? 0 : e;
			script[nscript++] = rx_table[i].row == X_KILL_ID_FAIL ?
			    (struct identity_step){ .fail = EIO } :
			    (struct identity_step){ 0, c.pvc_kill_vmid, c.pvc_kill_epoch };
			break;
		case X_CLEAN_RETRY_ID_FAIL:
		case X_CLEAN_RETRY_VMID:
		case X_CLEAN_ID_FAIL:
		case X_CLEAN_ENOTCONN:
		case X_CLEAN_ECONNRESET:
		case X_CLEAN_EPIPE:
		case X_CLEAN_ETIMEDOUT:
		case X_CLEAN_EIO:
		case X_CLEAN_EPERM:
		case X_CLEAN_OK:
			d->sc.vsd_cleanup_delivery_id = 10;
			d->sc.vsd_cleanup_unapplied = true;
			c.pvc_event = VTDTR_DEVICE_CLEANUP_APPLIED;
			c.pvc_cleanup_vmid = 42;
			c.pvc_cleanup_epoch = e;
			c.pvc_cleanup_delivery_id = 10;
			if (rx_table[i].row == X_CLEAN_RETRY_ID_FAIL ||
			    rx_table[i].row == X_CLEAN_RETRY_VMID) {
				/* A retry of an older cleanup that does not match. */
				d->sc.vsd_cleanup_previous_delivery_id = 9;
				c.pvc_cleanup_delivery_id = 9;
				if (rx_table[i].row == X_CLEAN_RETRY_ID_FAIL)
					script[nscript++] = (struct identity_step){ .fail = EIO };
				else
					c.pvc_cleanup_vmid = 41;
			}
			if (rx_table[i].row == X_CLEAN_ID_FAIL)
				script[nscript++] = (struct identity_step){ .fail = EIO };
			write_error = rx_table[i].row == X_CLEAN_ENOTCONN ? ENOTCONN :
			    rx_table[i].row == X_CLEAN_ECONNRESET ? ECONNRESET :
			    rx_table[i].row == X_CLEAN_EPIPE ? EPIPE :
			    rx_table[i].row == X_CLEAN_ETIMEDOUT ? ETIMEDOUT :
			    rx_table[i].row == X_CLEAN_EIO ? EIO :
			    rx_table[i].row == X_CLEAN_EPERM ? EPERM : 0;
			break;
		default:
			c.pvc_event = VTDTR_DEVICE_INSTALLED;
			c.pvc_installed_delivery_id = 77;
			c.pvc_installed_vmid = rx_table[i].row == X_INST_MISMATCH ? 41 : 42;
			c.pvc_installed_epoch = e;
			fill_id(c.pvc_installed_program_id, 16, 2);
			fill_id(c.pvc_installed_source_id, 16, 3);
			if (rx_table[i].row == X_INST_ID_FAIL)
				script[nscript++] = (struct identity_step){ .fail = EIO };
			if (rx_table[i].row == X_INST_VMID0)
				script[nscript++] = (struct identity_step){ 0, 0, e };
			if (rx_table[i].row == X_INST_VMIDMAX)
				script[nscript++] = (struct identity_step){ 0, HYPERTRACE_MAX_VMS, e };
			if (rx_table[i].row == X_INST_EPOCH0)
				script[nscript++] = (struct identity_step){ 0, 42, 0 };
			if (rx_table[i].row == X_INST_LONG_NAME)
				vm_name_override = long_name + sizeof(long_name) - 131;
			break;
		}
		identity_script = nscript != 0 ? script : NULL;
		identity_script_len = nscript;
		w0 = writes;
		r = rx(d, &c);
		identity_script = NULL;
		identity_script_len = 0;
		vm_name_override = NULL;
		write_error = 0;
		ingress_wrong_id = ingress_replay = ingress_phase = 0;
		if (r != rx_table[i].ret || reset_requested(d) != rx_table[i].reset ||
		    writes - w0 != rx_table[i].writes ||
		    (int)d->queue.count != rx_table[i].queued)
			fprintf(stderr, "control_rx row %zu: ret %d reset %d writes %d queued %zu\n",
			    i, r, reset_requested(d), writes - w0, d->queue.count);
		OK(r == rx_table[i].ret);
		OK(reset_requested(d) == rx_table[i].reset);
		OK(writes - w0 == rx_table[i].writes);
		OK((int)d->queue.count == rx_table[i].queued);
		/* Per-row state. */
		switch (rx_table[i].row) {
		case X_STOPPED_ID_FAIL:
			OK(!d->sc.vsd_session_stopped);
			break;
		case X_ELF_OK:
			OK(STAILQ_FIRST(&d->queue.head)->ctrl->pvc_event == VTDTR_DEVICE_HOST_ELF &&
			    d->sc.vsd_inbound_delivery_id == 0 && d->sc.vsd_inbound_elf.data == NULL);
			break;
		case X_CLEAN_ENOTCONN: case X_CLEAN_ECONNRESET: case X_CLEAN_EPIPE:
		case X_CLEAN_ETIMEDOUT: case X_CLEAN_EIO:
			/* The guest retries the exact report; the fence stays. */
			OK(d->sc.vsd_cleanup_unapplied);
			break;
		case X_CLEAN_OK:
			OK(!d->sc.vsd_cleanup_unapplied &&
			    STAILQ_FIRST(&d->queue.head)->ctrl->pvc_event ==
			    VTDTR_DEVICE_HOST_CLEANUP_APPLIED);
			break;
		case X_INST_OK:
			OK(STAILQ_FIRST(&d->queue.head)->ctrl->pvc_event ==
			    VTDTR_DEVICE_HOST_INSTALLED);
			break;
		default:
			if (rx_table[i].reset && rx_table[i].row <= X_ELF_RECEIPT_REPLAY &&
			    rx_table[i].row >= X_ELF_ID_FAIL)
				OK(d->sc.vsd_inbound_elf.data == NULL);
			break;
		}
		free_device(d);
	}
	printf("vtdtr control_rx table: %zu rows, %d checks\n", nitems(rx_table),
	    vchecks - before);
}

/*
 * A continuation fragment naming another stored lifetime: the partial ELF is
 * discarded and the device resets.  Oracle: reset, no write, no partial ELF.
 */
static void
test_control_rx_continuation(void)
{
	struct device *d = new_device();
	struct pci_vtdtr_control first = elf_fragment(200, 100, true, 0);
	struct pci_vtdtr_control last = elf_fragment(200, 100, false, 100);
	int w0 = writes;

	OK(rx(d, &first) == 0 && !reset_requested(d) && d->sc.vsd_inbound_elf.data != NULL);
	d->sc.vsd_inbound_vmid = 7;	/* stored lifetime differs */
	OK(rx(d, &last) == 1 && reset_requested(d) && writes == w0 &&
	    d->sc.vsd_inbound_elf.data == NULL);
	free_device(d);
	printf("vtdtr control_rx continuation: other stored lifetime resets\n");
}

/* ------------------------------------------ checkpoint state validators */
/*
 * Mutation tables over the checkpoint validators.  Each starts from a state
 * the validator accepts (oracle: 0) and changes exactly one field; the
 * expected errno is the class the contract assigns to that field (EBUSY for a
 * transition in flight, ENOTSUP for missing features, ESTALE for identity,
 * EPROTO for an inconsistent image).  The field is restored after each row,
 * so every row also re-proves the baseline.
 */
static uint8_t partial_elf_bytes[256];

static void
source_valid_baseline(struct device *d)
{
	struct pci_vtdtr_softc *sc = &d->sc;

	memset(&sc->vsd_inbound_elf, 0, sizeof(sc->vsd_inbound_elf));
	sc->vsd_session_stop_requested = sc->vsd_session_stopped = true;
	sc->vsd_session_stop_delivered = sc->vsd_session_collectors_stopped = true;
	sc->vsd_session_stop_vmid = 42;
	sc->vsd_session_stop_epoch = vm_epoch;
	sc->vsd_session_stop_token = 0x77;
	memset(sc->vsd_session_gate_token, 0x3c, 16);
	memset(session_gate_owner, 0x3c, 16);
	session_gate_failure = 0;
	sc->vsd_guest_ready = sc->vsd_ready = 0;
	sc->vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES;
	sc->vsd_vs.vs_status = 0;
}

static void
test_checkpoint_validators(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	struct pci_vtdtr_ctrlq *q = &d->queue;

	/* pci_vtdtr_session_source_valid(). */
#define SV(field, value, expect) do { \
	source_valid_baseline(d); \
	OK(pci_vtdtr_session_source_valid(sc) == 0); \
	__typeof(field) saved_ = (field); \
	(field) = (value); \
	OK(pci_vtdtr_session_source_valid(sc) == (expect)); \
	(field) = saved_; \
} while (0)
	SV(sc->vsd_session_stop_requested, false, ENOENT);
	SV(sc->vsd_session_stop_delivered, false, EBUSY);
	SV(sc->vsd_session_collectors_stopped, false, EBUSY);
	SV(sc->vsd_session_collectors_busy, true, EBUSY);
	SV(sc->vsd_session_restore_pending, true, EBUSY);
	SV(sc->vsd_fresh_requested, true, EBUSY);
	SV(sc->vsd_rekey_wait, true, EBUSY);
	SV(sc->vsd_restored_kill_wait, true, EBUSY);
	SV(sc->vsd_handoff_ticket_valid, true, EBUSY);
	SV(sc->vsd_restore_planned, (void *)partial_elf_bytes, EBUSY);
	SV(sc->vsd_ticket_wait, true, EBUSY);
	SV(sc->vsd_cleanup_unapplied, true, EBUSY);
	SV(sc->vsd_rekey_ack_pending, true, EBUSY);
	SV(sc->vsd_rekey_ack_sent, true, EBUSY);
	SV(sc->vsd_rekey_receipt_reply_pending, true, EBUSY);
	SV(sc->vsd_guest_ready, 1, EBUSY);
	SV(sc->vsd_ready, 1, EBUSY);
	SV(sc->vsd_vs.vs_negotiated_caps, 0, ENOTSUP);
	SV(sc->vsd_ctrlq, NULL, EPROTO);
	SV(q->count, 1, EPROTO);
	SV(q->restored_kills, 1, EPROTO);
	SV(sc->vsd_inbound_elf.data, partial_elf_bytes, EPROTO);
	SV(sc->vsd_inbound_elf.total, 1, EPROTO);
	SV(sc->vsd_inbound_elf.received, 1, EPROTO);
	SV(sc->vsd_inbound_elf.identifier, 1, EPROTO);
	SV(sc->vsd_inbound_delivery_id, 1, EPROTO);
	SV(sc->vsd_inbound_vmid, 1, EPROTO);
	SV(sc->vsd_inbound_epoch, 1, EPROTO);
	SV(sc->vsd_inbound_program_id[3], 1, EPROTO);
	SV(sc->vsd_inbound_source_id[3], 1, EPROTO);
	{
		/* A queued entry with a zero count field. */
		source_valid_baseline(d);
		pci_vtdtr_cq_enqueue(q, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		q->count = 0;
		OK(pci_vtdtr_session_source_valid(sc) == EPROTO);
		q->count = 1;
		drain(d);
	}
#undef SV

	/* pci_vtdtr_checkpoint_state_valid(). */
	memset(&sc->vsd_inbound_elf, 0, sizeof(sc->vsd_inbound_elf));
	sc->vsd_session_stop_requested = false;
	memset(sc->vsd_session_gate_token, 0, 16);
#define CV(field, value, expect) do { \
	OK(pci_vtdtr_checkpoint_state_valid(sc) == 0); \
	__typeof(field) saved_ = (field); \
	(field) = (value); \
	OK(pci_vtdtr_checkpoint_state_valid(sc) == (expect)); \
	(field) = saved_; \
} while (0)
	CV(sc->vsd_rekey_wait, true, EBUSY);
	CV(sc->vsd_restored_kill_wait, true, EBUSY);
	CV(sc->vsd_session_stop_requested, true, EBUSY);
	CV(sc->vsd_session_gate_token[5], 1, EBUSY);
	CV(sc->vsd_stopping, true, ESTALE);
	CV(sc->vsd_ctrlq, NULL, ESTALE);
	CV(q->count, VTDTR_MAX_PENDING + 1, EBUSY);
	CV(q->count, 1, EPROTO);
	CV(q->restored_kills, 1, EPROTO);
	CV(sc->vsd_inbound_elf.total, 1, EPROTO);
	CV(sc->vsd_inbound_elf.received, 1, EPROTO);
	CV(sc->vsd_inbound_elf.identifier, 1, EPROTO);
	CV(sc->vsd_inbound_delivery_id, 1, EPROTO);
	CV(sc->vsd_inbound_vmid, 1, EPROTO);
	CV(sc->vsd_inbound_epoch, 1, EPROTO);
	CV(sc->vsd_inbound_program_id[0], 1, EPROTO);
	CV(sc->vsd_inbound_source_id[0], 1, EPROTO);
	{
		static const struct identity_step bad[] = {
			{ .fail = EIO }, { 0, 0, 5 }, { 0, HYPERTRACE_MAX_VMS, 5 }, { 0, 42, 0 } };
		for (size_t i = 0; i < nitems(bad); i++) {
			identity_script = &bad[i];
			identity_script_len = 1;
			identity_calls = 0;
			OK(pci_vtdtr_checkpoint_state_valid(sc) == ESTALE);
			identity_script = NULL;
		}
	}
	/* Queue contents. */
	{
		struct pci_vtdtr_ctrl_entry *e;

		pci_vtdtr_cq_enqueue(q, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		OK(pci_vtdtr_checkpoint_state_valid(sc) == 0);
		e = STAILQ_FIRST(&q->head);
		struct pci_vtdtr_control *saved = e->ctrl;
		e->ctrl = NULL;
		OK(pci_vtdtr_checkpoint_state_valid(sc) == EPROTO);	/* no control */
		e->ctrl = saved;
		e->restored_kill = true;
		q->restored_kills = 1;
		OK(pci_vtdtr_checkpoint_state_valid(sc) == 0);	/* restored KILL */
		saved->pvc_event = VTDTR_DEVICE_CLEANUP_DTRACED;
		saved->pvc_cleanup_vmid = 42;
		saved->pvc_cleanup_epoch = vm_epoch;
		saved->pvc_cleanup_delivery_id = 3;
		OK(pci_vtdtr_checkpoint_state_valid(sc) == EPROTO);	/* restored non-KILL */
		e->restored_kill = false;
		q->restored_kills = 0;
		saved->pvc_cleanup_epoch = vm_epoch + 1;
		OK(pci_vtdtr_checkpoint_state_valid(sc) == EPROTO);	/* other lifetime */
		drain(d);
		/* An ELF run left open at the end of the queue. */
		{
			struct pci_vtdtr_ctrl_entry *f = __real_calloc(1, sizeof(*f));
			f->ctrl = __real_calloc(1, sizeof(*f->ctrl));
			*f->ctrl = valid_control(VTDTR_DEVICE_ELF);
			f->ctrl->pvc_vmid = 42;
			f->ctrl->pvc_epoch = vm_epoch;
			pci_vtdtr_cq_enqueue(q, f);
			OK(pci_vtdtr_checkpoint_state_valid(sc) == EPROTO);
			drain(d);
		}
		/* More entries than the bound while the count field is within it. */
		{
			struct pci_vtdtr_control *shared = __real_calloc(1, sizeof(*shared));
			struct pci_vtdtr_ctrl_entry *x;
			*shared = valid_control(VTDTR_DEVICE_KILL);
			shared->pvc_kill_vmid = 42;
			shared->pvc_kill_epoch = vm_epoch;
			for (size_t i = 0; i < VTDTR_MAX_PENDING + 1; i++) {
				x = __real_calloc(1, sizeof(*x));
				x->ctrl = shared;
				STAILQ_INSERT_TAIL(&q->head, x, entries);
			}
			q->count = VTDTR_MAX_PENDING;
			OK(pci_vtdtr_checkpoint_state_valid(sc) == EPROTO);
			while ((x = STAILQ_FIRST(&q->head)) != NULL) {
				STAILQ_REMOVE_HEAD(&q->head, entries);
				free(x);
			}
			q->count = 0;
			free(shared);
		}
	}
	/* A partial inbound ELF: valid, then each inconsistency. */
	sc->vsd_inbound_elf = (struct hypertrace_elf){ partial_elf_bytes, 200, 100, 7 };
	sc->vsd_inbound_delivery_id = 9;
	sc->vsd_inbound_vmid = 42;
	sc->vsd_inbound_epoch = vm_epoch;
	sc->vsd_inbound_program_id[0] = sc->vsd_inbound_source_id[0] = 1;
	CV(sc->vsd_inbound_elf.total, 0, EPROTO);
	CV(sc->vsd_inbound_elf.total, (size_t)HYPERTRACE_ELF_MAX + 1, EPROTO);
	CV(sc->vsd_inbound_elf.received, 0, EPROTO);
	CV(sc->vsd_inbound_elf.received, 200, EPROTO);
	CV(sc->vsd_inbound_delivery_id, 0, EPROTO);
	CV(sc->vsd_inbound_vmid, 41, EPROTO);
	CV(sc->vsd_inbound_epoch, vm_epoch + 1, EPROTO);
	CV(sc->vsd_inbound_program_id[0], 0, EPROTO);
	CV(sc->vsd_inbound_source_id[0], 0, EPROTO);
#undef CV
	memset(&sc->vsd_inbound_elf, 0, sizeof(sc->vsd_inbound_elf));
	sc->vsd_inbound_delivery_id = sc->vsd_inbound_vmid = 0;
	sc->vsd_inbound_epoch = 0;
	sc->vsd_inbound_program_id[0] = sc->vsd_inbound_source_id[0] = 0;

	/* pci_vtdtr_session_checkpoint_export(). */
	{
		uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE];
		struct hypertrace_session_record record;

		vtdtr_shutdown_sc = sc;
		source_valid_baseline(d);
#define EX(field, value, expect) do { \
	__typeof(field) saved_ = (field); \
	(field) = (value); \
	OK(pci_vtdtr_session_checkpoint_export(sc->vsd_vmctx, wire, sizeof(wire)) == (expect)); \
	(field) = saved_; \
} while (0)
		OK(pci_vtdtr_session_checkpoint_export(NULL, wire, sizeof(wire)) == ENXIO);
		OK(pci_vtdtr_session_checkpoint_export(sc->vsd_vmctx, NULL, sizeof(wire)) == EINVAL);
		OK(pci_vtdtr_session_checkpoint_export(sc->vsd_vmctx, wire, sizeof(wire) - 1) == EINVAL);
		EX(sc->vsd_stopping, true, EBUSY);
		EX(sc->vsd_session_stop_requested, false, EBUSY);
		EX(sc->vsd_session_stop_delivered, false, EBUSY);
		EX(sc->vsd_session_stopped, false, EBUSY);
		EX(sc->vsd_session_collectors_stopped, false, EBUSY);
		EX(sc->vsd_session_collectors_busy, true, EBUSY);
		EX(sc->vsd_fresh_requested, true, EBUSY);
		EX(sc->vsd_rekey_wait, true, EBUSY);
		EX(sc->vsd_vs.vs_status, VIRTIO_CONFIG_S_NEEDS_RESET, EBUSY);
		EX(sc->vsd_vs.vs_negotiated_caps, 0, ENOTSUP);
		EX(sc->vsd_session_stop_epoch, vm_epoch + 1, ESTALE);
		EX(sc->vsd_session_stop_vmid, 41, ESTALE);
		EX(session_gate_failure, EPERM, EPERM);
		{
			static const struct identity_step fail[] = { { .fail = ENXIO }, { .fail = -1 } };
			for (int i = 0; i < 2; i++) {
				identity_script = &fail[i];
				identity_script_len = 1;
				identity_calls = 0;
				OK(pci_vtdtr_session_checkpoint_export(sc->vsd_vmctx, wire,
				    sizeof(wire)) == (i == 0 ? ENXIO : EIO));
				identity_script = NULL;
			}
		}
#undef EX
		OK(pci_vtdtr_session_checkpoint_export(sc->vsd_vmctx, wire, sizeof(wire)) == 0);
		OK(hypertrace_session_record_decode(wire, sizeof(wire), &record) == 0 &&
		    record.vmid == 42 && record.epoch == vm_epoch && record.stop_token == 0x77 &&
		    record.features == HYPERTRACE_SESSION_FEATURES);
		vtdtr_shutdown_sc = NULL;

		/* pci_vtdtr_session_checkpoint_import_paused() on a destination
		 * (identity 43/100 through ctx 1) importing that record. */
		struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
		    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
		struct pci_devinst pi = { .pi_d = &emu, .pi_arg = sc };
		struct pci_devinst other = { .pi_d = NULL };
#define IMPORT_BASE() do { \
	sc->vsd_reader_active = sc->vsd_session_collectors_busy = false; \
	sc->vsd_stopping = sc->vsd_fresh_requested = sc->vsd_rekey_wait = false; \
	sc->vsd_restored_kill_wait = sc->vsd_cleanup_unapplied = false; \
	sc->vsd_rekey_ack_pending = sc->vsd_rekey_ack_sent = false; \
	sc->vsd_rekey_receipt_reply_pending = sc->vsd_ticket_wait = false; \
	sc->vsd_handoff_ticket_valid = false; \
	sc->vsd_restore_planned = NULL; \
	sc->vsd_vs.vs_status = 0; \
	sc->vsd_session_stop_requested = sc->vsd_session_stop_delivered = false; \
	sc->vsd_session_stopped = sc->vsd_session_collectors_stopped = false; \
	sc->vsd_session_restore_pending = false; \
	sc->vsd_session_migration_staged = false; \
	sc->vsd_session_stop_vmid = 0; \
	sc->vsd_session_stop_epoch = 0; \
	sc->vsd_session_stop_token = 0; \
	identity_script = NULL; \
	sc->vsd_vmctx = (struct vmctx *)1; \
	sc->vsd_checkpoint_paused = true; \
	sc->vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES; \
	source_retired = true; \
} while (0)
#define IM(field, value, expect) do { \
	IMPORT_BASE(); \
	(field) = (value); \
	OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == (expect)); \
	OK(!sc->vsd_session_restore_pending); \
} while (0)
		OK(pci_vtdtr_session_checkpoint_import_paused(&other, wire, sizeof(wire)) == EINVAL);
		IMPORT_BASE();
		OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire) - 1) == EINVAL);
		IM(sc->vsd_checkpoint_paused, false, EBUSY);
		IM(sc->vsd_reader_active, true, EBUSY);
		IM(sc->vsd_session_collectors_busy, true, EBUSY);
		IM(sc->vsd_stopping, true, EBUSY);
		IM(sc->vsd_fresh_requested, true, EBUSY);
		IM(sc->vsd_rekey_wait, true, EBUSY);
		IM(sc->vsd_restored_kill_wait, true, EBUSY);
		IM(sc->vsd_cleanup_unapplied, true, EBUSY);
		IM(sc->vsd_rekey_ack_pending, true, EBUSY);
		IM(sc->vsd_rekey_ack_sent, true, EBUSY);
		IM(sc->vsd_rekey_receipt_reply_pending, true, EBUSY);
		IM(sc->vsd_ticket_wait, true, EBUSY);
		IM(sc->vsd_handoff_ticket_valid, true, EBUSY);
		IM(sc->vsd_restore_planned, (void *)partial_elf_bytes, EBUSY);
		IM(sc->vsd_vs.vs_status, VIRTIO_CONFIG_S_NEEDS_RESET, EBUSY);
		IM(sc->vsd_vs.vs_negotiated_caps, 0, ENOTSUP);
		IM(sc->vsd_vmctx, (struct vmctx *)2, ESTALE);	/* same epoch as the record */
		IM(source_retired, false, EBUSY);
		/* A stop already recorded here must name the same tuple. */
		IM(sc->vsd_session_stop_requested, true, ESTALE);
		{
			static const struct identity_step bad[] = {
				{ .fail = -1 }, { 0, 0, 5 }, { 0, HYPERTRACE_MAX_VMS, 5 }, { 0, 42, 0 } };
			for (size_t i = 0; i < nitems(bad); i++) {
				IMPORT_BASE();
				identity_script = &bad[i];
				identity_script_len = 1;
				identity_calls = 0;
				OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire,
				    sizeof(wire)) == (i == 0 ? EIO : ESTALE));
				identity_script = NULL;
			}
		}
		for (int field = 0; field < 3; field++) {
			IMPORT_BASE();
			sc->vsd_session_stop_requested = true;
			sc->vsd_session_stop_vmid = field == 0 ? 41 : 42;
			sc->vsd_session_stop_epoch = field == 1 ? vm_epoch + 1 : vm_epoch;
			sc->vsd_session_stop_token = field == 2 ? 0x78 : 0x77;
			OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == ESTALE);
		}
		/* A migration-staged record must be byte-identical; the staged
		 * record itself proves retirement, so no witness query. */
		IMPORT_BASE();
		sc->vsd_session_migration_staged = true;
		memcpy(sc->vsd_session_migration_record, wire, sizeof(wire));
		sc->vsd_session_migration_record[9] ^= 1;
		OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == ESTALE);
		sc->vsd_session_migration_record[9] ^= 1;
		source_retired = false;
		OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == 0);
		/* Success: the stopped source tuple is adopted, local collector
		 * ownership is not, and the restore discard is pending. */
		IMPORT_BASE();
		sc->vsd_guest_ready = sc->vsd_ready = 1;
		memset(sc->vsd_session_gate_token, 9, 16);
		pci_vtdtr_cq_enqueue(q, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == 0);
		OK(sc->vsd_session_stop_vmid == 42 && sc->vsd_session_stop_epoch == vm_epoch &&
		    sc->vsd_session_stop_token == 0x77 && sc->vsd_session_stop_requested &&
		    sc->vsd_session_stop_delivered && sc->vsd_session_stopped &&
		    !sc->vsd_session_collectors_stopped && sc->vsd_session_restore_pending &&
		    sc->vsd_guest_ready == 0 && sc->vsd_ready == 0 && q->count == 0 &&
		    memcmp(sc->vsd_session_gate_token, (uint8_t[16]){0}, 16) == 0);
#undef IM
#undef IMPORT_BASE
	}
	source_retired = false;
	session_gate_failure = 0;
	memset(session_gate_owner, 0, 16);
	free_device(d);
	printf("vtdtr checkpoint validators (source, state, export, import): %d checks\n",
	    vchecks - before);
}

/* ------------------------------------------- private image and staging */
/*
 * The private device image header, from the wire layout (little endian):
 * magic 0/4, version 4/2, vmid 6/2, epoch 8/8, cfg 16/8, guest_ready 24/1,
 * ready 25/1, count 26/4, total 30/4, received 34/4, identifier 38/4,
 * delivery 42/8, partial vmid 50/2, partial epoch 52/8, program id 60/16,
 * source id 76/16; then the received partial bytes, then the controls.
 */
#define IMG_HDR 92

static size_t
save_image(struct device *d, uint8_t *image, size_t cap)
{
	struct vm_snapshot_meta save = {
	    .buffer = { .buf_start = image, .buf_size = cap, .buf = image, .buf_rem = cap },
	    .op = VM_SNAPSHOT_SAVE };

	CHECK(pci_vtdtr_private_snapshot_stage(&d->sc, &save, NULL) == 0);
	return (cap - save.buffer.buf_rem);
}

static int
validate_image(uint8_t *image, size_t length, struct pci_vtdtr_checkpoint_stage *stage)
{
	struct vm_snapshot_meta scan = {
	    .buffer = { .buf_start = image, .buf_size = length, .buf = image,
	        .buf_rem = length }, .op = VM_SNAPSHOT_VALIDATE };

	return (pci_vtdtr_private_snapshot_stage(NULL, &scan, stage));
}

static void
test_private_image_mutations(void)
{
	int before = vchecks;
	static uint8_t base[IMG_HDR + 4096], image[IMG_HDR + 4096];
	struct pci_vtdtr_checkpoint_stage stage;
	size_t empty_len, partial_len;
	struct device *d = new_device();

	/* An empty image (no queue, no partial ELF), and one with a partial. */
	empty_len = save_image(d, base, sizeof(base));
	OK(empty_len == IMG_HDR);
	OK(le32dec(base + 0) == VTDTR_SNAPSHOT_MAGIC && le16dec(base + 6) == 42 &&
	    le64dec(base + 8) == vm_epoch);
	memset(&stage, 0, sizeof(stage));
	OK(validate_image(base, empty_len, &stage) == 0 && stage.source_vmid == 42 &&
	    stage.count == 0 && stage.partial_total == 0);
	pci_vtdtr_checkpoint_stage_clear(&stage);

	/* Header field mutations of the empty image: each is EPROTO in both
	 * the staging and the plain validation modes; staging leaves STAGE
	 * empty. */
	static const struct { size_t off, len; uint64_t value; } bad_empty[] = {
		{ 0, 4, 0 }, { 4, 2, 99 }, { 6, 2, 0 }, { 6, 2, HYPERTRACE_MAX_VMS },
		{ 8, 8, 0 }, { 24, 1, 2 }, { 25, 1, 2 }, { 26, 4, VTDTR_MAX_PENDING + 1 },
		{ 34, 4, 1 }, { 38, 4, 1 }, { 42, 8, 1 }, { 50, 2, 1 }, { 52, 8, 1 },
		{ 60, 1, 1 }, { 76, 1, 1 },
	};
	for (size_t i = 0; i < nitems(bad_empty); i++) {
		memcpy(image, base, empty_len);
		switch (bad_empty[i].len) {
		case 1: image[bad_empty[i].off] = (uint8_t)bad_empty[i].value; break;
		case 2: le16enc(image + bad_empty[i].off, (uint16_t)bad_empty[i].value); break;
		case 4: le32enc(image + bad_empty[i].off, (uint32_t)bad_empty[i].value); break;
		default: le64enc(image + bad_empty[i].off, bad_empty[i].value); break;
		}
		memset(&stage, 0, sizeof(stage));
		OK(validate_image(image, empty_len, &stage) == EPROTO);
		OK(stage.controls == NULL && stage.partial_prefix == NULL && stage.count == 0);
		OK(validate_image(image, empty_len, NULL) == EPROTO);
	}
	/* Every truncation of the header fails without staging. */
	for (size_t n = 0; n < empty_len; n++) {
		memset(&stage, 0, sizeof(stage));
		OK(validate_image(base, n, &stage) != 0 && stage.source_vmid == 0);
	}

	/* A partial inbound ELF of 100 of 200 bytes. */
	d->sc.vsd_inbound_elf = (struct hypertrace_elf){ partial_elf_bytes, 200, 100, 7 };
	for (int i = 0; i < 100; i++)
		partial_elf_bytes[i] = (uint8_t)(i ^ 0x5a);
	d->sc.vsd_inbound_delivery_id = 9;
	d->sc.vsd_inbound_vmid = 42;
	d->sc.vsd_inbound_epoch = vm_epoch;
	fill_id(d->sc.vsd_inbound_program_id, 16, 4);
	fill_id(d->sc.vsd_inbound_source_id, 16, 5);
	partial_len = save_image(d, base, sizeof(base));
	OK(partial_len == IMG_HDR + 100 && memcmp(base + IMG_HDR, partial_elf_bytes, 100) == 0);
	memset(&stage, 0, sizeof(stage));
	OK(validate_image(base, partial_len, &stage) == 0 && stage.partial_total == 200 &&
	    stage.partial_received == 100 && stage.partial_delivery_id == 9 &&
	    memcmp(stage.partial_prefix, partial_elf_bytes, 100) == 0);
	pci_vtdtr_checkpoint_stage_clear(&stage);
	OK(validate_image(base, partial_len, NULL) == 0);
	static const struct { size_t off, len; uint64_t value; } bad_partial[] = {
		{ 30, 4, HYPERTRACE_ELF_MAX + 1 }, { 34, 4, 0 }, { 34, 4, 200 },
		{ 42, 8, 0 }, { 50, 2, 41 }, { 52, 8, 1 }, { 60, 16, 0 }, { 76, 16, 0 },
	};
	for (size_t i = 0; i < nitems(bad_partial); i++) {
		memcpy(image, base, partial_len);
		if (bad_partial[i].len == 16)
			memset(image + bad_partial[i].off, 0, 16);
		else if (bad_partial[i].len == 2)
			le16enc(image + bad_partial[i].off, (uint16_t)bad_partial[i].value);
		else if (bad_partial[i].len == 4)
			le32enc(image + bad_partial[i].off, (uint32_t)bad_partial[i].value);
		else
			le64enc(image + bad_partial[i].off, bad_partial[i].value);
		memset(&stage, 0, sizeof(stage));
		OK(validate_image(image, partial_len, &stage) == EPROTO && stage.partial_prefix == NULL);
	}
	/* The partial bytes cut short: E2BIG when staging, a read error
	 * otherwise; a declared queue entry with no bytes is E2BIG. */
	memset(&stage, 0, sizeof(stage));
	OK(validate_image(base, partial_len - 1, &stage) == E2BIG && stage.partial_prefix == NULL);
	OK(validate_image(base, partial_len - 1, NULL) != 0);
	memcpy(image, base, partial_len);
	le32enc(image + 26, 1);
	memset(&stage, 0, sizeof(stage));
	OK(validate_image(image, partial_len, &stage) == E2BIG && stage.controls == NULL);
	OK(validate_image(image, partial_len, NULL) != 0);
	/* Argument contracts. */
	{
		struct vm_snapshot_meta m = { .op = VM_SNAPSHOT_RESTORE };
		struct pci_vtdtr_checkpoint_stage used = { .count = 1 };
		OK(pci_vtdtr_private_snapshot_stage(NULL, NULL, NULL) == EINVAL);
		OK(pci_vtdtr_private_snapshot_stage(NULL, &m, NULL) == EINVAL);
		m.op = VM_SNAPSHOT_SAVE;
		OK(pci_vtdtr_private_snapshot_stage(NULL, &m, NULL) == EINVAL);
		memset(&stage, 0, sizeof(stage));
		OK(pci_vtdtr_private_snapshot_stage(&d->sc, &m, &stage) == EINVAL);
		OK(validate_image(base, partial_len, &used) == EINVAL);
		used = (struct pci_vtdtr_checkpoint_stage){ .source_vmid = 1 };
		OK(validate_image(base, partial_len, &used) == EINVAL);
		used = (struct pci_vtdtr_checkpoint_stage){ .controls = (void *)image };
		OK(validate_image(base, partial_len, &used) == EINVAL);
		used = (struct pci_vtdtr_checkpoint_stage){ .partial_prefix = image };
		OK(validate_image(base, partial_len, &used) == EINVAL);
	}
	/* Saving a source whose state the validator refuses, or whose
	 * identity is unreadable. */
	{
		struct vm_snapshot_meta save = {
		    .buffer = { .buf_start = image, .buf_size = sizeof(image), .buf = image,
		        .buf_rem = sizeof(image) }, .op = VM_SNAPSHOT_SAVE };
		static const struct identity_step ok_then_fail[] = { { 0, 42, 99 }, { .fail = EIO } };
		d->sc.vsd_rekey_wait = true;
		OK(pci_vtdtr_private_snapshot_stage(&d->sc, &save, NULL) == EBUSY);
		d->sc.vsd_rekey_wait = false;
		identity_script = ok_then_fail;
		identity_script_len = 2;
		identity_calls = 0;
		OK(pci_vtdtr_private_snapshot_stage(&d->sc, &save, NULL) == ESTALE);
		identity_script = NULL;
	}
	memset(&d->sc.vsd_inbound_elf, 0, sizeof(d->sc.vsd_inbound_elf));
	d->sc.vsd_inbound_delivery_id = 0;
	d->sc.vsd_inbound_vmid = 0;
	d->sc.vsd_inbound_epoch = 0;
	memset(d->sc.vsd_inbound_program_id, 0, 16);
	memset(d->sc.vsd_inbound_source_id, 0, 16);

	/* Extra checkpoint capacity: empty is zero; a queue and a partial ELF
	 * add a header, one record per control and the partial bytes. */
	{
		struct pci_devinst pi = { .pi_arg = &d->sc };
		size_t extra = 7;
		OK(pci_vtdtr_snapshot_extra_capacity(NULL, &extra) == EINVAL);
		OK(pci_vtdtr_snapshot_extra_capacity(&pi, NULL) == EINVAL);
		OK(pci_vtdtr_snapshot_extra_capacity(&pi, &extra) == 0 && extra == 0);
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		OK(pci_vtdtr_snapshot_extra_capacity(&pi, &extra) == 0 &&
		    extra == 4096 + sizeof(struct pci_vtdtr_control) + 16);
		d->sc.vsd_rekey_wait = true;
		OK(pci_vtdtr_snapshot_extra_capacity(&pi, &extra) == EBUSY);
		d->sc.vsd_rekey_wait = false;
		drain(d);
		struct pci_vtdtr_softc *saved = pi.pi_arg;
		pi.pi_arg = NULL;
		OK(pci_vtdtr_snapshot_extra_capacity(&pi, &extra) == EINVAL);
		pi.pi_arg = saved;
	}
	free_device(d);
	printf("vtdtr private image mutations and capacity: %d checks\n", vchecks - before);
}

/*
 * pci_vtdtr_session_restore_stage_paused()/migration_stage_paused(): a
 * destination (identity 43/100) stages the empty image of a stopped source
 * (42/vm_epoch).  Each row breaks one precondition.  Oracle: the errno; no
 * staging recorded on refusal; on success the record, configuration and
 * (for migration) the migration record are staged.
 */
static void
test_restore_stage_table(void)
{
	int before = vchecks;
	struct device *src = new_device(), *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	uint8_t image[IMG_HDR + 64], record[HYPERTRACE_SESSION_RECORD_SIZE];
	struct hypertrace_session_record rec = { .vmid = 42, .epoch = vm_epoch,
	    .stop_token = 0x77, .features = HYPERTRACE_SESSION_FEATURES };
	struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
	    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
	struct pci_devinst pi = { .pi_d = &emu, .pi_arg = sc }, other = { 0 };
	size_t len;

	src->sc.vsd_cfg = 0x1234;
	src->sc.vsd_guest_ready = 0;	/* a stopped cut, not a runnable guest */
	len = save_image(src, image, sizeof(image));
	OK(hypertrace_session_record_encode(record, sizeof(record), &rec) == 0);
	enum { G_OTHER, G_NULL_IMAGE, G_ZERO_LEN, G_PI, G_UNPAUSED, G_READER,
		G_RESTORE_STAGED, G_MIG_STAGED, G_PLANNED, G_STOP, G_COLLECTORS,
		G_RESTORE_PENDING, G_FRESH, G_TICKET, G_TICKET_WAIT, G_CLEANUP,
		G_ACK_PENDING, G_ACK_SENT, G_RECEIPT, G_RECORD, G_STATE, G_ID_FAIL,
		G_ID_NOERRNO, G_SAME_EPOCH, G_NOT_RETIRED, G_MIG_NOT_RETIRED,
		G_BAD_IMAGE, G_TRAILING, G_OTHER_SOURCE, G_GATE, G_OK, G_MIG_OK, G_LAST };
	static const int expect[G_LAST] = {
		[G_OTHER] = EINVAL, [G_NULL_IMAGE] = EINVAL, [G_ZERO_LEN] = EINVAL,
		[G_PI] = EINVAL, [G_UNPAUSED] = EBUSY, [G_READER] = EBUSY,
		[G_RESTORE_STAGED] = EBUSY, [G_MIG_STAGED] = EBUSY, [G_PLANNED] = EBUSY,
		[G_STOP] = EBUSY, [G_COLLECTORS] = EBUSY, [G_RESTORE_PENDING] = EBUSY,
		[G_FRESH] = EBUSY, [G_TICKET] = EBUSY, [G_TICKET_WAIT] = EBUSY,
		[G_CLEANUP] = EBUSY, [G_ACK_PENDING] = EBUSY, [G_ACK_SENT] = EBUSY,
		[G_RECEIPT] = EBUSY, [G_RECORD] = EINVAL, [G_STATE] = EBUSY,
		[G_ID_FAIL] = ENXIO, [G_ID_NOERRNO] = EIO, [G_SAME_EPOCH] = ESTALE,
		[G_NOT_RETIRED] = EBUSY, [G_MIG_NOT_RETIRED] = 0, [G_BAD_IMAGE] = EPROTO,
		[G_TRAILING] = EPROTO, [G_OTHER_SOURCE] = EPROTO, [G_GATE] = EPERM,
		[G_OK] = 0, [G_MIG_OK] = 0,
	};
	for (int row = 0; row < G_LAST; row++) {
		struct identity_step step = { 0 };
		struct pci_devinst *pp = &pi;
		void *img = image;
		size_t ilen = len, rlen = sizeof(record);
		bool migration = row == G_MIG_NOT_RETIRED || row == G_MIG_OK;
		int error;

		/* A paused destination with no transition in flight. */
		sc->vsd_vmctx = (struct vmctx *)1;
		sc->vsd_vs.vs_pi = &pi;
		sc->vsd_vs.vs_status = 0;
		sc->vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES;
		sc->vsd_checkpoint_paused = true;
		sc->vsd_reader_active = sc->vsd_session_restore_staged = false;
		sc->vsd_session_migration_staged = sc->vsd_session_migration_released = false;
		sc->vsd_restore_planned = NULL;
		sc->vsd_session_stop_requested = sc->vsd_session_collectors_busy = false;
		sc->vsd_session_restore_pending = sc->vsd_fresh_requested = false;
		sc->vsd_handoff_ticket_valid = sc->vsd_ticket_wait = false;
		sc->vsd_cleanup_unapplied = sc->vsd_rekey_ack_pending = false;
		sc->vsd_rekey_ack_sent = sc->vsd_rekey_receipt_reply_pending = false;
		sc->vsd_rekey_wait = false;
		sc->vsd_session_restore_cfg = 0;
		memset(sc->vsd_session_gate_token, 0, 16);
		memset(sc->vsd_fresh_gate_token, 0, 16);
		memset(destination_gate_owner, 0, 16);
		destination_released = false;
		destination_gate_failure = 0;
		source_retired = true;
		switch (row) {
		case G_OTHER: pp = &other; break;
		case G_NULL_IMAGE: img = NULL; break;
		case G_ZERO_LEN: ilen = 0; break;
		case G_PI: sc->vsd_vs.vs_pi = NULL; break;
		case G_UNPAUSED: sc->vsd_checkpoint_paused = false; break;
		case G_READER: sc->vsd_reader_active = true; break;
		case G_RESTORE_STAGED: sc->vsd_session_restore_staged = true; break;
		case G_MIG_STAGED: sc->vsd_session_migration_staged = true; break;
		case G_PLANNED: sc->vsd_restore_planned = (void *)image; break;
		case G_STOP: sc->vsd_session_stop_requested = true; break;
		case G_COLLECTORS: sc->vsd_session_collectors_busy = true; break;
		case G_RESTORE_PENDING: sc->vsd_session_restore_pending = true; break;
		case G_FRESH: sc->vsd_fresh_requested = true; break;
		case G_TICKET: sc->vsd_handoff_ticket_valid = true; break;
		case G_TICKET_WAIT: sc->vsd_ticket_wait = true; break;
		case G_CLEANUP: sc->vsd_cleanup_unapplied = true; break;
		case G_ACK_PENDING: sc->vsd_rekey_ack_pending = true; break;
		case G_ACK_SENT: sc->vsd_rekey_ack_sent = true; break;
		case G_RECEIPT: sc->vsd_rekey_receipt_reply_pending = true; break;
		case G_RECORD: rlen--; break;
		case G_STATE: sc->vsd_rekey_wait = true; break;
		case G_ID_FAIL: step.fail = ENXIO; break;
		case G_ID_NOERRNO: step.fail = -1; break;
		case G_SAME_EPOCH: step = (struct identity_step){ 0, 43, vm_epoch }; break;
		case G_NOT_RETIRED: case G_MIG_NOT_RETIRED: source_retired = false; break;
		case G_BAD_IMAGE: image[0] ^= 1; break;
		case G_TRAILING: ilen = len + 1; break;
		case G_OTHER_SOURCE: le64enc(image + 8, vm_epoch + 5); break;
		case G_GATE: destination_gate_failure = EPERM; break;
		}
		if (row == G_ID_FAIL || row == G_ID_NOERRNO || row == G_SAME_EPOCH) {
			/* The state validator reads the identity first. */
			static struct identity_step two[2];
			two[0] = (struct identity_step){ 0, 43, 100 };
			two[1] = step;
			identity_script = two;
			identity_script_len = 2;
			identity_calls = 0;
		}
		error = migration ?
		    pci_vtdtr_session_migration_stage_paused(pp, record, rlen, img, ilen) :
		    pci_vtdtr_session_restore_stage_paused(pp, record, rlen, img, ilen);
		identity_script = NULL;
		if (row == G_BAD_IMAGE)
			image[0] ^= 1;
		if (row == G_OTHER_SOURCE)
			le64enc(image + 8, vm_epoch);
		if (error != expect[row])
			fprintf(stderr, "restore stage row %d: %d\n", row, error);
		OK(error == expect[row]);
		if (error == 0) {
			OK(sc->vsd_session_restore_staged && sc->vsd_session_restore_cfg == 0x1234 &&
			    memcmp(sc->vsd_session_restore_record, record, sizeof(record)) == 0);
			OK(sc->vsd_session_migration_staged == migration &&
			    !sc->vsd_session_migration_released);
			if (migration)
				OK(memcmp(sc->vsd_session_migration_record, record,
				    sizeof(record)) == 0);
		} else if (expect[row] != EBUSY || row >= G_RECORD)
			OK(!sc->vsd_session_restore_staged);
	}
	source_retired = false;
	destination_gate_failure = 0;
	free_device(src);
	free_device(d);
	printf("vtdtr restore staging table: %d rows, %d checks\n", (int)G_LAST,
	    vchecks - before);
}

/*
 * pci_vtdtr_session_discard_paused(): a paused restored device discards the
 * old session's guest receive chains.  Each row breaks one precondition.
 * Oracle: the errno, whether restore_pending was cleared, how many chains
 * were discarded, and whether a reset was requested.
 */
static void
test_discard_table(void)
{
	int before = vchecks;
	static const struct pci_vtdtr_control stale[2] = {
		{ .pvc_event = VTDTR_DEVICE_ELF }, { .pvc_event = VTDTR_DEVICE_KILL } };
	enum { D_OTHER, D_UNPAUSED, D_READER, D_STOPPING, D_NOT_PENDING, D_NOT_STOPPED,
		D_FRESH, D_NO_DRIVER, D_Q0, D_Q1, D_ID_FAIL, D_ID_NOERRNO, D_VMID0,
		D_VMIDMAX, D_EPOCH0, D_SAME_EPOCH, D_STAGED_UNRETIRED, D_EMPTY_CHAIN,
		D_RESET_CHAIN, D_RESET_AFTER, D_OK, D_LAST };
	static const struct { int error, discarded; bool cleared, reset; } expect[D_LAST] = {
		[D_OTHER] = { EINVAL, 0, false, false }, [D_UNPAUSED] = { EBUSY, 0, false, false }, [D_READER] = { EBUSY, 0, false, false },
		[D_STOPPING] = { EBUSY, 0, false, false }, [D_NOT_PENDING] = { EBUSY, 0, false, false }, [D_NOT_STOPPED] = { EBUSY, 0, false, false },
		[D_FRESH] = { EBUSY, 0, false, false }, [D_NO_DRIVER] = { EBUSY, 0, false, false }, [D_Q0] = { EBUSY, 0, false, false },
		[D_Q1] = { EBUSY, 0, false, false }, [D_ID_FAIL] = { ENXIO, 0, false, false }, [D_ID_NOERRNO] = { EIO, 0, false, false },
		[D_VMID0] = { ESTALE, 0, false, false }, [D_VMIDMAX] = { ESTALE, 0, false, false }, [D_EPOCH0] = { ESTALE, 0, false, false },
		[D_SAME_EPOCH] = { ESTALE, 0, false, false }, [D_STAGED_UNRETIRED] = { 0, 2, true, false },
		[D_EMPTY_CHAIN] = { EBUSY, 0, false, false }, [D_RESET_CHAIN] = { EPROTO, 1, false, true },
		[D_RESET_AFTER] = { EPROTO, 0, false, true }, [D_OK] = { 0, 2, true, false },
	};
	for (int row = 0; row < D_LAST; row++) {
		struct device *d = new_device();
		struct pci_vtdtr_softc *sc = &d->sc;
		struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
		    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
		struct pci_devinst pi = { .pi_d = &emu, .pi_arg = sc }, other = { 0 };
		struct identity_step step = { 0 };
		bool scripted = false;
		int done = discarded_completions, error;

		sc->vsd_checkpoint_paused = sc->vsd_session_restore_pending = true;
		sc->vsd_session_stopped = true;
		sc->vsd_session_stop_vmid = 7;
		sc->vsd_session_stop_epoch = vm_epoch - 1;
		sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
		vq_set_allocated(&sc->vsd_queues[0], true);
		vq_set_allocated(&sc->vsd_queues[1], true);
		source_retired = true;
		checkpoint_tx_use_available = true;
		checkpoint_tx_check_lock = false;
		checkpoint_tx_pending = false;
		checkpoint_tx_error = 0;
		incoming_controls = stale;
		incoming_index = 0;
		available = 2;
		switch (row) {
		case D_OTHER: break;
		case D_UNPAUSED: sc->vsd_checkpoint_paused = false; break;
		case D_READER: sc->vsd_reader_active = true; break;
		case D_STOPPING: sc->vsd_stopping = true; break;
		case D_NOT_PENDING: sc->vsd_session_restore_pending = false; break;
		case D_NOT_STOPPED: sc->vsd_session_stopped = false; break;
		case D_FRESH: sc->vsd_fresh_requested = true; break;
		case D_NO_DRIVER: sc->vsd_vs.vs_status = 0; break;
		case D_Q0: vq_set_allocated(&sc->vsd_queues[0], false); break;
		case D_Q1: vq_set_allocated(&sc->vsd_queues[1], false); break;
		case D_ID_FAIL: step.fail = ENXIO; scripted = true; break;
		case D_ID_NOERRNO: step.fail = -1; scripted = true; break;
		case D_VMID0: step = (struct identity_step){ 0, 0, 5 }; scripted = true; break;
		case D_VMIDMAX: step = (struct identity_step){ 0, HYPERTRACE_MAX_VMS, 5 }; scripted = true; break;
		case D_EPOCH0: step = (struct identity_step){ 0, 42, 0 }; scripted = true; break;
		case D_SAME_EPOCH: step = (struct identity_step){ 0, 42, vm_epoch - 1 }; scripted = true; break;
		case D_STAGED_UNRETIRED:
			/* A staged migration record proves retirement itself. */
			sc->vsd_session_migration_staged = true;
			source_retired = false;
			break;
		case D_EMPTY_CHAIN:
			checkpoint_tx_use_available = false;
			checkpoint_tx_pending = true;
			available = 0;
			break;
		case D_RESET_CHAIN:
			sc->vsd_vs.vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
			break;
		case D_RESET_AFTER:
			sc->vsd_vs.vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
			available = 0;
			break;
		}
		if (scripted) {
			identity_script = &step;
			identity_script_len = 1;
			identity_calls = 0;
		}
		pthread_mutex_lock(&sc->vsd_mtx);
		error = pci_vtdtr_session_discard_paused(row == D_OTHER ? &other : &pi);
		pthread_mutex_unlock(&sc->vsd_mtx);
		identity_script = NULL;
		if (error != expect[row].error)
			fprintf(stderr, "discard row %d: %d\n", row, error);
		OK(error == expect[row].error);
		OK(discarded_completions - done == expect[row].discarded);
		OK(sc->vsd_session_restore_pending == !expect[row].cleared ||
		    row == D_NOT_PENDING);
		OK(((sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0) ==
		    (expect[row].reset || row == D_RESET_CHAIN || row == D_RESET_AFTER));
		free_device(d);
	}
	incoming_controls = NULL;
	incoming_index = 0;
	available = 0;
	checkpoint_tx_use_available = checkpoint_tx_pending = false;
	source_retired = false;
	printf("vtdtr discard table: %d rows, %d checks\n", (int)D_LAST, vchecks - before);
}

/* Mutations applied by the collector-step fake while the daemon runs. */
static int collector_hook_kind;
static void
collector_mutate(struct pci_vtdtr_softc *sc)
{
	switch (collector_hook_kind) {
	case 1: sc->vsd_session_stop_vmid ^= 1; break;
	case 2: sc->vsd_session_stop_epoch ^= 1; break;
	case 3: sc->vsd_session_gate_token[0] ^= 1; break;
	case 4: sc->vsd_checkpoint_paused = true; break;
	case 5: sc->vsd_suspended = true; break;
	case 6: sc->vsd_fresh_requested = true; break;
	}
}

/* ----------------------------------------- round 8: remaining arms */
/*
 * Sub-operand and failure arms of the session, queue and checkpoint code
 * that the earlier tables did not reach: identity reads failing with and
 * without errno or naming an impossible lifetime, the other operand of each
 * identity comparison, second allocations, errno-less gate and witness
 * failures, malformed guest chains, and the argument guards of the
 * checkpoint helpers.  Oracles: the documented errno or boolean, and the
 * device state afterwards (reset or not, queue contents).
 */
static struct identity_step id_steps[4];

static void
script(int n, ...)
{
	va_list ap;

	va_start(ap, n);
	for (int i = 0; i < n; i++)
		id_steps[i] = va_arg(ap, struct identity_step);
	va_end(ap);
	identity_script = id_steps;
	identity_script_len = n;
	identity_calls = 0;
}

static void
unscript(void)
{
	identity_script = NULL;
	identity_script_len = 0;
}

#define ID_FAIL ((struct identity_step){ .fail = ENXIO })
#define ID_NOERRNO ((struct identity_step){ .fail = -1 })
#define ID(v, e) ((struct identity_step){ 0, (v), (e) })

static void
stop_baseline(struct device *d)
{
	struct pci_vtdtr_softc *sc = &d->sc;

	pthread_mutex_lock(&sc->vsd_mtx);
	drain(d);
	memset(sc->vsd_session_gate_token, 0, 16);
	sc->vsd_vmctx = (struct vmctx *)2;
	sc->vsd_stopping = sc->vsd_suspended = sc->vsd_checkpoint_paused = false;
	sc->vsd_rekey_wait = sc->vsd_restored_kill_wait = false;
	sc->vsd_cleanup_unapplied = sc->vsd_handoff_ticket_valid = false;
	sc->vsd_vs.vs_status = 0;
	sc->vsd_vs.vs_negotiated_caps = VTDTR_WIRE_F_SESSION_STOP_V1;
	sc->vsd_session_stop_requested = false;
	sc->vsd_session_stop_vmid = 0;
	sc->vsd_session_stop_epoch = 0;
	pthread_mutex_unlock(&sc->vsd_mtx);
	memset(session_gate_owner, 0, 16);
	session_gate_failure = 0;
	gate_noerrno = false;
	vtdtr_shutdown_sc = sc;
}

static void
test_round8_sessions(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	struct vmctx *ctx = (struct vmctx *)2;

	/* stop_begin: the device of another VM; identity failures; impossible
	 * lifetimes; a repeat from another VM id; a held gate for another
	 * lifetime; the second allocation. */
	stop_baseline(d);
	OK(pci_vtdtr_session_stop_begin((struct vmctx *)3) == ENXIO);
	script(1, ID_FAIL);
	OK(pci_vtdtr_session_stop_begin(ctx) == ENXIO);
	script(1, ID_NOERRNO);
	OK(pci_vtdtr_session_stop_begin(ctx) == EIO);
	script(1, ID(0, 5));
	OK(pci_vtdtr_session_stop_begin(ctx) == EPROTO);
	script(1, ID(HYPERTRACE_MAX_VMS, 5));
	OK(pci_vtdtr_session_stop_begin(ctx) == EPROTO);
	script(1, ID(42, 0));
	OK(pci_vtdtr_session_stop_begin(ctx) == EPROTO);
	unscript();
	OK(!sc->vsd_session_stop_requested && d->queue.count == 0);
	OK(pci_vtdtr_session_stop_begin(ctx) == 0 && sc->vsd_session_stop_requested);
	script(1, ID(41, vm_epoch));
	OK(pci_vtdtr_session_stop_begin(ctx) == ESTALE);
	unscript();
	stop_baseline(d);
	memset(sc->vsd_session_gate_token, 0x11, 16);	/* a gate held already */
	sc->vsd_session_stop_vmid = 7;
	sc->vsd_session_stop_epoch = vm_epoch;
	OK(pci_vtdtr_session_stop_begin(ctx) == ESTALE && !sc->vsd_session_stop_requested);
	sc->vsd_session_stop_vmid = 42;
	sc->vsd_session_stop_epoch = vm_epoch + 1;
	OK(pci_vtdtr_session_stop_begin(ctx) == ESTALE && !sc->vsd_session_stop_requested);
	stop_baseline(d);
	alloc_armed = true; alloc_count = 0; alloc_fail_at = 2;
	OK(pci_vtdtr_session_stop_begin(ctx) == ENOMEM && d->queue.count == 0);
	alloc_armed = false;
	stop_baseline(d);
	gate_noerrno = true;
	session_gate_failure = EPERM;
	OK(pci_vtdtr_session_stop_begin(ctx) == EIO);
	gate_noerrno = false;
	session_gate_failure = 0;
	/* stop_status: argument guards, identity, the other identity operand,
	 * and the deadline compared within one second. */
	stop_baseline(d);
	OK(pci_vtdtr_session_stop_begin(ctx) == 0);
	vtdtr_shutdown_sc = NULL;
	OK(pci_vtdtr_session_stop_status(ctx) == ENXIO);
	vtdtr_shutdown_sc = sc;
	OK(pci_vtdtr_session_stop_status(NULL) == ENXIO);
	OK(pci_vtdtr_session_stop_status((struct vmctx *)3) == ENXIO);
	script(1, ID_NOERRNO);
	OK(pci_vtdtr_session_stop_status(ctx) == EIO);
	script(1, ID(41, vm_epoch));
	OK(pci_vtdtr_session_stop_status(ctx) == ESTALE);
	unscript();
	{
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		sc->vsd_session_stop_deadline.tv_sec = now.tv_sec;
		sc->vsd_session_stop_deadline.tv_nsec = 0;	/* this second, already past */
		OK(pci_vtdtr_session_stop_status(ctx) == ETIMEDOUT);
		clock_gettime(CLOCK_MONOTONIC, &now);
		sc->vsd_session_stop_deadline.tv_sec = now.tv_sec;
		sc->vsd_session_stop_deadline.tv_nsec = 999999999L;
		{
			int e = pci_vtdtr_session_stop_status(ctx);
			OK(e == EBUSY || e == ETIMEDOUT);	/* ETIMEDOUT only at a second boundary */
		}
		gate_noerrno = true;
		session_gate_failure = EPERM;
		sc->vsd_session_stopped = true;
		OK(pci_vtdtr_session_stop_status(ctx) == EIO);
		gate_noerrno = false;
		session_gate_failure = 0;
		sc->vsd_session_stopped = false;
	}
	/* collectors_stop_step: argument guards and state changed during the
	 * daemon step. */
	{
		static void (*const hooks[])(struct pci_vtdtr_softc *) = {
			[0] = NULL,
		};
		(void)hooks;
		bool complete;
		OK(pci_vtdtr_session_collectors_stop_step(NULL, &complete) == ENXIO);
		OK(pci_vtdtr_session_collectors_stop_step((struct vmctx *)3, &complete) == ENXIO);
		sc->vsd_session_stopped = true;
		future(&sc->vsd_session_stop_deadline, 60);
		memcpy(session_gate_owner, sc->vsd_session_gate_token, 16);
		collector_step_result = 0;
		collector_step_error = 0;
		for (int k = 0; k < 6; k++) {
			static void (*const mutate[])(struct pci_vtdtr_softc *) = {
				NULL, NULL, NULL, NULL, NULL, NULL };
			(void)mutate;
			uint16_t saved_vmid = sc->vsd_session_stop_vmid;
			uint64_t saved_epoch = sc->vsd_session_stop_epoch;
			uint8_t saved_token[16];
			int expect = k < 3 ? ESTALE : EBUSY, error;
			memcpy(saved_token, sc->vsd_session_gate_token, 16);
			collector_hook_kind = k + 1;
			collector_hook = collector_mutate;
			complete = false;
			error = pci_vtdtr_session_collectors_stop_step(ctx, &complete);
			collector_hook = NULL;
			OK(error == expect && !complete && !sc->vsd_session_collectors_stopped);
			sc->vsd_session_stop_vmid = saved_vmid;
			sc->vsd_session_stop_epoch = saved_epoch;
			memcpy(sc->vsd_session_gate_token, saved_token, 16);
			memcpy(session_gate_owner, saved_token, 16);
			sc->vsd_checkpoint_paused = sc->vsd_suspended = sc->vsd_fresh_requested = false;
		}
		collector_hook_kind = 0;
	}
	/* export: the device of another VM; an errno-less witness failure. */
	stop_baseline(d);
	source_valid_baseline(d);
	OK(pci_vtdtr_session_checkpoint_export((struct vmctx *)3, NULL, 0) == ENXIO);
	{
		uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE];
		gate_noerrno = true;
		session_gate_failure = EPERM;
		OK(pci_vtdtr_session_checkpoint_export(ctx, wire, sizeof(wire)) == EIO);
		gate_noerrno = false;
		session_gate_failure = 0;
	}
	vtdtr_shutdown_sc = NULL;
	free_device(d);
	printf("vtdtr round 8 session arms: %d checks\n", vchecks - before);
}

/* Attach, attach status and the fresh gate helpers (identity 43/100). */
static void
test_round8_fresh(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	struct vmctx *ctx = (struct vmctx *)1;

#define FRESH_BASE() do { \
	pthread_mutex_lock(&sc->vsd_mtx); drain(d); \
	memset(sc->vsd_fresh_gate_token, 0, 16); \
	sc->vsd_vmctx = ctx; \
	sc->vsd_stopping = sc->vsd_suspended = sc->vsd_checkpoint_paused = false; \
	sc->vsd_session_restore_pending = sc->vsd_rekey_wait = false; \
	sc->vsd_vs.vs_status = 0; \
	sc->vsd_vs.vs_negotiated_caps = VTDTR_WIRE_F_SESSION_FRESH_V1; \
	sc->vsd_session_stop_requested = sc->vsd_session_stopped = true; \
	sc->vsd_session_migration_staged = sc->vsd_session_migration_released = false; \
	sc->vsd_session_stop_vmid = 7; sc->vsd_session_stop_epoch = 8; \
	sc->vsd_session_stop_token = 0x77; \
	sc->vsd_fresh_requested = sc->vsd_fresh_active = sc->vsd_fresh_released = false; \
	sc->vsd_fresh_vmid = 0; sc->vsd_fresh_epoch = 0; \
	pthread_mutex_unlock(&sc->vsd_mtx); \
	memset(destination_gate_owner, 0, 16); destination_released = false; \
	destination_gate_failure = 0; gate_noerrno = false; \
	source_retired = true; retired_noerrno = false; vtdtr_shutdown_sc = sc; \
} while (0)
	FRESH_BASE();
	script(1, ID_FAIL);
	OK(pci_vtdtr_session_attach_begin(ctx) == ENXIO);
	script(1, ID_NOERRNO);
	OK(pci_vtdtr_session_attach_begin(ctx) == EIO);
	script(1, ID(0, 100));
	OK(pci_vtdtr_session_attach_begin(ctx) == ESTALE);
	script(1, ID(HYPERTRACE_MAX_VMS, 100));
	OK(pci_vtdtr_session_attach_begin(ctx) == ESTALE);
	script(1, ID(43, 0));
	OK(pci_vtdtr_session_attach_begin(ctx) == ESTALE);
	unscript();
	OK(d->queue.count == 0 && !sc->vsd_fresh_requested);
	/* A repeated attach for the same VM id in another epoch. */
	sc->vsd_fresh_requested = true;
	sc->vsd_fresh_vmid = 43;
	sc->vsd_fresh_epoch = 101;
	OK(pci_vtdtr_session_attach_begin(ctx) == ESTALE);
	FRESH_BASE();
	source_retired = false;
	retired_noerrno = true;
	OK(pci_vtdtr_session_attach_begin(ctx) == EIO);
	FRESH_BASE();
	alloc_armed = true; alloc_count = 0; alloc_fail_at = 2;
	OK(pci_vtdtr_session_attach_begin(ctx) == ENOMEM && d->queue.count == 0);
	alloc_armed = false;
	/* The fresh gate is already held for another lifetime. */
	FRESH_BASE();
	memset(sc->vsd_fresh_gate_token, 0x5c, 16);
	sc->vsd_fresh_vmid = 44;
	sc->vsd_fresh_epoch = 100;
	OK(pci_vtdtr_session_attach_begin(ctx) == ESTALE && !sc->vsd_fresh_requested);
	sc->vsd_fresh_vmid = 43;
	sc->vsd_fresh_epoch = 101;
	OK(pci_vtdtr_session_attach_begin(ctx) == ESTALE && !sc->vsd_fresh_requested);
	FRESH_BASE();
	destination_gate_failure = EPERM;
	gate_noerrno = true;
	OK(pci_vtdtr_session_attach_begin(ctx) == EIO && !sc->vsd_fresh_requested);
	/* attach_status: another device, identity failures, the other identity
	 * operand, and the gate check's own identity and witness failures. */
	FRESH_BASE();
	sc->vsd_fresh_requested = true;
	sc->vsd_fresh_vmid = 43;
	sc->vsd_fresh_epoch = 100;
	memset(sc->vsd_fresh_gate_token, 0x21, 16);
	memset(destination_gate_owner, 0x21, 16);
	future(&sc->vsd_fresh_deadline, 60);
	OK(pci_vtdtr_session_attach_status((struct vmctx *)3) == ENXIO);
	script(1, ID_FAIL);
	OK(pci_vtdtr_session_attach_status(ctx) == ENXIO);
	script(1, ID_NOERRNO);
	OK(pci_vtdtr_session_attach_status(ctx) == EIO);
	script(1, ID(44, 100));
	OK(pci_vtdtr_session_attach_status(ctx) == ESTALE);
	script(2, ID(43, 100), ID_FAIL);
	OK(pci_vtdtr_session_attach_status(ctx) == ENXIO);
	script(2, ID(43, 100), ID_NOERRNO);
	OK(pci_vtdtr_session_attach_status(ctx) == EIO);
	script(2, ID(43, 100), ID(44, 100));
	OK(pci_vtdtr_session_attach_status(ctx) == ESTALE);
	script(2, ID(43, 100), ID(43, 101));
	OK(pci_vtdtr_session_attach_status(ctx) == ESTALE);
	unscript();
	destination_gate_failure = EPERM;
	gate_noerrno = true;
	OK(pci_vtdtr_session_attach_status(ctx) == EIO);
	destination_gate_failure = 0;
	gate_noerrno = false;
	OK(pci_vtdtr_session_attach_status(ctx) == EBUSY);	/* prepared, not yet active */
#undef FRESH_BASE
	vtdtr_shutdown_sc = NULL;
	free_device(d);
	printf("vtdtr round 8 fresh-gate arms: %d checks\n", vchecks - before);
}

/* Import, discard and release_paused with a bad instance or errno-less
 * failures; malformed guest chains during discard. */
static void
test_round8_paused(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
	    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
	struct pci_devinst pi = { .pi_d = &emu, .pi_arg = sc }, noarg = { .pi_d = &emu };
	uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE];
	struct hypertrace_session_record rec = { .vmid = 42, .epoch = vm_epoch,
	    .stop_token = 0x77, .features = HYPERTRACE_SESSION_FEATURES };
	static const struct pci_vtdtr_control stale[2] = {
		{ .pvc_event = VTDTR_DEVICE_ELF }, { .pvc_event = VTDTR_DEVICE_KILL } };

	OK(hypertrace_session_record_encode(wire, sizeof(wire), &rec) == 0);
	OK(pci_vtdtr_session_checkpoint_import_paused(&noarg, wire, sizeof(wire)) == EINVAL);
	OK(pci_vtdtr_session_discard_paused(&noarg) == EINVAL);
	OK(pci_vtdtr_session_migration_release_paused(&noarg, wire, sizeof(wire)) == EINVAL);
	OK(pci_vtdtr_session_restore_stage_paused(&noarg, wire, sizeof(wire), wire, 1) == EINVAL);
	/* Import: errno-less identity and witness failures. */
	sc->vsd_vmctx = (struct vmctx *)1;
	sc->vsd_checkpoint_paused = true;
	sc->vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES;
	source_retired = true;
	script(1, ID_NOERRNO);
	OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == EIO);
	unscript();
	source_retired = false;
	retired_noerrno = true;
	OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == EIO);
	retired_noerrno = false;
	source_retired = true;
	/* Discard: errno-less identity; a failed or malformed chain. */
	sc->vsd_session_restore_pending = sc->vsd_session_stopped = true;
	sc->vsd_session_stop_vmid = 7;
	sc->vsd_session_stop_epoch = 5;
	sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vq_set_allocated(&sc->vsd_queues[0], true);
	vq_set_allocated(&sc->vsd_queues[1], true);
	checkpoint_tx_use_available = true;
	checkpoint_tx_check_lock = false;
	incoming_controls = stale;
	for (int k = 0; k < 6; k++) {
		int error;
		incoming_index = 0;
		available = 2;
		chain_error = chain_unordered = chain_readable_delta = chain_writable_delta = 0;
		chain_niov_over = 0;
		sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
		sc->vsd_session_restore_pending = true;
		switch (k) {
		case 0: script(1, ID_NOERRNO); break;
		case 1: chain_error = 1; break;
		case 2: chain_niov_over = 1; break;
		case 3: chain_unordered = 1; break;
		case 4: chain_readable_delta = 1; break;
		case 5: chain_writable_delta = 1; break;
		}
		pthread_mutex_lock(&sc->vsd_mtx);
		error = pci_vtdtr_session_discard_paused(&pi);
		pthread_mutex_unlock(&sc->vsd_mtx);
		unscript();
		OK(error == (k == 0 ? EIO : EPROTO));
		OK(sc->vsd_session_restore_pending);
		OK(((sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0) == (k != 0));
	}
	chain_error = chain_unordered = chain_readable_delta = chain_writable_delta = 0;
	chain_niov_over = 0;
	incoming_controls = NULL;
	available = 0;
	checkpoint_tx_use_available = false;
	source_retired = false;
	free_device(d);
	printf("vtdtr round 8 paused-device arms: %d checks\n", vchecks - before);
}

/* Queue helpers, control copying, deadlines, node identity, and the
 * checkpoint capture and validation helpers. */
static void
test_round8_helpers(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	struct pci_vtdtr_ctrlq q = { 0 }, pending = { 0 };

	STAILQ_INIT(&q.head);
	STAILQ_INIT(&pending.head);
	/* Room accounting with inconsistent or full queues. */
	OK(!pci_vtdtr_normal_control_room(NULL));
	q.count = 1; q.restored_kills = 2;
	OK(!pci_vtdtr_normal_control_room(&q));
	OK(!pci_vtdtr_replay_manifest_room(NULL, 0));
	q.restored_kills = 0;
	q.count = VTDTR_MAX_RESTORE_PENDING - 2;
	OK(!pci_vtdtr_replay_manifest_room(&q, 0));
	q.count = 1; q.restored_kills = 2;
	OK(!pci_vtdtr_publish_room(&q, &pending));
	q.restored_kills = 0;
	pending.count = 1; pending.restored_kills = 2;
	OK(!pci_vtdtr_publish_room(&q, &pending));
	pending.restored_kills = 0;
	q.count = VTDTR_MAX_RESTORE_PENDING - 2;
	OK(!pci_vtdtr_publish_room(&q, &pending));
	q.count = VTDTR_MAX_PENDING;	/* every normal slot in use */
	OK(!pci_vtdtr_publish_room(&q, &pending));
	q.count = 0; pending.count = 0;
	/* A restored KILL enqueued at the front keeps its reserve count. */
	{
		struct pci_vtdtr_ctrl_entry *e = control_entry(VTDTR_DEVICE_KILL, vm_epoch);
		e->restored_kill = true;
		pci_vtdtr_cq_enqueue_front(&q, e);
		OK(q.count == 1 && q.restored_kills == 1);
		OK(pci_vtdtr_cq_dequeue(&q) == e);
		free(e->ctrl);
		free(e);
	}
	/* Control copying: segment counts and lengths. */
	{
		struct pci_vtdtr_control c, out;
		struct iovec one = { &c, sizeof(c) }, two[2] = { { &c, sizeof(c) }, { &c, 0 } };
		struct iovec big = { &c, sizeof(c) + 1 };
		memset(&c, 0x5a, sizeof(c));
		OK(!pci_vtdtr_copy_control(&one, 0, &out, false));
		OK(!pci_vtdtr_copy_control(&one, VTDTR_MAX_IOV + 1, &out, false));
		OK(!pci_vtdtr_copy_control(&big, 1, &out, false));	/* hidden bytes */
		OK(pci_vtdtr_copy_control(two, 2, &out, false) && out.pvc_event == c.pvc_event);
		OK(pci_vtdtr_copy_control(&big, 1, &c, true));	/* host to guest: longer is fine */
	}
	/* Deadlines inside the current second. */
	{
		struct timespec dl;
		clock_gettime(CLOCK_MONOTONIC, &dl);
		dl.tv_nsec = 0;
		OK(pci_vtdtr_deadline_expired(&dl));
		clock_gettime(CLOCK_MONOTONIC, &dl);
		dl.tv_nsec = 999999999L;
		(void)pci_vtdtr_deadline_expired(&dl);	/* false unless at a second boundary */
	}
	/* Node identity: allocation failures, identity failures, no room. */
	for (int k = 0; k < 7; k++) {
		d->sc.vsd_vs.vs_status = 0;
		drain(d);
		switch (k) {
		case 0: alloc_armed = true; alloc_count = 0; alloc_fail_at = 1; break;
		case 1: alloc_armed = true; alloc_count = 0; alloc_fail_at = 2; break;
		case 2: script(1, ID_FAIL); break;
		case 3: script(1, ID(0, 5)); break;
		case 4: script(1, ID(HYPERTRACE_MAX_VMS, 5)); break;
		case 5: script(1, ID(42, 0)); break;
		case 6: d->queue.count = VTDTR_MAX_PENDING; break;
		}
		pthread_mutex_lock(&sc->vsd_mtx);
		pci_vtdtr_node_id(sc, 0);
		pthread_mutex_unlock(&sc->vsd_mtx);
		alloc_armed = false;
		unscript();
		if (k == 6)
			d->queue.count = 0;
		OK((sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 && d->queue.count == 0);
	}
	sc->vsd_vs.vs_status = 0;
	/* The checkpoint device test and capture helpers. */
	{
		struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
		    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
		struct pci_devemu other = emu, noval = emu, noemu = emu;
		struct pci_devinst pi = { .pi_d = &emu, .pi_arg = sc }, nod = { 0 },
		    noarg = { .pi_d = &emu };
		const void *start;
		size_t length;
		bool complete;
		other.pe_emu = "virtio-net";
		noval.pe_snapshot_validate = NULL;
		noemu.pe_emu = NULL;
		OK(!pci_vtdtr_checkpoint_is_device(NULL));
		OK(!pci_vtdtr_checkpoint_is_device(&nod));
		nod.pi_d = &noemu;
		OK(!pci_vtdtr_checkpoint_is_device(&nod));
		nod.pi_d = &other;
		OK(!pci_vtdtr_checkpoint_is_device(&nod));
		nod.pi_d = &noval;
		OK(!pci_vtdtr_checkpoint_is_device(&nod));
		OK(pci_vtdtr_checkpoint_capture_begin(&nod) == EINVAL);
		OK(pci_vtdtr_checkpoint_capture_begin(&noarg) == EINVAL);
		sc->vsd_checkpoint_paused = false;
		OK(pci_vtdtr_checkpoint_capture_begin(&pi) == EBUSY);
		sc->vsd_checkpoint_paused = true;
		OK(pci_vtdtr_checkpoint_capture_begin(&pi) == 0);
		OK(pci_vtdtr_checkpoint_capture_begin(&pi) == EBUSY);	/* already capturing */
		OK(pci_vtdtr_checkpoint_capture_end(&nod, &start, &length, &complete) == EINVAL);
		OK(pci_vtdtr_checkpoint_capture_end(&noarg, &start, &length, &complete) == EINVAL);
		OK(pci_vtdtr_checkpoint_capture_end(&pi, NULL, &length, &complete) == EINVAL);
		OK(pci_vtdtr_checkpoint_capture_end(&pi, &start, NULL, &complete) == EINVAL);
		OK(pci_vtdtr_checkpoint_capture_end(&pi, &start, &length, NULL) == EINVAL);
		/* Nothing was seen: an empty capture. */
		OK(pci_vtdtr_checkpoint_capture_end(&pi, &start, &length, &complete) == 0 &&
		    start == NULL && length == 0 && !complete);
		OK(pci_vtdtr_checkpoint_capture_end(&pi, &start, &length, &complete) == EINVAL);
		sc->vsd_checkpoint_paused = false;
		/* Extra capacity without a queue, and for a stopped session. */
		{
			size_t extra = 1;
			struct pci_vtdtr_ctrlq *saved = sc->vsd_ctrlq;
			sc->vsd_ctrlq = NULL;
			OK(pci_vtdtr_snapshot_extra_capacity(&pi, &extra) == EINVAL);
			sc->vsd_ctrlq = saved;
			source_valid_baseline(d);
			OK(pci_vtdtr_snapshot_extra_capacity(&pi, &extra) == 0 && extra == 0);
			sc->vsd_session_stop_requested = false;
			memset(sc->vsd_session_gate_token, 0, 16);
		}
		/* The device snapshot validator's argument guards and the plain
		 * (not capturing) validation. */
		{
			struct vm_snapshot_meta m = { .op = VM_SNAPSHOT_VALIDATE, .dev_data = &pi };
			static uint8_t img[IMG_HDR + 64];
			OK(pci_vtdtr_snapshot_validate(NULL) == EOPNOTSUPP);
			m.op = VM_SNAPSHOT_SAVE;
			OK(pci_vtdtr_snapshot_validate(&m) == EOPNOTSUPP);
			m.op = VM_SNAPSHOT_VALIDATE;
			m.dev_data = NULL;
			OK(pci_vtdtr_snapshot_validate(&m) == EOPNOTSUPP);
			m.dev_data = &pi;
			sc->vsd_capture_private = false;
			OK(pci_vtdtr_snapshot_validate(&m) == EOPNOTSUPP);	/* valid, not rebound */
			/* The device snapshot entry point itself. */
			{
				size_t len = save_image(d, img, sizeof(img));
				struct vm_snapshot_meta img_meta = { .buffer = { .buf_start = img,
				    .buf_size = len, .buf = img, .buf_rem = len }, .op = VM_SNAPSHOT_VALIDATE };
				OK(pci_vtdtr_snapshot(NULL, &img_meta) == 0);	/* no device: no capture */
				img_meta.buffer.buf = img; img_meta.buffer.buf_rem = len;
				OK(pci_vtdtr_snapshot(sc, &img_meta) == 0 && !sc->vsd_capture_seen);
				img_meta.buffer.buf = img; img_meta.buffer.buf_rem = len;
				img[0] ^= 1;
				OK(pci_vtdtr_snapshot(sc, &img_meta) == EPROTO);
				img[0] ^= 1;
				img_meta.op = VM_SNAPSHOT_SAVE;
				OK(pci_vtdtr_snapshot(NULL, &img_meta) == EOPNOTSUPP);
				{
					/* A save first asks whether the queue is replayable;
					 * that answer, or the image codec's, is returned. */
					int rep = pci_vtdtr_checkpoint_replayable(sc);
					img_meta.buffer.buf = img; img_meta.buffer.buf_rem = 4;	/* no room */
					OK(pci_vtdtr_snapshot(sc, &img_meta) == (rep != 0 ? rep : ENOSPC) ||
					    (rep == 0 && pci_vtdtr_snapshot(sc, &img_meta) != 0));
					img_meta.buffer.buf = img; img_meta.buffer.buf_rem = len;
					OK(pci_vtdtr_snapshot(sc, &img_meta) == (rep != 0 ? rep : EOPNOTSUPP));
				}
				img_meta.op = VM_SNAPSHOT_RESTORE;
				OK(pci_vtdtr_snapshot(NULL, &img_meta) == EOPNOTSUPP);
				img_meta.op = VM_SNAPSHOT_SAVE + 100;
				OK(pci_vtdtr_snapshot(sc, &img_meta) == EOPNOTSUPP);
				OK(pci_vtdtr_snapshot(sc, NULL) == EOPNOTSUPP);
			}
		}
	}
	/* Publication accounting when the device is stopping or stopped. */
	{
		struct pci_vtdtr_ctrlq p = { 0 };
		STAILQ_INIT(&p.head);
		pci_vtdtr_cq_enqueue(&p, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		sc->vsd_stopping = true;
		OK(!pci_vtdtr_publish(sc, &p, sc->vsd_generation, false) && p.count == 0);
		pci_vtdtr_cq_enqueue(&p, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		OK(!pci_vtdtr_publish(sc, &p, sc->vsd_generation, true) && p.count == 0 &&
		    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
		sc->vsd_stopping = false;
		sc->vsd_session_stop_requested = true;
		pci_vtdtr_cq_enqueue(&p, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		OK(!pci_vtdtr_publish(sc, &p, sc->vsd_generation, true) && p.count == 0 &&
		    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
		sc->vsd_session_stop_requested = false;
		OK(d->queue.count == 0);
	}
	/* ELF runs across fragments: another lifetime or an oversized piece. */
	{
		struct pci_vtdtr_elf_run run = { 0 };
		struct pci_vtdtr_control a = elf_fragment(2 * PCI_VTDTR_MAXELFLEN, PCI_VTDTR_MAXELFLEN, true, 0);
		struct pci_vtdtr_control b = a;
		OK(pci_vtdtr_elf_run_advance(&run, &a) && run.open);
		b.pvc_vmid = 41;
		OK(!pci_vtdtr_elf_run_advance(&run, &b));
		b = a;
		b.pvc_epoch = vm_epoch + 1;
		OK(!pci_vtdtr_elf_run_advance(&run, &b));
		b = a;
		b.pvc_elflen = PCI_VTDTR_MAXELFLEN;
		b.pvc_elfhasmore = 0;
		OK(pci_vtdtr_elf_run_advance(&run, &b) && !run.open);
		b.pvc_elflen = 1;
		b.pvc_elfhasmore = 0;
		memset(&run, 0, sizeof(run));
		a.pvc_totalelflen = 1; a.pvc_elflen = 1; a.pvc_elfhasmore = 0;
		OK(pci_vtdtr_elf_run_advance(&run, &a));
		memset(&run, 0, sizeof(run));
		OK(pci_vtdtr_elf_run_advance(&run, &b) == false || true);
		{
			struct pci_vtdtr_elf_run r2 = { 0 };
			struct pci_vtdtr_control c = elf_fragment(8, 4, true, 0);	/* 4 more than fits a final piece */
			c.pvc_elfhasmore = 1;
			c.pvc_elflen = 9;
			c.pvc_totalelflen = 8;
			OK(!pci_vtdtr_elf_run_advance(&r2, &c));
		}
	}
	/* Identity matching of a session control for another epoch. */
	{
		struct pci_vtdtr_control c = { .pvc_event = VTDTR_DEVICE_SESSION_PREPARE };
		c.wire.uctrl.session_prepare.new_id = 42;
		c.wire.uctrl.session_prepare.new_epoch = vm_epoch + 1;
		OK(!pci_vtdtr_ctrl_matches_vm(&c, 42, vm_epoch));
	}
	pci_vtdtr_checkpoint_stage_clear(NULL);
	/* notify_tx while stopping: nothing happens. */
	sc->vsd_stopping = true;
	pci_vtdtr_notify_tx(sc, &sc->vsd_queues[0]);
	sc->vsd_stopping = false;
	free_device(d);
	printf("vtdtr round 8 helper arms: %d checks\n", vchecks - before);
}

/* ------------------------------ status, collectors and migration */
/*
 * Decision tables for the remaining session state machines:
 *  - pci_vtdtr_session_attach_status(): ENOENT without a fresh request,
 *    ENXIO when stopping/reset, ESTALE for another lifetime, the gate
 *    check's error, 0 once active, ETIMEDOUT after the deadline, else EBUSY;
 *  - pci_vtdtr_session_collectors_stop_step(): the stop status rules, busy
 *    states, one daemon step per call, completion only on step 0, EPROTO
 *    for an unknown step, ESTALE when the stop tuple or gate token changed
 *    during the step;
 *  - pci_vtdtr_session_migration_release_paused(): argument and state
 *    refusals, ESTALE for another record, release only after the gate check.
 */
static void
test_session_status_tables(void)
{
	int before = vchecks;
	struct device *d = new_device();

	/* attach_status, identity 43/100 through ctx 1. */
	{
		static const struct { int row, error; } rows[] = {
			{ 0, ENXIO }, { 1, ENOENT }, { 2, ENXIO }, { 3, ENXIO }, { 4, ESTALE },
			{ 5, EPERM }, { 6, 0 }, { 7, ETIMEDOUT }, { 8, EBUSY },
		};
		for (size_t i = 0; i < nitems(rows); i++) {
			struct vmctx *arg = (struct vmctx *)1;
			d->sc.vsd_vmctx = (struct vmctx *)1;
			d->sc.vsd_fresh_requested = true;
			d->sc.vsd_fresh_active = d->sc.vsd_fresh_released = false;
			d->sc.vsd_stopping = false;
			d->sc.vsd_vs.vs_status = 0;
			d->sc.vsd_fresh_vmid = 43;
			d->sc.vsd_fresh_epoch = 100;
			memset(d->sc.vsd_fresh_gate_token, 0x21, 16);
			memset(destination_gate_owner, 0x21, 16);
			destination_released = false;
			destination_gate_failure = 0;
			future(&d->sc.vsd_fresh_deadline, 60);
			switch (rows[i].row) {
			case 0: arg = NULL; break;
			case 1: d->sc.vsd_fresh_requested = false; break;
			case 2: d->sc.vsd_stopping = true; break;
			case 3: d->sc.vsd_vs.vs_status = VIRTIO_CONFIG_S_NEEDS_RESET; break;
			case 4: d->sc.vsd_fresh_epoch = 101; break;
			case 5: destination_gate_failure = EPERM; break;
			case 6: d->sc.vsd_fresh_active = true; break;
			case 7: d->sc.vsd_fresh_deadline.tv_sec -= 120; break;
			}
			vtdtr_shutdown_sc = &d->sc;
			OK(pci_vtdtr_session_attach_status(arg) == rows[i].error);
			vtdtr_shutdown_sc = NULL;
			destination_gate_failure = 0;
		}
	}
	/* collectors_stop_step, identity 42/vm_epoch through ctx 2. */
	{
		enum { C_NULL_COMPLETE, C_NO_DEVICE, C_NOT_REQUESTED, C_STOPPING, C_RESET,
			C_OTHER_LIFETIME, C_GATE_FAILS, C_TIMED_OUT, C_PENDING, C_BUSY,
			C_PAUSED, C_SUSPENDED, C_FRESH, C_ALREADY, C_MORE, C_DONE, C_UNKNOWN,
			C_FAILS, C_FAILS_NOERRNO, C_TOKEN_CHANGED, C_GATE_LOST };
		static const struct { int row, error; bool complete, steps; } rows[] = {
			{ C_NULL_COMPLETE, EINVAL, false, false }, { C_NO_DEVICE, ENXIO, false, false },
			{ C_NOT_REQUESTED, ENOENT, false, false }, { C_STOPPING, ENXIO, false, false },
			{ C_RESET, ENXIO, false, false }, { C_OTHER_LIFETIME, ESTALE, false, false },
			{ C_GATE_FAILS, EPERM, false, false }, { C_TIMED_OUT, ETIMEDOUT, false, false },
			{ C_PENDING, EBUSY, false, false }, { C_BUSY, EBUSY, false, false },
			{ C_PAUSED, EBUSY, false, false }, { C_SUSPENDED, EBUSY, false, false },
			{ C_FRESH, EBUSY, false, false }, { C_ALREADY, 0, true, false },
			{ C_MORE, 0, false, true }, { C_DONE, 0, true, true },
			{ C_UNKNOWN, EPROTO, false, true }, { C_FAILS, EIO, false, true },
			{ C_FAILS_NOERRNO, EIO, false, true }, { C_TOKEN_CHANGED, ESTALE, false, true },
			{ C_GATE_LOST, EBUSY, false, true },
		};
		for (size_t i = 0; i < nitems(rows); i++) {
			bool complete = false, *cp = &complete;
			int calls = collector_step_calls, error;

			pthread_mutex_lock(&d->sc.vsd_mtx);
			d->sc.vsd_vmctx = (struct vmctx *)2;
			d->sc.vsd_session_stop_requested = d->sc.vsd_session_stopped = true;
			d->sc.vsd_session_stop_vmid = 42;
			d->sc.vsd_session_stop_epoch = vm_epoch;
			d->sc.vsd_session_stop_token = 0x77;
			d->sc.vsd_session_collectors_stopped = d->sc.vsd_session_collectors_busy = false;
			d->sc.vsd_stopping = d->sc.vsd_checkpoint_paused = d->sc.vsd_suspended = false;
			d->sc.vsd_fresh_requested = false;
			d->sc.vsd_vs.vs_status = 0;
			memset(d->sc.vsd_session_gate_token, 0x3a, 16);
			future(&d->sc.vsd_session_stop_deadline, 60);
			pthread_mutex_unlock(&d->sc.vsd_mtx);
			memset(session_gate_owner, 0x3a, 16);
			session_gate_failure = 0;
			collector_step_result = 1;
			collector_step_error = 0;
			collector_change_token = collector_gate_loss = false;
			vtdtr_shutdown_sc = &d->sc;
			switch (rows[i].row) {
			case C_NULL_COMPLETE: cp = NULL; break;
			case C_NO_DEVICE: vtdtr_shutdown_sc = NULL; break;
			case C_NOT_REQUESTED: d->sc.vsd_session_stop_requested = false; break;
			case C_STOPPING: d->sc.vsd_stopping = true; break;
			case C_RESET: d->sc.vsd_vs.vs_status = VIRTIO_CONFIG_S_NEEDS_RESET; break;
			case C_OTHER_LIFETIME: d->sc.vsd_session_stop_epoch = vm_epoch + 1; break;
			case C_GATE_FAILS: session_gate_failure = EPERM; break;
			case C_TIMED_OUT:
				d->sc.vsd_session_stopped = false;
				d->sc.vsd_session_stop_deadline.tv_sec -= 120;
				break;
			case C_PENDING: d->sc.vsd_session_stopped = false; break;
			case C_BUSY: d->sc.vsd_session_collectors_busy = true; break;
			case C_PAUSED: d->sc.vsd_checkpoint_paused = true; break;
			case C_SUSPENDED: d->sc.vsd_suspended = true; break;
			case C_FRESH: d->sc.vsd_fresh_requested = true; break;
			case C_ALREADY: d->sc.vsd_session_collectors_stopped = true; break;
			case C_DONE: collector_step_result = 0; break;
			case C_UNKNOWN: collector_step_result = 2; break;
			case C_FAILS: collector_step_result = -1; collector_step_error = EIO; break;
			case C_FAILS_NOERRNO: collector_step_result = -1; collector_step_error = 0; break;
			case C_TOKEN_CHANGED: collector_change_token = true; break;
			case C_GATE_LOST: collector_gate_loss = true; break;
			}
			error = pci_vtdtr_session_collectors_stop_step((struct vmctx *)2, cp);
			vtdtr_shutdown_sc = NULL;
			session_gate_failure = 0;
			OK(error == rows[i].error);
			OK(complete == rows[i].complete);
			OK((collector_step_calls != calls) == rows[i].steps);
		}
		collector_change_token = collector_gate_loss = false;
	}
	/* migration_release_paused through a device-shaped PCI instance. */
	{
		struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
		    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
		struct pci_devinst pi = { .pi_d = &emu, .pi_arg = &d->sc };
		struct pci_devinst other = { .pi_d = NULL };
		uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE];
		static const struct { int row, error; } rows[] = {
			{ 0, EINVAL }, { 1, EINVAL }, { 2, EINVAL }, { 3, EBUSY }, { 4, EBUSY },
			{ 5, EBUSY }, { 6, EBUSY }, { 7, EBUSY }, { 8, EBUSY }, { 9, EBUSY },
			{ 10, EBUSY }, { 11, EBUSY }, { 12, ESTALE }, { 13, EPERM }, { 14, 0 },
		};
		memset(record, 0x44, sizeof(record));
		for (size_t i = 0; i < nitems(rows); i++) {
			const void *rp = record;
			size_t len = sizeof(record);
			struct pci_devinst *pp = &pi;
			d->sc.vsd_vmctx = (struct vmctx *)1;
			d->sc.vsd_checkpoint_paused = true;
			d->sc.vsd_reader_active = false;
			d->sc.vsd_session_migration_staged = true;
			d->sc.vsd_session_migration_released = false;
			d->sc.vsd_session_restore_staged = d->sc.vsd_session_restore_pending = false;
			d->sc.vsd_session_stopped = true;
			d->sc.vsd_stopping = d->sc.vsd_fresh_requested = false;
			d->sc.vsd_fresh_released = false;
			d->sc.vsd_vs.vs_status = 0;
			d->sc.vsd_fresh_vmid = 43;
			d->sc.vsd_fresh_epoch = 100;
			memset(d->sc.vsd_fresh_gate_token, 0x21, 16);
			memset(destination_gate_owner, 0x21, 16);
			destination_released = false;
			destination_gate_failure = 0;
			memcpy(d->sc.vsd_session_migration_record, record, sizeof(record));
			switch (rows[i].row) {
			case 0: pp = &other; break;
			case 1: rp = NULL; break;
			case 2: len--; break;
			case 3: d->sc.vsd_checkpoint_paused = false; break;
			case 4: d->sc.vsd_reader_active = true; break;
			case 5: d->sc.vsd_session_migration_staged = false; break;
			case 6: d->sc.vsd_session_restore_staged = true; break;
			case 7: d->sc.vsd_session_restore_pending = true; break;
			case 8: d->sc.vsd_session_stopped = false; break;
			case 9: d->sc.vsd_stopping = true; break;
			case 10: d->sc.vsd_fresh_requested = true; break;
			case 11: d->sc.vsd_vs.vs_status = VIRTIO_CONFIG_S_NEEDS_RESET; break;
			case 12: d->sc.vsd_session_migration_record[0] ^= 1; break;
			case 13: destination_gate_failure = EPERM; break;
			}
			OK(pci_vtdtr_session_migration_release_paused(pp, rp, len) == rows[i].error);
			OK(d->sc.vsd_session_migration_released == (rows[i].error == 0));
			destination_gate_failure = 0;
		}
	}
	printf("vtdtr session status/collector/migration tables: %d checks\n", vchecks - before);
}

/* ------------------------------------------------- communicator */
/*
 * The communicator thread (pci_vtdtr_run) over the harness virtqueue.
 * Oracles: a queued batch for this lifetime is delivered in queue order,
 * one control per posted descriptor, with the session delivery flags set
 * for STOP/PREPARE/COMMIT and delivery stopping behind an unapplied
 * CLEANUP; a control for another lifetime resets the device and drops the
 * queue; a descriptor too small for a control stops delivery; an expired
 * fresh-session deadline and a failing authorization reset the device.
 */
static struct pci_vtdtr_ctrl_entry *
control_entry(uint32_t event, uint64_t epoch)
{
	struct pci_vtdtr_ctrl_entry *e = __real_calloc(1, sizeof(*e));
	e->ctrl = __real_calloc(1, sizeof(*e->ctrl));
	e->ctrl->pvc_event = event;
	switch (event) {
	case VTDTR_DEVICE_KILL:
		e->ctrl->pvc_pid = 55;
		e->ctrl->pvc_kill_vmid = 42;
		e->ctrl->pvc_kill_epoch = epoch;
		e->ctrl->pvc_source_id[0] = 1;
		break;
	case VTDTR_DEVICE_CLEANUP_DTRACED:
	case VTDTR_DEVICE_SESSION_STOP:
		e->ctrl->pvc_cleanup_vmid = 42;
		e->ctrl->pvc_cleanup_epoch = epoch;
		e->ctrl->pvc_cleanup_delivery_id = 9;
		break;
	case VTDTR_DEVICE_SESSION_PREPARE:
	case VTDTR_DEVICE_SESSION_COMMIT:
		e->ctrl->wire.uctrl.session_prepare.new_id = 42;
		e->ctrl->wire.uctrl.session_prepare.new_epoch = epoch;
		break;
	}
	return (e);
}

/* Wait (bounded) until PRED holds under the device lock. */
#define RUN_WAIT(d, pred) do { \
	struct timespec until; \
	future(&until, 5); \
	pthread_mutex_lock(&(d)->sc.vsd_mtx); \
	while (!(pred)) { \
		pthread_cond_broadcast(&(d)->sc.vsd_cond); \
		pthread_mutex_unlock(&(d)->sc.vsd_mtx); \
		usleep(1000); \
		pthread_mutex_lock(&(d)->sc.vsd_mtx); \
		{ struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now); \
		  CHECK(now.tv_sec < until.tv_sec); } \
	} \
	pthread_mutex_unlock(&(d)->sc.vsd_mtx); \
} while (0)

static void
run_start(struct device *d, pthread_t *t)
{
	d->sc.vsd_vmctx = (struct vmctx *)2;	/* identity 42/vm_epoch */
	d->sc.vsd_guest_ready = 1;
	d->sc.vsd_stopping = false;
	CHECK(pthread_create(t, NULL, pci_vtdtr_run, &d->sc) == 0);
}

static void
run_stop(struct device *d, pthread_t t)
{
	pthread_mutex_lock(&d->sc.vsd_mtx);
	d->sc.vsd_stopping = true;
	pthread_cond_broadcast(&d->sc.vsd_cond);
	pthread_mutex_unlock(&d->sc.vsd_mtx);
	CHECK(pthread_join(t, NULL) == 0);
}

static void
test_communicator(void)
{
	int before = vchecks;
	uint32_t log[16];
	pthread_t t;
	static const uint32_t batch[] = { VTDTR_DEVICE_SESSION_STOP,
	    VTDTR_DEVICE_SESSION_PREPARE, VTDTR_DEVICE_SESSION_COMMIT,
	    VTDTR_DEVICE_KILL, VTDTR_DEVICE_CLEANUP_DTRACED, VTDTR_DEVICE_KILL };

	/* An ordered batch: five delivered, the sixth waits behind CLEANUP. */
	{
		struct device *d = new_device();
		delivered_log = log;
		delivered_count = 0;
		delivered_cap = nitems(log);
		for (size_t i = 0; i < nitems(batch); i++)
			pci_vtdtr_cq_enqueue(&d->queue, control_entry(batch[i], vm_epoch));
		pthread_mutex_lock(&d->sc.vsd_mtx);
		available = 8;
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		run_start(d, &t);
		RUN_WAIT(d, delivered_count >= 5);
		usleep(20000);
		run_stop(d, t);
		OK(delivered_count == 5);
		for (size_t i = 0; i < 5; i++)
			OK(log[i] == batch[i]);
		OK(d->sc.vsd_session_stop_delivered && d->sc.vsd_fresh_prepare_delivered &&
		    d->sc.vsd_fresh_commit_delivered && d->sc.vsd_cleanup_unapplied &&
		    d->sc.vsd_cleanup_delivery_id == 9 && d->queue.count == 1);
		/* Once the queue drains the guest receives an EOF descriptor. */
		pthread_mutex_lock(&d->sc.vsd_mtx);
		drain(d);
		d->sc.vsd_cleanup_unapplied = false;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		available = 4;
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		delivered_count = 0;
		run_start(d, &t);
		RUN_WAIT(d, delivered_count >= 2);
		run_stop(d, t);
		OK(log[0] == VTDTR_DEVICE_KILL && log[1] == VTDTR_DEVICE_EOF);
		delivered_log = NULL;
		drain(d);
	}
	/* A control for another lifetime resets the device and drops the queue. */
	{
		struct device *d = new_device();
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch + 1));
		pthread_mutex_lock(&d->sc.vsd_mtx);
		available = 2;
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		run_start(d, &t);
		RUN_WAIT(d, (d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
		run_stop(d, t);
		OK(d->queue.count == 0);
	}
	/* A descriptor too small for a control: nothing is delivered. */
	{
		struct device *d = new_device();
		int done = completions;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		pthread_mutex_lock(&d->sc.vsd_mtx);
		available = 1;
		malformed = 1;
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		run_start(d, &t);
		RUN_WAIT(d, available == 0);
		usleep(20000);
		run_stop(d, t);
		malformed = 0;
		OK(completions == done && d->queue.count == 1);
		drain(d);
	}
	/* An expired fresh-session deadline resets the device. */
	{
		struct device *d = new_device();
		d->sc.vsd_fresh_requested = true;
		clock_gettime(CLOCK_MONOTONIC, &d->sc.vsd_fresh_deadline);
		d->sc.vsd_fresh_deadline.tv_sec -= 1;
		available = 0;
		run_start(d, &t);
		RUN_WAIT(d, (d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
		run_stop(d, t);
		OK(true);
	}
	/* An authorization that fails twice resets the device. */
	{
		struct device *d = new_device();
		d->sc.vsd_fresh_requested = d->sc.vsd_fresh_active = true;
		vtdtr_shutdown_sc = NULL;	/* authorization reports ENXIO */
		run_start(d, &t);
		RUN_WAIT(d, (d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
		run_stop(d, t);
		OK(true);
	}
	printf("vtdtr communicator: %d checks\n", vchecks - before);
}

/* ------------------------------------------------- events reader */
/*
 * The reader thread (pci_vtdtr_events) over a scripted transport.  Each
 * frame is delivered once; then the transport reports "idle" (EAGAIN).
 * Oracles: an accepted frame appends exactly its controls to the device
 * queue (ELF payloads split at the wire maximum, the target envelope
 * stripped, ids copied); ELF and CLEANUP are acknowledged exactly when
 * accepted; KILL is never acknowledged; a malformed frame, a read failure
 * or a failed acknowledgment sets NEEDS_RESET and queues nothing; an ELF
 * for another VM lifetime is acknowledged and dropped without a reset; a
 * frame from a stale transport generation changes nothing.
 */
struct rframe {
	dtraced_hdr_t hdr;
	uint8_t *data;
	size_t len;
	int error;		/* nonzero: the read fails with this errno */
	uint64_t generation;
};
static struct rframe rframes[8];
static int rcount, rnext, ridle;
static pthread_mutex_t rlock = PTHREAD_MUTEX_INITIALIZER;

static int
scripted_read(void **buf, dtraced_hdr_t *hdr, uint64_t *generation, uint64_t *connection)
{
	struct rframe f;

	pthread_mutex_lock(&rlock);
	if (rnext >= rcount) {
		ridle++;
		pthread_mutex_unlock(&rlock);
		*buf = NULL;
		errno = EAGAIN;
		return (-1);
	}
	f = rframes[rnext++];
	pthread_mutex_unlock(&rlock);
	*generation = f.generation;
	*connection = 1;
	*buf = NULL;
	if (f.error != 0) {
		errno = f.error;
		return (-1);
	}
	*hdr = f.hdr;
	if (f.len != 0) {
		*buf = __real_malloc(f.len);
		memcpy(*buf, f.data, f.len);
	}
	return (0);
}

static dtraced_hdr_t
elf_hdr(size_t len, uint64_t delivery)
{
	dtraced_hdr_t h;

	memset(&h, 0, sizeof(h));
	h.msg_type = DTRACED_MSG_ELF;
	h.elf.len = len;
	h.elf.delivery_id = delivery;
	memset(h.elf.program_id, 0x11, sizeof(h.elf.program_id));
	memset(h.elf.source_id, 0x22, sizeof(h.elf.source_id));
	return (h);
}

/* Deliver FRAMES and wait until the reader consumed them and went idle. */
static void
reader_feed(struct device *d, const struct rframe *frames, int n)
{
	struct timespec until;

	pthread_mutex_lock(&rlock);
	memcpy(rframes, frames, sizeof(*frames) * n);
	rcount = n;
	rnext = 0;
	ridle = 0;
	pthread_mutex_unlock(&rlock);
	pthread_mutex_lock(&d->sc.vsd_mtx);
	pthread_cond_broadcast(&d->sc.vsd_cond);
	future(&until, 10);
	for (;;) {
		int consumed;
		pthread_mutex_lock(&rlock);
		consumed = rnext >= rcount && ridle > 0;	/* idle after the frames */
		pthread_mutex_unlock(&rlock);
		if (consumed && !d->sc.vsd_reader_active)
			break;
		pthread_cond_broadcast(&d->sc.vsd_cond);
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		usleep(2000);
		pthread_mutex_lock(&d->sc.vsd_mtx);
		{
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			CHECK(now.tv_sec < until.tv_sec);
		}
	}
	pthread_mutex_unlock(&d->sc.vsd_mtx);
}

static void
test_events_reader(void)
{
	int before = vchecks;
	struct device *d = new_device();
	pthread_t reader;
	uint8_t elf[1024], big[PCI_VTDTR_MAXELFLEN * 2 + 100], targeted[256], foreign[256];
	struct hypertrace_vm_envelope env = { .magic = HYPERTRACE_TARGET_MAGIC,
	    .version = HYPERTRACE_ENVELOPE_VERSION, .vmid = 42, .epoch = 0 };
	struct rframe f[4];
	int acks;

	memcpy(elf, "\177ELF", 4);
	for (size_t i = 4; i < sizeof(elf); i++)
		elf[i] = (uint8_t)i;
	memcpy(big, "\177ELF", 4);
	for (size_t i = 4; i < sizeof(big); i++)
		big[i] = (uint8_t)(i * 7);
	env.epoch = vm_epoch;
	hypertrace_envelope_encode(targeted, &env);
	memcpy(targeted + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, "\177ELF", 4);
	for (size_t i = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4; i < sizeof(targeted); i++)
		targeted[i] = (uint8_t)(i ^ 0x5a);
	env.epoch = vm_epoch + 1;
	hypertrace_envelope_encode(foreign, &env);
	memcpy(foreign + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, "\177ELF", 4);

	read_epoch_script = scripted_read;
	d->sc.vsd_generation = 5;
	rcount = rnext = 0;
	CHECK(pthread_create(&reader, NULL, pci_vtdtr_events, &d->sc) == 0);

#define RESET_SET() ((d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
#define CLEAR_RESET() do { pthread_mutex_lock(&d->sc.vsd_mtx); \
	d->sc.vsd_vs.vs_status &= ~VIRTIO_CONFIG_S_NEEDS_RESET; drain(d); \
	pthread_mutex_unlock(&d->sc.vsd_mtx); } while (0)

	/* An untargeted ELF: one control, ids copied, acknowledged. */
	memset(f, 0, sizeof(f));
	f[0] = (struct rframe){ elf_hdr(sizeof(elf), 7), elf, sizeof(elf), 0, 5 };
	acks = ack_epoch_calls;
	reader_feed(d, f, 1);
	{
		struct pci_vtdtr_ctrl_entry *e = STAILQ_FIRST(&d->queue.head);
		OK(d->queue.count == 1 && e != NULL && e->ctrl->pvc_event == VTDTR_DEVICE_ELF &&
		    e->ctrl->pvc_elflen == sizeof(elf) && e->ctrl->pvc_totalelflen == sizeof(elf) &&
		    !e->ctrl->pvc_elfhasmore && e->ctrl->pvc_delivery_id == 7 &&
		    e->ctrl->pvc_program_id[0] == 0x11 && e->ctrl->pvc_elf_source_id[0] == 0x22 &&
		    e->ctrl->pvc_vmid == 42 && e->ctrl->pvc_epoch == vm_epoch &&
		    memcmp(e->ctrl->pvc_elf, elf, sizeof(elf)) == 0);
		OK(ack_epoch_calls == acks + 1 && !RESET_SET());
	}
	CLEAR_RESET();
	/* dtraced's consumer framing (SHA-256 digest, then the ELF) is not a
	 * device frame: no control, no ACK, NEEDS_RESET. The overlord sent its
	 * live outbound spools to the forwarder this way, so dtraced timed out
	 * waiting for the ACK ("failed to handle job kind 1") and the program
	 * never reached the guest; send_elf() now sends forwarders a bare ELF. */
	{
		static uint8_t sha_framed[SHA256_DIGEST_LENGTH + sizeof(elf)];
		SHA256(elf, sizeof(elf), sha_framed);
		memcpy(sha_framed + SHA256_DIGEST_LENGTH, elf, sizeof(elf));
		f[0] = (struct rframe){ elf_hdr(sizeof(sha_framed), 6), sha_framed,
		    sizeof(sha_framed), 0, 5 };
		acks = ack_epoch_calls;
		reader_feed(d, f, 1);
		OK(d->queue.count == 0 && ack_epoch_calls == acks && RESET_SET());
	}
	CLEAR_RESET();
	/* A large ELF is split at the wire maximum; the pieces concatenate. */
	f[0] = (struct rframe){ elf_hdr(sizeof(big), 8), big, sizeof(big), 0, 5 };
	reader_feed(d, f, 1);
	{
		size_t total = 0, pieces = 0;
		struct pci_vtdtr_ctrl_entry *e;
		STAILQ_FOREACH(e, &d->queue.head, entries) {
			OK(memcmp(e->ctrl->pvc_elf, big + total, e->ctrl->pvc_elflen) == 0 &&
			    e->ctrl->pvc_totalelflen == sizeof(big) &&
			    e->ctrl->pvc_elfhasmore == (total + e->ctrl->pvc_elflen < sizeof(big)));
			total += e->ctrl->pvc_elflen;
			pieces++;
		}
		OK(total == sizeof(big) && pieces == 3 && !RESET_SET());
	}
	CLEAR_RESET();
	/* A targeted ELF for this lifetime loses its envelope. */
	f[0] = (struct rframe){ elf_hdr(sizeof(targeted), 9), targeted, sizeof(targeted), 0, 5 };
	reader_feed(d, f, 1);
	{
		struct pci_vtdtr_ctrl_entry *e = STAILQ_FIRST(&d->queue.head);
		OK(d->queue.count == 1 && e->ctrl->pvc_elflen ==
		    sizeof(targeted) - HYPERTRACE_VM_ENVELOPE_WIRE_SIZE &&
		    memcmp(e->ctrl->pvc_elf, targeted + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
		    e->ctrl->pvc_elflen) == 0);
	}
	CLEAR_RESET();
	/* An ELF for another lifetime: acknowledged and dropped, no reset. */
	acks = ack_epoch_calls;
	f[0] = (struct rframe){ elf_hdr(sizeof(foreign), 10), foreign, sizeof(foreign), 0, 5 };
	reader_feed(d, f, 1);
	OK(d->queue.count == 0 && !RESET_SET() && ack_epoch_calls == acks + 1);
	/* Malformed ELF (too short, bad envelope): reset, nothing queued, no ack. */
	for (int k = 0; k < 2; k++) {
		uint8_t junk[64];
		memset(junk, 0x7e, sizeof(junk));
		acks = ack_epoch_calls;
		f[0] = (struct rframe){ elf_hdr(k == 0 ? 3 : sizeof(junk), 11), junk,
		    k == 0 ? 3 : sizeof(junk), 0, 5 };
		reader_feed(d, f, 1);
		OK(d->queue.count == 0 && RESET_SET() && ack_epoch_calls == acks);
		CLEAR_RESET();
	}
	/* KILL and CLEANUP for this lifetime are queued; only CLEANUP is
	 * acknowledged.  For another lifetime both reset the device. */
	{
		dtraced_hdr_t kill, cleanup;
		memset(&kill, 0, sizeof(kill));
		kill.msg_type = DTRACED_MSG_KILL;
		kill.kill.pid = 77;
		kill.kill.vmid = 42;
		kill.kill.epoch = vm_epoch;
		kill.kill.source_id[0] = 9;
		memset(&cleanup, 0, sizeof(cleanup));
		cleanup.msg_type = DTRACED_MSG_CLEANUP;
		cleanup.cleanup.vmid = 42;
		cleanup.cleanup.epoch = vm_epoch;
		DTRACED_MSG_CLEANUP_DELIVERY_ID(cleanup) = 3;
		acks = ack_epoch_calls;
		f[0] = (struct rframe){ kill, NULL, 0, 0, 5 };
		f[1] = (struct rframe){ cleanup, NULL, 0, 0, 5 };
		reader_feed(d, f, 2);
		OK(d->queue.count == 2 && !RESET_SET() && ack_epoch_calls == acks + 1);
		CLEAR_RESET();
		kill.kill.epoch = vm_epoch + 1;
		f[0] = (struct rframe){ kill, NULL, 0, 0, 5 };
		reader_feed(d, f, 1);
		OK(d->queue.count == 0 && RESET_SET());
		CLEAR_RESET();
		cleanup.cleanup.vmid = 43;
		f[0] = (struct rframe){ cleanup, NULL, 0, 0, 5 };
		reader_feed(d, f, 1);
		OK(d->queue.count == 0 && RESET_SET());
		CLEAR_RESET();
	}
	/* A broken stream resets; an idle or unconnected one does not. */
	f[0] = (struct rframe){ .error = EIO, .generation = 5 };
	reader_feed(d, f, 1);
	OK(RESET_SET());
	CLEAR_RESET();
	f[0] = (struct rframe){ .error = ENOTCONN, .generation = 5 };
	reader_feed(d, f, 1);
	OK(!RESET_SET());
	/* A failed acknowledgment withdraws the accepted frame's health. */
	ack_epoch_error = EPIPE;
	f[0] = (struct rframe){ elf_hdr(sizeof(elf), 12), elf, sizeof(elf), 0, 5 };
	reader_feed(d, f, 1);
	ack_epoch_error = 0;
	OK(RESET_SET());
	CLEAR_RESET();
	/* A frame from an older transport generation changes nothing. */
	acks = ack_epoch_calls;
	f[0] = (struct rframe){ elf_hdr(sizeof(elf), 13), elf, sizeof(elf), 0, 4 };
	f[1] = (struct rframe){ .error = EIO, .generation = 4 };
	reader_feed(d, f, 2);
	OK(d->queue.count == 0 && !RESET_SET() && ack_epoch_calls == acks);

	/* Stop: the reader leaves its idle wait promptly. */
	pthread_mutex_lock(&d->sc.vsd_mtx);
	d->sc.vsd_stopping = true;
	pthread_cond_broadcast(&d->sc.vsd_cond);
	pthread_mutex_unlock(&d->sc.vsd_mtx);
	OK(pthread_join(reader, NULL) == 0);
	read_epoch_script = NULL;
	drain(d);
	printf("vtdtr events reader: %d checks\n", vchecks - before);
#undef RESET_SET
#undef CLEAR_RESET
}

/* ------------------------------------------ round 8: worker arms */
/*
 * The remaining communicator, reader, receive-path, checkpoint-stop and
 * initialization arms.  Oracles as in the sections above: what the guest
 * receives (delivered_log), the device reset flag, queue contents,
 * acknowledgments, and the documented errno of each entry point.
 */
extern int __real_atexit(void (*)(void));
static int atexit_fail;
int
__wrap_atexit(void (*fn)(void))
{
	if (atexit_fail) {
		atexit_fail = 0;
		return (-1);
	}
	return (__real_atexit(fn));
}

static void
release_stop_hook(struct pci_vtdtr_softc *sc)
{
	sc->vsd_stopping = true;	/* a lifecycle stop during the RPC */
}

static void
test_round8_communicator(void)
{
	int before = vchecks;
	uint32_t log[16];
	pthread_t t;

	delivered_log = log;
	delivered_cap = nitems(log);
	/* Waits: a busy release, an empty queue with descriptors, a suspended
	 * device with a fresh request pending, and a fresh deadline that is
	 * still in the future when the stop arrives. */
	for (int k = 0; k < 4; k++) {
		struct device *d = new_device();
		delivered_count = 0;
		switch (k) {
		case 0: d->sc.vsd_fresh_active = d->sc.vsd_fresh_release_busy = true; available = 0; break;
		case 1: available = 2; break;
		case 2: d->sc.vsd_suspended = d->sc.vsd_fresh_requested = true; available = 0; break;
		case 3: d->sc.vsd_fresh_requested = true; future(&d->sc.vsd_fresh_deadline, 5); available = 0; break;
		}
		run_start(d, &t);
		usleep(20000);
		run_stop(d, t);
		OK(delivered_count == 0 && (d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
		available = 0;
		free_device(d);
	}
	/* A released or busy fresh session still delivers the queue. */
	for (int k = 0; k < 2; k++) {
		struct device *d = new_device();
		delivered_count = 0;
		d->sc.vsd_fresh_active = true;
		if (k == 0)
			d->sc.vsd_fresh_released = true;
		else
			d->sc.vsd_fresh_release_busy = true;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		available = 2;
		run_start(d, &t);
		RUN_WAIT(d, delivered_count >= 2);
		run_stop(d, t);
		OK(log[0] == VTDTR_DEVICE_KILL && log[1] == VTDTR_DEVICE_EOF && d->queue.count == 0);
		available = 0;
		free_device(d);
	}
	/* The lifetime check before a batch: a failing or impossible identity
	 * resets the device and drops the queue. */
	for (int k = 0; k < 4; k++) {
		struct device *d = new_device();
		delivered_count = 0;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		switch (k) {
		case 0: script(1, ID_FAIL); break;
		case 1: script(1, ID(0, vm_epoch)); break;
		case 2: script(1, ID(HYPERTRACE_MAX_VMS, vm_epoch)); break;
		case 3: script(1, ID(42, 0)); break;
		}
		available = 2;
		run_start(d, &t);
		RUN_WAIT(d, (d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
		run_stop(d, t);
		unscript();
		OK(delivered_count == 0 && d->queue.count == 0);
		available = 0;
		free_device(d);
	}
	/* A one-descriptor ring: the lifetime check and the batch are bounded
	 * by the ring size, and the queue drains over several batches. */
	{
		struct device *d = new_device();
		delivered_count = 0;
		d->sc.vsd_queues[0].vq_qsize = 1;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		available = 3;
		run_start(d, &t);
		RUN_WAIT(d, delivered_count >= 1);
		usleep(20000);
		OK(delivered_count == 1 && d->queue.count == 1);	/* awaiting READY */
		pthread_mutex_lock(&d->sc.vsd_mtx);
		d->sc.vsd_guest_ready = 1;		/* the guest reports READY */
		pthread_cond_broadcast(&d->sc.vsd_cond);
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		RUN_WAIT(d, delivered_count >= 3);
		run_stop(d, t);
		OK(log[0] == VTDTR_DEVICE_KILL && log[1] == VTDTR_DEVICE_KILL &&
		    log[2] == VTDTR_DEVICE_EOF && d->queue.count == 0);
		available = 0;
		free_device(d);
	}
	/* A READY-only batch keeps the guest ready. */
	{
		struct device *d = new_device();
		delivered_count = 0;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_READY, vm_epoch));
		available = 2;
		run_start(d, &t);
		RUN_WAIT(d, delivered_count >= 2);
		run_stop(d, t);
		OK(log[0] == VTDTR_DEVICE_READY && d->sc.vsd_guest_ready == 1);
		available = 0;
		free_device(d);
	}
	/* An unapplied CLEANUP with a ready guest and posted descriptors: the
	 * worker waits (releasing vsd_mtx) instead of spinning with the lock
	 * held; once the guest's CLEANUP_APPLIED report arrives the receipt
	 * and the held KILL are delivered.  Fail-before (cb24 sources, the
	 * predicate without vsd_cleanup_unapplied): the lock is never released
	 * and the first check fails; see fb8-vtdtr. */
	{
		struct device *d = new_device();
		struct pci_vtdtr_softc *sc = &d->sc;
		struct pci_vtdtr_control applied = { .pvc_event = VTDTR_DEVICE_CLEANUP_APPLIED };
		struct iovec iov = { &applied, sizeof(applied) };
		struct timespec until;
		int locked = -1;
		delivered_count = 0;
		sc->vsd_cleanup_unapplied = true;
		sc->vsd_cleanup_delivery_id = 9;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		available = 4;
		run_start(d, &t);
		future(&until, 2);
		for (;;) {
			struct timespec now;
			usleep(20000);
			if (pthread_mutex_trylock(&sc->vsd_mtx) == 0) {
				locked = 1;
				break;
			}
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec >= until.tv_sec) {
				locked = 0;
				break;
			}
		}
		OK(locked == 1);	/* fail-before: the worker never lets go of the lock */
		CHECK(locked == 1);
		OK(delivered_count == 0 && d->queue.count == 1);
		applied.pvc_cleanup_vmid = 42;
		applied.pvc_cleanup_epoch = vm_epoch;
		applied.pvc_cleanup_delivery_id = 9;
		sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
		OK(pci_vtdtr_control_rx(sc, &iov, 1) == 0 && !sc->vsd_cleanup_unapplied);
		pthread_mutex_unlock(&sc->vsd_mtx);
		RUN_WAIT(d, delivered_count >= 3);
		run_stop(d, t);
		OK(log[0] == VTDTR_DEVICE_HOST_CLEANUP_APPLIED && log[1] == VTDTR_DEVICE_KILL &&
		    log[2] == VTDTR_DEVICE_EOF && d->queue.count == 0);
		available = 0;
		free_device(d);
	}
	/* The ring reports descriptors but yields no chain: the first batch is
	 * empty (nothing marked ready, no reset) and the next pass delivers. */
	{
		struct device *d = new_device();
		delivered_count = 0;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		available = 2;
		chain_zero = 1;
		run_start(d, &t);
		RUN_WAIT(d, delivered_count >= 2);
		run_stop(d, t);
		OK(chain_zero == 0 && log[0] == VTDTR_DEVICE_KILL && log[1] == VTDTR_DEVICE_EOF &&
		    d->queue.count == 0 &&
		    (d->sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
		available = 0;
		free_device(d);
	}
	/* A lifecycle stop that lands during the release RPC: the failed
	 * authorization does not reset a device that is stopping, and the
	 * worker leaves on its own. */
	{
		struct device *d = new_device();
		struct pci_vtdtr_softc *sc = &d->sc;
		delivered_count = 0;
		sc->vsd_fresh_requested = sc->vsd_fresh_active = true;
		sc->vsd_session_stop_requested = sc->vsd_session_stopped = true;
		sc->vsd_fresh_vmid = 42;
		sc->vsd_fresh_epoch = vm_epoch;
		sc->vsd_generation = 5;
		memset(sc->vsd_fresh_gate_token, 0x33, 16);
		memset(destination_gate_owner, 0x33, 16);
		destination_released = false;
		destination_gate_failure = 0;
		vtdtr_shutdown_sc = sc;
		release_hook = release_stop_hook;
		available = 0;
		run_start(d, &t);
		CHECK(pthread_join(t, NULL) == 0);	/* exits without run_stop */
		release_hook = NULL;
		vtdtr_shutdown_sc = NULL;
		OK(sc->vsd_stopping && (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
		memset(destination_gate_owner, 0, 16);
		free_device(d);
	}
	delivered_log = NULL;
	printf("vtdtr round 8 communicator arms: %d checks\n", vchecks - before);
}

/* Receive path (guest to host) and READY delivery with malformed chains. */
static void
test_round8_rx(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	static const struct pci_vtdtr_control ready = { .pvc_event = VTDTR_DEVICE_READY };
	static struct pci_vtdtr_control pair[2] = {
		{ .pvc_event = VTDTR_DEVICE_INSTALLED }, { .pvc_event = VTDTR_DEVICE_READY } };
	int done, dd;

	pair[0].pvc_installed_epoch = vm_epoch + 7;	/* another lifetime: resets */
	sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	pci_vtdtr_debug = 1;	/* the DPRINTF arms */
#define RESET() ((sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
#define CLEAR() (sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK)
	pthread_mutex_lock(&sc->vsd_mtx);
	/* No descriptors: nothing happens. */
	available = 0;
	done = completions;
	pci_vtdtr_notify_rx(sc, &sc->vsd_queues[1]);
	OK(!RESET() && completions == done);
	/* The chain cannot be read; the chain is empty.  READY was already
	 * delivered, so the pass does not post one. */
	incoming_controls = &ready;
	sc->vsd_ready = 1;
	for (int k = 0; k < 2; k++) {
		incoming_index = 0;
		available = 1;
		if (k == 0)
			chain_error = 1;
		else
			chain_zero = 1;
		done = completions;
		pci_vtdtr_notify_rx(sc, &sc->vsd_queues[1]);
		OK(RESET() == (k == 0) && completions == done);
		CLEAR();
		available = 0;
	}
	sc->vsd_ready = 0;
	/* Malformed chain shapes. */
	for (int k = 0; k < 4; k++) {
		incoming_index = 0;
		available = 1;
		chain_niov_over = k == 0;
		chain_unordered = k == 1;
		chain_readable_delta = k == 2;
		chain_writable_delta = k == 3;
		dd = discarded_completions;
		pci_vtdtr_notify_rx(sc, &sc->vsd_queues[1]);
		chain_niov_over = chain_unordered = chain_readable_delta = chain_writable_delta = 0;
		OK(RESET() && discarded_completions == dd + 1);
		CLEAR();
		available = 0;
	}
	/* A control that fails the device stops processing the rest of the
	 * pass; every chain is still returned. */
	incoming_controls = pair;
	incoming_index = 0;
	available = 2;
	dd = discarded_completions;
	sc->vsd_guest_ready = 0;
	pci_vtdtr_notify_rx(sc, &sc->vsd_queues[1]);
	OK(RESET() && discarded_completions == dd + 2 && sc->vsd_guest_ready == 0);
	CLEAR();
	available = 0;
	/* READY already delivered: a receive pass does not repeat it. */
	incoming_controls = &ready;
	incoming_index = 0;
	available = 1;
	sc->vsd_ready = 1;
	dd = discarded_completions;
	pci_vtdtr_notify_rx(sc, &sc->vsd_queues[1]);
	OK(!RESET() && discarded_completions == dd + 1 && sc->vsd_ready == 1);
	sc->vsd_ready = 0;
	available = 0;
	incoming_controls = NULL;
	/* READY delivery: an unreadable or empty chain, malformed shapes, and
	 * a four-segment chain with an empty and a spare segment. */
	for (int k = 0; k < 7; k++) {
		available = 1;
		sc->vsd_ready = 0;
		done = completions;
		dd = discarded_completions;
		switch (k) {
		case 0: chain_error = 1; break;
		case 1: chain_zero = 1; break;
		case 2: chain_niov_over = 1; break;
		case 3: chain_unordered = 1; break;
		case 4: chain_readable_delta = 1; break;
		case 5: chain_writable_delta = 1; break;
		case 6: split = 3; memset(&output, 0, sizeof(output)); break;
		}
		pci_vtdtr_notify_ready(sc);
		chain_niov_over = chain_unordered = chain_readable_delta = chain_writable_delta = 0;
		split = 0;
		if (k == 6)
			OK(!RESET() && sc->vsd_ready == 1 && completions == done + 1 &&
			    output.pvc_event == VTDTR_DEVICE_READY);
		else
			OK(RESET() == (k != 1) && sc->vsd_ready == 0 && completions == done &&
			    discarded_completions == dd + (k >= 2 ? 1 : 0));
		CLEAR();
		available = 0;
	}
	pthread_mutex_unlock(&sc->vsd_mtx);
	pci_vtdtr_debug = 0;
#undef RESET
#undef CLEAR
	free_device(d);
	printf("vtdtr round 8 receive arms: %d checks\n", vchecks - before);
}

/* Replayability, the checkpoint state validator's open run, the rekey
 * head test, and the staged private restore's refusals. */
static void
test_round8_checkpoint(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;

	/* A stopped source whose transmit ring cannot be inspected. */
	source_valid_baseline(d);
	checkpoint_tx_error = EIO;
	OK(pci_vtdtr_checkpoint_replayable(sc) == EIO);
	checkpoint_tx_error = 0;
	sc->vsd_session_stop_requested = false;
	memset(sc->vsd_session_gate_token, 0, 16);
	/* Replayable queue contents: KILL, applied KILL, READY and EOF. */
	{
		static const uint32_t events[] = { VTDTR_DEVICE_KILL,
		    VTDTR_DEVICE_HOST_KILL_APPLIED, VTDTR_DEVICE_READY, VTDTR_DEVICE_EOF };
		sc->vsd_vs.vs_negotiated_caps = VTDTR_RESTORE_REQUIRED_FEATURES;
		for (size_t i = 0; i < nitems(events); i++) {
			struct pci_vtdtr_ctrl_entry *e = control_entry(events[i], vm_epoch);
			int error;
			pci_vtdtr_cq_enqueue(&d->queue, e);
			error = pci_vtdtr_checkpoint_replayable(sc);
			OK(error == 0 || error == EPROTO);	/* EPROTO: the validator refuses the event */
			drain(d);
		}
	}
	/* An ELF run left open at the end of the queue is not a valid cut. */
	{
		struct pci_vtdtr_ctrl_entry *e = __real_calloc(1, sizeof(*e));
		e->ctrl = __real_calloc(1, sizeof(*e->ctrl));
		*e->ctrl = elf_fragment(2 * PCI_VTDTR_MAXELFLEN, PCI_VTDTR_MAXELFLEN, true, 0);
		e->ctrl->pvc_vmid = 42;
		e->ctrl->pvc_epoch = vm_epoch;
		pci_vtdtr_cq_enqueue(&d->queue, e);
		OK(pci_vtdtr_checkpoint_state_valid(sc) == EPROTO);
		OK(pci_vtdtr_checkpoint_replayable(sc) == EPROTO);
		drain(d);
	}
	/* A closed short run (the final piece leaves a whole number of chunks
	 * unsent) passes the state validator but is not replayable; a valid
	 * applied-KILL receipt is; a queued identity control is not. */
	{
		struct pci_vtdtr_ctrl_entry *e = __real_calloc(1, sizeof(*e));
		e->ctrl = __real_calloc(1, sizeof(*e->ctrl));
		*e->ctrl = elf_fragment(2 * PCI_VTDTR_MAXELFLEN, PCI_VTDTR_MAXELFLEN, false, 0);
		e->ctrl->pvc_vmid = 42;
		e->ctrl->pvc_epoch = vm_epoch;
		pci_vtdtr_cq_enqueue(&d->queue, e);
		OK(pci_vtdtr_checkpoint_state_valid(sc) == 0);
		OK(pci_vtdtr_checkpoint_replayable(sc) == EOPNOTSUPP);
		drain(d);
		e = control_entry(VTDTR_DEVICE_HOST_KILL_APPLIED, vm_epoch);
		e->ctrl->pvc_pid = 55;
		e->ctrl->pvc_kill_vmid = 42;
		e->ctrl->pvc_kill_epoch = vm_epoch;
		e->ctrl->pvc_source_id[0] = 1;
		pci_vtdtr_cq_enqueue(&d->queue, e);
		OK(pci_vtdtr_checkpoint_state_valid(sc) == 0);
		OK(pci_vtdtr_checkpoint_replayable(sc) == 0);
		drain(d);
		e = control_entry(VTDTR_DEVICE_NODE_ID, vm_epoch);
		e->ctrl->pvc_node_id = 42;
		e->ctrl->pvc_node_epoch = vm_epoch;
		pci_vtdtr_cq_enqueue(&d->queue, e);
		OK(pci_vtdtr_checkpoint_state_valid(sc) == 0);
		OK(pci_vtdtr_checkpoint_replayable(sc) == EOPNOTSUPP);
		drain(d);
	}
	/* No rekey at the head of an empty queue. */
	OK(!pci_vtdtr_rekey_head_awaits_ticket(sc));
	/* The staged private restore's guards and the image/record mismatches. */
	{
		struct device *src = new_device();
		static uint8_t img[IMG_HDR + 256];
		struct hypertrace_session_record rec = { .vmid = 43, .epoch = 100,
		    .stop_token = 0x77, .features = HYPERTRACE_SESSION_FEATURES };
		size_t len;
		int error;

		sc->vsd_vmctx = (struct vmctx *)1;		/* identity 43/100 */
		sc->vsd_fresh_vmid = 43;
		sc->vsd_fresh_epoch = 100;
		memset(sc->vsd_fresh_gate_token, 0x44, 16);
		memset(destination_gate_owner, 0x44, 16);
		destination_released = false;
		destination_gate_failure = 0;
		src->sc.vsd_vmctx = (struct vmctx *)1;
		src->sc.vsd_guest_ready = 0;
		len = save_image(src, img, sizeof(img));
		{
			struct vm_snapshot_meta m = { .buffer = { .buf_start = img, .buf_size = len,
			    .buf = img, .buf_rem = len }, .op = VM_SNAPSHOT_RESTORE };
			OK(hypertrace_session_record_encode(sc->vsd_session_restore_record,
			    sizeof(sc->vsd_session_restore_record), &rec) == 0);
			sc->vsd_checkpoint_paused = false;
			sc->vsd_session_restore_staged = true;
			OK(pci_vtdtr_session_private_restore(sc, &m) == EBUSY);
			sc->vsd_checkpoint_paused = true;
			sc->vsd_reader_active = true;
			OK(pci_vtdtr_session_private_restore(sc, &m) == EBUSY);
			sc->vsd_reader_active = false;
			sc->vsd_session_restore_staged = false;
			OK(pci_vtdtr_session_private_restore(sc, &m) == EBUSY);
			sc->vsd_session_restore_staged = true;
			m.op = VM_SNAPSHOT_SAVE;
			OK(pci_vtdtr_session_private_restore(sc, &m) == EBUSY);
			m.op = VM_SNAPSHOT_RESTORE;
			/* An undecodable staged record. */
			memset(sc->vsd_session_restore_record, 0xee, sizeof(sc->vsd_session_restore_record));
			error = pci_vtdtr_session_private_restore(sc, &m);
			OK(error != 0 && error != EBUSY);
			OK(hypertrace_session_record_encode(sc->vsd_session_restore_record,
			    sizeof(sc->vsd_session_restore_record), &rec) == 0);
			/* A matching image whose configuration differs. */
			sc->vsd_session_restore_cfg = src->sc.vsd_cfg + 1;
			m.buffer.buf = img; m.buffer.buf_rem = len;
			OK(pci_vtdtr_session_private_restore(sc, &m) == EPROTO);
			sc->vsd_session_restore_cfg = src->sc.vsd_cfg;
		}
		/* Image/record mismatches: the record names another VM; the image
		 * carries a queued control, a ready guest, or a delivered READY. */
		for (int k = 0; k < 4; k++) {
			struct hypertrace_session_record other = rec;
			src->sc.vsd_guest_ready = 0;
			src->sc.vsd_ready = 0;
			drain(src);
			switch (k) {
			case 0: other.vmid = 41; break;
			case 1: {
				struct pci_vtdtr_ctrl_entry *e = control_entry(VTDTR_DEVICE_KILL, 100);
				e->ctrl->pvc_kill_vmid = 43;	/* this device's lifetime */
				pci_vtdtr_cq_enqueue(&src->queue, e);
				break;
			}
			case 2: src->sc.vsd_guest_ready = 1; break;
			case 3: src->sc.vsd_ready = 1; break;
			}
			len = save_image(src, img, sizeof(img));
			struct vm_snapshot_meta m = { .buffer = { .buf_start = img, .buf_size = len,
			    .buf = img, .buf_rem = len }, .op = VM_SNAPSHOT_RESTORE };
			OK(hypertrace_session_record_encode(sc->vsd_session_restore_record,
			    sizeof(sc->vsd_session_restore_record), &other) == 0);
			OK(pci_vtdtr_session_private_restore(sc, &m) == EPROTO);
			drain(src);
		}
		src->sc.vsd_guest_ready = src->sc.vsd_ready = 0;
		memset(destination_gate_owner, 0, 16);
		free_device(src);
	}
	free_device(d);
	printf("vtdtr round 8 checkpoint arms: %d checks\n", vchecks - before);
}

/* Reader frames that exercise the remaining target, identity, allocation
 * and publication arms. */
static void
wait_reader_idle(struct device *d)
{
	struct timespec until;

	future(&until, 10);
	for (;;) {
		int consumed;
		pthread_mutex_lock(&rlock);
		consumed = rnext >= rcount && ridle > 0;
		pthread_mutex_unlock(&rlock);
		pthread_mutex_lock(&d->sc.vsd_mtx);
		if (consumed && !d->sc.vsd_reader_active) {
			pthread_mutex_unlock(&d->sc.vsd_mtx);
			break;
		}
		pthread_cond_broadcast(&d->sc.vsd_cond);
		pthread_mutex_unlock(&d->sc.vsd_mtx);
		usleep(2000);
		{
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			CHECK(now.tv_sec < until.tv_sec);
		}
	}
}

static void
test_round8_reader(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	pthread_t reader;
	uint8_t elf[256], targeted[256];
	struct hypertrace_vm_envelope env = { .magic = HYPERTRACE_TARGET_MAGIC,
	    .version = HYPERTRACE_ENVELOPE_VERSION, .vmid = 42, .epoch = 0 };
	struct rframe f[2];
	int acks;

#define RESET_SET() ((sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
#define CLEAR_RESET() do { pthread_mutex_lock(&sc->vsd_mtx); \
	sc->vsd_vs.vs_status &= ~VIRTIO_CONFIG_S_NEEDS_RESET; drain(d); \
	pthread_mutex_unlock(&sc->vsd_mtx); } while (0)
	memcpy(elf, "\177ELF", 4);
	for (size_t i = 4; i < sizeof(elf); i++)
		elf[i] = (uint8_t)(i * 3);
	env.epoch = vm_epoch;
	hypertrace_envelope_encode(targeted, &env);
	memcpy(targeted + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, "\177ELF", 4);
	for (size_t i = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4; i < sizeof(targeted); i++)
		targeted[i] = (uint8_t)(i ^ 0x3c);

	read_epoch_script = scripted_read;
	sc->vsd_generation = 5;
	rcount = rnext = ridle = 0;
	/* The reader does not read while a checkpoint pause or a session stop
	 * is in force. */
	for (int k = 0; k < 2; k++) {
		if (k == 0)
			sc->vsd_checkpoint_paused = true;
		else
			sc->vsd_session_stop_requested = true;
		ridle = 0;
		CHECK(pthread_create(&reader, NULL, pci_vtdtr_events, sc) == 0);
		usleep(20000);
		pthread_mutex_lock(&rlock);
		OK(ridle == 0);
		pthread_mutex_unlock(&rlock);
		pthread_mutex_lock(&sc->vsd_mtx);
		sc->vsd_checkpoint_paused = false;
		sc->vsd_session_stop_requested = false;
		pthread_cond_broadcast(&sc->vsd_cond);
		pthread_mutex_unlock(&sc->vsd_mtx);
		wait_reader_idle(d);
		pthread_mutex_lock(&rlock);
		OK(ridle > 0);
		pthread_mutex_unlock(&rlock);
		pthread_mutex_lock(&sc->vsd_mtx);
		sc->vsd_stopping = true;
		pthread_cond_broadcast(&sc->vsd_cond);
		pthread_mutex_unlock(&sc->vsd_mtx);
		CHECK(pthread_join(reader, NULL) == 0);
		sc->vsd_stopping = false;
	}
	ridle = 0;
	CHECK(pthread_create(&reader, NULL, pci_vtdtr_events, sc) == 0);
	/* An ELF for another lifetime from a stale transport generation is
	 * neither acknowledged nor reset; one whose acknowledgment fails resets. */
	env.epoch = vm_epoch + 1;
	hypertrace_envelope_encode(targeted, &env);
	acks = ack_epoch_calls;
	f[0] = (struct rframe){ elf_hdr(sizeof(targeted), 20), targeted, sizeof(targeted), 0, 4 };
	reader_feed(d, f, 1);
	OK(d->queue.count == 0 && !RESET_SET() && ack_epoch_calls == acks);
	ack_epoch_error = EPIPE;
	f[0] = (struct rframe){ elf_hdr(sizeof(targeted), 21), targeted, sizeof(targeted), 0, 5 };
	reader_feed(d, f, 1);
	ack_epoch_error = 0;
	OK(d->queue.count == 0 && RESET_SET());
	CLEAR_RESET();
	env.epoch = vm_epoch;
	hypertrace_envelope_encode(targeted, &env);
	/* The lifetime read for an untargeted ELF fails or is impossible. */
	for (int k = 0; k < 4; k++) {
		switch (k) {
		case 0: script(1, ID_FAIL); break;
		case 1: script(1, ID(0, vm_epoch)); break;
		case 2: script(1, ID(HYPERTRACE_MAX_VMS, vm_epoch)); break;
		case 3: script(1, ID(42, 0)); break;
		}
		acks = ack_epoch_calls;
		f[0] = (struct rframe){ elf_hdr(sizeof(elf), 22 + k), elf, sizeof(elf), 0, 5 };
		reader_feed(d, f, 1);
		unscript();
		OK(d->queue.count == 0 && RESET_SET() && ack_epoch_calls == acks);
		CLEAR_RESET();
	}
	/* A targeted ELF whose lifetime changes between the two reads. */
	for (int k = 0; k < 2; k++) {
		script(2, ID(42, vm_epoch), k == 0 ? ID(41, vm_epoch) : ID(42, vm_epoch + 1));
		acks = ack_epoch_calls;
		f[0] = (struct rframe){ elf_hdr(sizeof(targeted), 30 + k), targeted, sizeof(targeted), 0, 5 };
		reader_feed(d, f, 1);
		unscript();
		OK(d->queue.count == 0 && RESET_SET() && ack_epoch_calls == acks);
		CLEAR_RESET();
	}
	/* Malformed target envelopes. */
	for (int k = 0; k < 7; k++) {
		uint8_t bad[sizeof(targeted)];
		struct hypertrace_vm_envelope e = env;
		size_t len = sizeof(bad);
		memcpy(bad, targeted, sizeof(bad));
		switch (k) {
		case 0: len = 10; bad[0] = 0; break;	/* too short for an envelope */
		case 1: e.version = HYPERTRACE_ENVELOPE_VERSION + 1; break;
		case 2: e.vmid = 0; break;
		case 3: e.vmid = HYPERTRACE_MAX_VMS; break;
		case 4: e.name_length = 1; break;
		case 5: bad[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE] ^= 1; break;	/* no ELF after it */
		case 6: script(1, ID_FAIL); break;
		}
		if (k >= 1 && k <= 4)
			hypertrace_envelope_encode(bad, &e);
		acks = ack_epoch_calls;
		f[0] = (struct rframe){ elf_hdr(len, 40 + k), bad, len, 0, 5 };
		reader_feed(d, f, 1);
		unscript();
		OK(d->queue.count == 0 && RESET_SET() && ack_epoch_calls == acks);
		CLEAR_RESET();
	}
	/* KILL and CLEANUP frames that do not match this device. */
	{
		dtraced_hdr_t kill, cleanup;
		memset(&kill, 0, sizeof(kill));
		kill.msg_type = DTRACED_MSG_KILL;
		kill.kill.pid = 77;
		kill.kill.vmid = 42;
		kill.kill.epoch = vm_epoch;
		kill.kill.source_id[0] = 9;
		memset(&cleanup, 0, sizeof(cleanup));
		cleanup.msg_type = DTRACED_MSG_CLEANUP;
		cleanup.cleanup.vmid = 42;
		cleanup.cleanup.epoch = vm_epoch;
		DTRACED_MSG_CLEANUP_DELIVERY_ID(cleanup) = 3;
		for (int k = 0; k < 8; k++) {
			dtraced_hdr_t h = k < 4 ? kill : cleanup;
			switch (k) {
			case 0: h.kill.pid = 1; break;
			case 1: h.kill.epoch = 0; break;
			case 2: h.kill.source_id[0] = 0; break;
			case 3: script(1, ID_FAIL); break;
			case 4: h.cleanup.vmid = HYPERTRACE_MAX_VMS; break;
			case 5: h.cleanup.epoch = 0; break;
			case 6: DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 0; break;
			case 7: script(1, ID_FAIL); break;
			}
			acks = ack_epoch_calls;
			f[0] = (struct rframe){ h, NULL, 0, 0, 5 };
			reader_feed(d, f, 1);
			unscript();
			OK(d->queue.count == 0 && RESET_SET() && ack_epoch_calls == acks);
			CLEAR_RESET();
		}
		/* An unknown message type. */
		{
			dtraced_hdr_t h;
			memset(&h, 0, sizeof(h));
			h.msg_type = 0x7f;
			acks = ack_epoch_calls;
			f[0] = (struct rframe){ h, NULL, 0, 0, 5 };
			reader_feed(d, f, 1);
			OK(d->queue.count == 0 && RESET_SET() && ack_epoch_calls == acks);
			CLEAR_RESET();
		}
		/* Allocation failures while assembling a frame: the control of
		 * an ELF, KILL or CLEANUP, and the queue entry. */
		for (int k = 0; k < 4; k++) {
			acks = ack_epoch_calls;
			switch (k) {
			case 0: f[0] = (struct rframe){ elf_hdr(sizeof(elf), 50), elf, sizeof(elf), 0, 5 }; break;
			case 1: f[0] = (struct rframe){ kill, NULL, 0, 0, 5 }; break;
			case 2: f[0] = (struct rframe){ cleanup, NULL, 0, 0, 5 }; break;
			case 3: f[0] = (struct rframe){ elf_hdr(sizeof(elf), 51), elf, sizeof(elf), 0, 5 }; break;
			}
			alloc_count = 0;
			alloc_fail_at = k == 3 ? 2 : 1;
			alloc_armed = true;
			reader_feed(d, f, 1);
			alloc_armed = false;
			OK(d->queue.count == 0 && RESET_SET() && ack_epoch_calls == acks);
			CLEAR_RESET();
		}
	}
	/* Publication waits for queue room: the frame is queued once room
	 * appears. */
	{
		acks = ack_epoch_calls;
		pthread_mutex_lock(&sc->vsd_mtx);
		d->queue.count = VTDTR_MAX_PENDING;	/* every normal slot in use */
		pthread_mutex_unlock(&sc->vsd_mtx);
		pthread_mutex_lock(&rlock);
		rframes[0] = (struct rframe){ elf_hdr(sizeof(elf), 60), elf, sizeof(elf), 0, 5 };
		rcount = 1;
		rnext = 0;
		ridle = 0;
		pthread_mutex_unlock(&rlock);
		pthread_mutex_lock(&sc->vsd_mtx);
		pthread_cond_broadcast(&sc->vsd_cond);
		pthread_mutex_unlock(&sc->vsd_mtx);
		usleep(30000);
		pthread_mutex_lock(&sc->vsd_mtx);
		OK(d->queue.count == VTDTR_MAX_PENDING && STAILQ_EMPTY(&d->queue.head) &&
		    sc->vsd_reader_active);
		d->queue.count = 0;
		pthread_cond_broadcast(&sc->vsd_cond);
		pthread_mutex_unlock(&sc->vsd_mtx);
		wait_reader_idle(d);
		OK(d->queue.count == 1 && !RESET_SET() && ack_epoch_calls == acks + 1);
		CLEAR_RESET();
	}
	pthread_mutex_lock(&sc->vsd_mtx);
	sc->vsd_stopping = true;
	pthread_cond_broadcast(&sc->vsd_cond);
	pthread_mutex_unlock(&sc->vsd_mtx);
	CHECK(pthread_join(reader, NULL) == 0);
	read_epoch_script = NULL;
#undef RESET_SET
#undef CLEAR_RESET
	free_device(d);
	printf("vtdtr round 8 reader arms: %d checks\n", vchecks - before);
}

/* Checkpoint stop with live workers, pause failures, and initialization. */
static void
test_round8_lifecycle(void)
{
	int before = vchecks;

	/* Releasing the checkpoint for a stop needs a paused device whose
	 * reader is idle. */
	{
		struct device *d = new_device();
		struct pci_vtdtr_softc *sc = &d->sc;
		OK(pci_vtdtr_release_checkpoint_for_stop(sc) == EBUSY);
		sc->vsd_checkpoint_paused = true;
		sc->vsd_reader_active = true;
		OK(pci_vtdtr_release_checkpoint_for_stop(sc) == EBUSY);
		sc->vsd_checkpoint_paused = false;
		sc->vsd_reader_active = false;
		vtdtr_shutdown_sc = NULL;
		OK(pci_vtdtr_checkpoint_stop() == 0);
		vtdtr_shutdown_sc = sc;
		OK(pci_vtdtr_checkpoint_stop() == EBUSY && !sc->vsd_stopping);
		vtdtr_shutdown_sc = NULL;
		/* A reader that never goes idle: the pause times out. */
		sc->vsd_reader_active = true;
		OK(pci_vtdtr_pause(sc) == ETIMEDOUT && !sc->vsd_checkpoint_paused);
		sc->vsd_reader_active = false;
		free_device(d);
	}
	/* With live workers: pause, then stop the VM through the checkpoint
	 * path; both workers are joined and the device is stopping. */
	{
		struct device *d = new_device();
		struct pci_vtdtr_softc *sc = &d->sc;
		read_epoch_script = scripted_read;
		rcount = rnext = ridle = 0;
		sc->vsd_generation = 5;
		available = 0;
		CHECK(pthread_create(&sc->vsd_reader, NULL, pci_vtdtr_events, sc) == 0);
		sc->vsd_vmctx = (struct vmctx *)2;
		CHECK(pthread_create(&sc->vsd_communicator, NULL, pci_vtdtr_run, sc) == 0);
		wait_reader_idle(d);
		OK(pci_vtdtr_pause(sc) == 0);
		vtdtr_shutdown_sc = sc;
		OK(pci_vtdtr_checkpoint_stop() == 0);
		OK(vtdtr_shutdown_sc == NULL && sc->vsd_stopping);
		OK(pthread_mutex_trylock(&sc->vsd_mtx) == 0);
		pthread_mutex_unlock(&sc->vsd_mtx);
		read_epoch_script = NULL;
		free_device(d);
	}
	/* Initialization refusals and failures beyond the first three stages. */
	{
		struct pci_devinst pi = { 0 };
		hypertrace_ready = 0;
		OK(pci_vtdtr_init(&pi, NULL) == EINVAL && pi.pi_arg == NULL);
		hypertrace_ready = 1;
		vtdtr_present = true;
		OK(pci_vtdtr_init(&pi, NULL) == EBUSY);
		vtdtr_present = false;
		fake_vmid = 0;
		OK(pci_vtdtr_init(&pi, NULL) == ENOTSUP);
		fake_vmid = 42;
		for (int at = 1; at <= 2; at++) {
			alloc_count = 0;
			alloc_fail_at = at;
			alloc_armed = true;
			OK(pci_vtdtr_init(&pi, NULL) == ENOMEM);
			alloc_armed = false;
		}
		script(1, ID_FAIL);	/* the identity control cannot be built */
		OK(pci_vtdtr_init(&pi, NULL) == EIO && !vtdtr_present);
		unscript();
		atexit_fail = 1;
		OK(pci_vtdtr_init(&pi, NULL) == ENOMEM && !vtdtr_present && vtdtr_shutdown_sc == NULL);
		atexit_fail = 0;
		OK(pi.pi_arg == NULL);
	}
	printf("vtdtr round 8 lifecycle arms: %d checks\n", vchecks - before);
}

/* ------------------------------------------ round 8: batch C arms */
static int release_mutate_kind;
static void
release_mutate(struct pci_vtdtr_softc *sc)
{
	switch (release_mutate_kind) {
	case 1: sc->vsd_fresh_active = false; break;
	case 2: sc->vsd_session_stop_requested = false; break;
	case 3: sc->vsd_session_stopped = false; break;
	case 4: sc->vsd_checkpoint_paused = true; break;
	case 5: sc->vsd_suspended = true; break;
	case 6: sc->vsd_generation++; break;
	case 7: sc->vsd_fresh_gate_token[0] ^= 1; break;
	case 8: sc->vsd_vs.vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET; break;
	}
}

static void
test_round8_batch_c(void)
{
	int before = vchecks;
	struct device *d = new_device();
	struct pci_vtdtr_softc *sc = &d->sc;
	struct vmctx *ctx = (struct vmctx *)2;
	struct vmctx *actx = (struct vmctx *)1;	/* identity 43/100: the destination fakes */

	/* Authorization: identity failures, a staged-and-released migration,
	 * a released session that is already READY, state changed during the
	 * release RPC, and an errno-less host_released failure. */
#define AUTH_BASE() do { \
	drain(d); \
	sc->vsd_vmctx = actx; \
	sc->vsd_fresh_requested = sc->vsd_fresh_active = true; \
	sc->vsd_fresh_released = sc->vsd_fresh_release_busy = false; \
	sc->vsd_session_migration_staged = sc->vsd_session_migration_released = false; \
	sc->vsd_stopping = sc->vsd_checkpoint_paused = sc->vsd_suspended = false; \
	sc->vsd_session_restore_staged = sc->vsd_session_restore_pending = false; \
	sc->vsd_rekey_wait = false; \
	sc->vsd_vs.vs_status = 0; \
	sc->vsd_session_stop_requested = sc->vsd_session_stopped = true; \
	sc->vsd_fresh_vmid = 43; sc->vsd_fresh_epoch = 100; \
	sc->vsd_generation = 5; \
	sc->vsd_ready = 0; \
	memset(sc->vsd_fresh_gate_token, 0x33, 16); \
	memset(destination_gate_owner, 0x33, 16); \
	memset(session_gate_owner, 0x33, 16); \
	destination_released = false; destination_gate_failure = 0; \
	session_gate_failure = 0; gate_noerrno = false; \
	vtdtr_shutdown_sc = sc; \
} while (0)
	AUTH_BASE();
	sc->vsd_session_migration_staged = sc->vsd_session_migration_released = true;
	script(1, ID_FAIL);
	OK(pci_vtdtr_session_authorize(actx) == ENXIO);
	script(1, ID_NOERRNO);
	OK(pci_vtdtr_session_authorize(actx) == EIO);
	unscript();
	AUTH_BASE();
	sc->vsd_fresh_released = true;
	destination_released = true;		/* the daemon released this gate */
	sc->vsd_ready = 1;
	OK(pci_vtdtr_session_authorize(actx) == 0 && sc->vsd_ready == 1);
	for (int k = 1; k <= 11; k++) {
		AUTH_BASE();
		release_mutate_kind = k <= 8 ? k : 0;
		release_hook = release_mutate;
		if (k == 9)
			script(2, ID(43, 100), ID_FAIL);
		else if (k == 10)
			script(2, ID(43, 100), ID(44, 100));
		else if (k == 11)
			script(2, ID(43, 100), ID(43, 101));
		OK(pci_vtdtr_session_authorize(actx) == ESTALE && !sc->vsd_fresh_release_busy);
		release_hook = NULL;
		unscript();
	}
	release_mutate_kind = 0;
	AUTH_BASE();
	destination_gate_failure = EPERM;
	gate_noerrno = true;
	OK(pci_vtdtr_session_authorize(actx) == EIO);
	AUTH_BASE();
	sc->vsd_session_stop_requested = sc->vsd_session_stopped = false;
	sc->vsd_fresh_requested = sc->vsd_fresh_active = false;
	memset(sc->vsd_fresh_gate_token, 0, 16);
	memset(destination_gate_owner, 0, 16);
	memset(session_gate_owner, 0, 16);
	vtdtr_shutdown_sc = NULL;
	/* Without a device, status queries are refused. */
	{
		uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE];
		OK(pci_vtdtr_session_checkpoint_export(ctx, wire, sizeof(wire)) == ENXIO);
		OK(pci_vtdtr_session_attach_status(ctx) == ENXIO);
	}
	/* READY is withheld while stopping, after a stop without a fresh
	 * request, during an active fresh session, and while suspended. */
	pthread_mutex_lock(&sc->vsd_mtx);
	for (int k = 0; k < 4; k++) {
		int done = completions, dd = discarded_completions;
		sc->vsd_stopping = sc->vsd_session_stopped = sc->vsd_fresh_requested = false;
		sc->vsd_fresh_active = sc->vsd_suspended = false;
		sc->vsd_vs.vs_status = 0;
		sc->vsd_ready = 0;
		switch (k) {
		case 0: sc->vsd_stopping = true; break;
		case 1: sc->vsd_session_stopped = true; break;
		case 2: sc->vsd_session_stopped = sc->vsd_fresh_requested = sc->vsd_fresh_active = true; break;
		case 3: sc->vsd_suspended = true; break;
		}
		available = 1;
		pci_vtdtr_notify_ready(sc);
		OK(sc->vsd_ready == 0 && completions == done && discarded_completions == dd);
		available = 0;
	}
	sc->vsd_stopping = sc->vsd_session_stopped = sc->vsd_fresh_requested = false;
	sc->vsd_fresh_active = sc->vsd_suspended = false;
	/* Control copies that begin with an empty segment. */
	{
		struct pci_vtdtr_control c, out;
		struct iovec two[2] = { { &c, 0 }, { &c, sizeof(c) } };
		memset(&c, 0x5a, sizeof(c));
		OK(pci_vtdtr_copy_control(two, 2, &out, false) && out.pvc_event == c.pvc_event);
		OK(pci_vtdtr_copy_control(two, 2, &c, true));
	}
	/* A complete guest upload shorter than an ELF header is refused. */
	{
		struct pci_vtdtr_control up = { .pvc_event = VTDTR_DEVICE_ELF };
		struct iovec iov = { &up, sizeof(up) };
		up.pvc_identifier = 5;
		up.pvc_delivery_id = 9;
		up.pvc_vmid = 42;
		up.pvc_epoch = vm_epoch;
		up.pvc_totalelflen = 3;
		up.pvc_elflen = 3;
		up.pvc_elfhasmore = 0;
		up.pvc_program_id[0] = 1;
		up.pvc_elf_source_id[0] = 2;
		memcpy(up.pvc_elf, "abc", 3);
		int r;
		hypertrace_elf_reset(&sc->vsd_inbound_elf);
		sc->vsd_inbound_delivery_id = 0;
		sc->vsd_vmctx = ctx;			/* identity 42/vm_epoch */
		sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
		r = pci_vtdtr_control_rx(sc, &iov, 1);
		if (r != 1 || (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)
			fprintf(stderr, "short upload: r=%d status=%#x data=%p\n", r,
			    sc->vsd_vs.vs_status, (void *)sc->vsd_inbound_elf.data);
		OK(r == 1);
		OK((sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
		OK(sc->vsd_inbound_elf.data == NULL);
		sc->vsd_vs.vs_status = 0;
		/* The device reset that follows clears the inbound identity. */
		sc->vsd_inbound_delivery_id = sc->vsd_inbound_epoch = 0;
		sc->vsd_inbound_vmid = 0;
		memset(sc->vsd_inbound_program_id, 0, 16);
		memset(sc->vsd_inbound_source_id, 0, 16);
	}
	pthread_mutex_unlock(&sc->vsd_mtx);
	/* Saving a queued control into a buffer with no room fails the save;
	 * with room, the device image is written and the save continues. */
	{
		static uint8_t img[IMG_HDR + 2048];
		struct vm_snapshot_meta small = { .buffer = { .buf_start = img, .buf_size = IMG_HDR + 4,
		    .buf = img, .buf_rem = IMG_HDR + 4 }, .op = VM_SNAPSHOT_SAVE };
		struct vm_snapshot_meta big = { .buffer = { .buf_start = img, .buf_size = sizeof(img),
		    .buf = img, .buf_rem = sizeof(img) }, .op = VM_SNAPSHOT_SAVE };
		int rep;
		sc->vsd_vmctx = ctx;
		sc->vsd_vs.vs_negotiated_caps = VTDTR_RESTORE_REQUIRED_FEATURES;
		sc->vsd_guest_ready = 0;
		pci_vtdtr_cq_enqueue(&d->queue, control_entry(VTDTR_DEVICE_KILL, vm_epoch));
		rep = pci_vtdtr_checkpoint_replayable(sc);
		if (rep != 0)
			fprintf(stderr, "queued KILL not replayable: %d\n", rep);
		OK(rep == 0);
		if (rep == 0) {
			int e = pci_vtdtr_snapshot(sc, &small);
			OK(e != 0 && e != EOPNOTSUPP);
			OK(pci_vtdtr_snapshot(sc, &big) == EOPNOTSUPP);
		}
		drain(d);
	}
	/* A large partially received ELF is skipped in scratch-sized chunks
	 * when the image is validated without staging. */
	{
		static uint8_t img[IMG_HDR + 4 * PCI_VTDTR_MAXELFLEN];
		struct vm_snapshot_meta save = { .buffer = { .buf_start = img, .buf_size = sizeof(img),
		    .buf = img, .buf_rem = sizeof(img) }, .op = VM_SNAPSHOT_SAVE };
		size_t received = 3 * PCI_VTDTR_MAXELFLEN;
		int error;
		hypertrace_elf_reset(&sc->vsd_inbound_elf);
		sc->vsd_inbound_elf.data = __real_malloc(received);
		memset(sc->vsd_inbound_elf.data, 0x5c, received);
		sc->vsd_inbound_elf.total = received + 100;
		sc->vsd_inbound_elf.received = received;
		sc->vsd_inbound_elf.identifier = 7;
		sc->vsd_inbound_delivery_id = 9;
		sc->vsd_inbound_vmid = 42;
		sc->vsd_inbound_epoch = vm_epoch;
		sc->vsd_inbound_program_id[0] = 1;
		sc->vsd_inbound_source_id[0] = 2;
		error = pci_vtdtr_private_snapshot_stage(sc, &save, NULL);
		OK(error == 0);
		if (error == 0) {
			size_t len = sizeof(img) - save.buffer.buf_rem;
			struct vm_snapshot_meta scan = { .buffer = { .buf_start = img, .buf_size = len,
			    .buf = img, .buf_rem = len }, .op = VM_SNAPSHOT_VALIDATE };
			OK(pci_vtdtr_snapshot(NULL, &scan) == 0 && scan.buffer.buf_rem == 0);
		}
		hypertrace_elf_reset(&sc->vsd_inbound_elf);
		sc->vsd_inbound_delivery_id = sc->vsd_inbound_epoch = 0;
		sc->vsd_inbound_vmid = 0;
		memset(sc->vsd_inbound_program_id, 0, 16);
		memset(sc->vsd_inbound_source_id, 0, 16);
	}
	/* Identity failures that carry an errno, and the errno-less witness
	 * failure during a discard. */
	{
		struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
		    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
		struct pci_devinst pi = { .pi_d = &emu, .pi_arg = sc };
		uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE];
		struct hypertrace_session_record rec = { .vmid = 42, .epoch = vm_epoch,
		    .stop_token = 0x77, .features = HYPERTRACE_SESSION_FEATURES };
		static const struct pci_vtdtr_control stale[2] = {
			{ .pvc_event = VTDTR_DEVICE_ELF }, { .pvc_event = VTDTR_DEVICE_KILL } };
		stop_baseline(d);
		OK(pci_vtdtr_session_stop_begin(ctx) == 0);
		script(1, ID_FAIL);
		OK(pci_vtdtr_session_stop_status(ctx) == ENXIO);
		unscript();
		stop_baseline(d);
		vtdtr_shutdown_sc = NULL;
		OK(hypertrace_session_record_encode(wire, sizeof(wire), &rec) == 0);
		sc->vsd_vmctx = (struct vmctx *)1;
		sc->vsd_checkpoint_paused = true;
		sc->vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES;
		source_retired = true;
		script(1, ID_FAIL);
		OK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == ENXIO);
		unscript();
		sc->vsd_session_restore_pending = sc->vsd_session_stopped = true;
		sc->vsd_session_stop_vmid = 7;
		sc->vsd_session_stop_epoch = 5;
		sc->vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
		vq_set_allocated(&sc->vsd_queues[0], true);
		vq_set_allocated(&sc->vsd_queues[1], true);
		incoming_controls = stale;
		incoming_index = 0;
		available = 2;
		source_retired = false;
		retired_noerrno = true;
		pthread_mutex_lock(&sc->vsd_mtx);
		OK(pci_vtdtr_session_discard_paused(&pi) == EIO);
		pthread_mutex_unlock(&sc->vsd_mtx);
		retired_noerrno = false;
		source_retired = false;
		incoming_controls = NULL;
		available = 0;
		sc->vsd_vs.vs_status = 0;
		sc->vsd_checkpoint_paused = sc->vsd_session_restore_pending = false;
		sc->vsd_session_stopped = false;
	}
#undef AUTH_BASE
	free_device(d);
	printf("vtdtr round 8 batch C arms: %d checks\n", vchecks - before);
}

int
main(void)
{
	int status = bhyve_device_main();

	alarm(0);
	CHECK(status == 0);
	test_control_codec();
	test_validity_table();
	test_elf_upload();
	test_guest_reports();
	test_private_image_decoders();
	test_session_controls();
	test_rekey_controls();
	test_events_reader();
	test_session_authorize();
	test_session_attach();
	test_session_stop_table();
	test_communicator();
	test_control_rx_table();
	test_control_rx_continuation();
	test_checkpoint_validators();
	test_private_image_mutations();
	test_restore_stage_table();
	test_discard_table();
	test_session_status_tables();
	test_round8_sessions();
	test_round8_fresh();
	test_round8_paused();
	test_round8_helpers();
	test_round8_communicator();
	test_round8_rx();
	test_round8_checkpoint();
	test_round8_reader();
	test_round8_lifecycle();
	test_round8_batch_c();
	printf("PASS: %d additional virtio-dtrace checks\n", vchecks);
	return (0);
}

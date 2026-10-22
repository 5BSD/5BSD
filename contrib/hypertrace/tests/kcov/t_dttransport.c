/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for sys/dev/dttransport/dttransport.c compiled unmodified as a
 * kernel translation unit.  The module is entered only through its real
 * entry points: SYSINIT/module event handler, the cdevsw it registers, and
 * the exported dtt_* functions.  Oracles are independent: an explicit FIFO
 * model of the queue, exact byte comparison of copied entries, and the
 * documented errno contract of each operation.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/uio.h>

#include <dev/dttransport/dttransport.h>

#include "khx_kern.h"

static struct cdev *dev;
static struct thread *owner, *other;

/* ---- transport callback recorder -------------------------------------- */
static int send_calls, identity_calls, commit_calls, cleanup_calls;
static int send_error, identity_error, commit_error, cleanup_error;
static dtt_entry_t last_sent;
static struct dtt_vm_identity identity_reply, last_commit;
static struct dtt_cleanup_state cleanup_reply;
static int identity_saw_zero, cleanup_saw_zero;
static char cookie_a, cookie_b;

static int
rec_send(void *arg, dtt_entry_t *e)
{
	KHX_CHECK(arg == &cookie_a);
	send_calls++;
	last_sent = *e;
	return (send_error);
}

static int
rec_identity(void *arg, struct dtt_vm_identity *id)
{
	static const struct dtt_vm_identity zero;

	KHX_CHECK(arg == &cookie_a);
	identity_calls++;
	identity_saw_zero = memcmp(id, &zero, sizeof(zero)) == 0;
	*id = identity_reply;
	return (identity_error);
}

static int
rec_commit(void *arg, const struct dtt_vm_identity *id)
{
	KHX_CHECK(arg == &cookie_a);
	commit_calls++;
	last_commit = *id;
	return (commit_error);
}

static int
rec_cleanup(void *arg, struct dtt_cleanup_state *st)
{
	static const struct dtt_cleanup_state zero;

	KHX_CHECK(arg == &cookie_a);
	cleanup_calls++;
	cleanup_saw_zero = memcmp(st, &zero, sizeof(zero)) == 0;
	*st = cleanup_reply;
	return (cleanup_error);
}

/* ---- helpers ------------------------------------------------------------ */
static dtt_entry_t
mk(uint8_t kind, uint32_t ident)
{
	dtt_entry_t e;

	memset(&e, 0, sizeof(e));
	e.event_kind = kind;
	e.u.elf.identifier = ident;
	e.u.elf.len = ident % 97;
	e.u.elf.data[0] = (unsigned char)ident;
	e.u.elf.data[DTT_MAXDATALEN - 1] = (unsigned char)(ident >> 8);
	return (e);
}

static dtt_entry_t
mk_stop(uint64_t delivery, uint16_t vmid, uint64_t epoch)
{
	dtt_entry_t e;

	memset(&e, 0, sizeof(e));
	e.event_kind = DTT_SESSION_STOP;
	e.u.cleanup.delivery_id = delivery;
	e.u.cleanup.vmid = vmid;
	e.u.cleanup.epoch = epoch;
	return (e);
}

static int
do_read(struct thread *td, dtt_entry_t *out, size_t len, int flags)
{
	struct uio uio;
	struct iovec iov;

	khx_uio_init(&uio, &iov, out, len, UIO_READ, UIO_USERSPACE, td);
	return (khx_dev_read(dev, &uio, flags));
}

static int
do_write(struct thread *td, dtt_entry_t *in, size_t len)
{
	struct uio uio;
	struct iovec iov;

	khx_uio_init(&uio, &iov, in, len, UIO_WRITE, UIO_USERSPACE, td);
	return (khx_dev_write(dev, &uio, 0));
}

/* Read until EWOULDBLOCK; returns identifiers in order. */
static int
drain(struct thread *td, uint32_t *ids, int max)
{
	dtt_entry_t e;
	int n = 0, error;

	while ((error = do_read(td, &e, sizeof(e), O_NONBLOCK)) == 0) {
		if (n < max)
			ids[n] = e.event_kind == DTT_SESSION_STOP ?
			    0xffff0000u | (uint32_t)e.u.cleanup.delivery_id :
			    e.u.elf.identifier;
		n++;
	}
	KHX_EQ(error, EWOULDBLOCK);
	return (n);
}

static void
load(void)
{
	dev = khx_cdev_find("dttransport");
	KHX_CHECK(dev != NULL);
}

/* ---- cases -------------------------------------------------------------- */
static void
case_load_and_node(void)
{
	khx_host_case("load");
	khx_run_sysinits();
	load();
	KHX_EQ(khx_module_loaded("dttransport"), 1);
	KHX_EQ(dev->si_uid, UID_ROOT);
	KHX_EQ(dev->si_gid, GID_OPERATOR);
	KHX_EQ(dev->si_mode, S_IRUSR | S_IWUSR);
	/* Unknown module events are accepted without side effects. */
	KHX_EQ(khx_module_event("dttransport", MOD_SHUTDOWN), 0);
	KHX_CHECK(khx_cdev_find("dttransport") == dev);
}

/* Before any provider registers, transport-backed operations fail ENXIO. */
static void
case_no_transport(void)
{
	struct dtt_vm_identity id = { 0 };
	struct dtt_cleanup_state st;
	dtt_entry_t e = mk(DTT_INSTALLED, 3);

	khx_host_case("no-transport");
	KHX_EQ(khx_dev_open(dev, FREAD | FWRITE, owner), 0);
	KHX_EQ(do_write(owner, &e, sizeof(e)), ENXIO);
	memset(&id, 0x5a, sizeof(id));
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, owner),
	    ENXIO);
	/* The reply is zeroed even when no provider answers. */
	KHX_EQ(id.vmid, 0);
	KHX_EQ(id.epoch, 0);
	memset(&st, 0x5a, sizeof(st));
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_CLEANUP_STATE, (caddr_t)&st, 0,
	    owner), ENXIO);
	KHX_EQ(st.delivery_id, 0);
	id = (struct dtt_vm_identity){ .vmid = 1, .epoch = 1 };
	KHX_EQ(khx_dev_ioctl(dev, DTT_COMMIT_VM_REKEY, (caddr_t)&id, 0, owner),
	    ENXIO);
	KHX_EQ(khx_dev_close(dev, 0, owner), 0);
}

/* INVARIANTS: a uio with the wrong direction or a negative residual is a
 * caller bug and must panic, not be serviced. */
struct bogus_args {
	int write;
	enum uio_rw rw;
	ssize_t resid;
};

static void
bogus_io(void *argp)
{
	struct bogus_args *a = argp;
	dtt_entry_t e;
	struct uio uio;
	struct iovec iov;

	khx_uio_init(&uio, &iov, &e, sizeof(e), a->rw, UIO_SYSSPACE, owner);
	uio.uio_resid = a->resid;
	if (a->write)
		(void)dev->si_devsw->d_write(dev, &uio, 0);
	else
		(void)dev->si_devsw->d_read(dev, &uio, 0);
}

static void
case_invariants(void)
{
	struct bogus_args a;

	khx_host_case("invariants");
	a = (struct bogus_args){ 0, UIO_WRITE, sizeof(dtt_entry_t) };
	KHX_CHECK(KHX_PANICS(bogus_io, &a));
	KHX_CHECK(strstr(khx_host_last_panic(), "bogus write") != NULL);
	KHX_EQ(khx_release_locks_after_panic(curthread), 1);
	a = (struct bogus_args){ 0, UIO_READ, -1 };
	KHX_CHECK(KHX_PANICS(bogus_io, &a));
	KHX_CHECK(strstr(khx_host_last_panic(), "negative resid") != NULL);
	KHX_EQ(khx_release_locks_after_panic(curthread), 1);
	a = (struct bogus_args){ 1, UIO_READ, sizeof(dtt_entry_t) };
	KHX_CHECK(KHX_PANICS(bogus_io, &a));
	KHX_CHECK(strstr(khx_host_last_panic(), "bogus write") != NULL);
	KHX_EQ(khx_release_locks_after_panic(curthread), 1);
	a = (struct bogus_args){ 1, UIO_WRITE, -1 };
	KHX_CHECK(KHX_PANICS(bogus_io, &a));
	KHX_CHECK(strstr(khx_host_last_panic(), "negative resid") != NULL);
	KHX_EQ(khx_release_locks_after_panic(curthread), 1);
	/* The device is fully usable afterwards. */
	KHX_EQ(khx_dev_open(dev, FREAD, owner), 0);
	KHX_EQ(khx_dev_close(dev, 0, owner), 0);
}

static void
case_registration(void)
{
	khx_host_case("registration");
	KHX_EQ(dtt_register_transport(NULL, rec_identity, rec_commit,
	    rec_cleanup, &cookie_a), EINVAL);
	KHX_EQ(dtt_register_transport(rec_send, NULL, rec_commit,
	    rec_cleanup, &cookie_a), EINVAL);
	KHX_EQ(dtt_register_transport(rec_send, rec_identity, NULL,
	    rec_cleanup, &cookie_a), EINVAL);
	KHX_EQ(dtt_register_transport(rec_send, rec_identity, rec_commit,
	    NULL, &cookie_a), EINVAL);
	KHX_EQ(dtt_register_transport(rec_send, rec_identity, rec_commit,
	    rec_cleanup, NULL), EINVAL);
	KHX_EQ(dtt_register_transport(rec_send, rec_identity, rec_commit,
	    rec_cleanup, &cookie_a), 0);
	KHX_EQ(dtt_register_transport(rec_send, rec_identity, rec_commit,
	    rec_cleanup, &cookie_b), EBUSY);
	/* A different owner cannot withdraw the registration. */
	dtt_unregister_transport(&cookie_b);
	KHX_EQ(dtt_register_transport(rec_send, rec_identity, rec_commit,
	    rec_cleanup, &cookie_b), EBUSY);
}

static void
case_open_close(void)
{
	struct pstats *saved;

	khx_host_case("open-close");
	KHX_EQ(khx_dev_open(dev, FREAD | FWRITE, owner), 0);
	KHX_EQ(khx_dev_open(dev, FREAD | FWRITE, other), EBUSY);
	KHX_EQ(khx_dev_open(dev, FREAD | FWRITE, owner), EBUSY);
	KHX_EQ(khx_dev_close(dev, 0, owner), 0);
	/* A process without stats cannot become the owner. */
	saved = other->td_proc->p_stats;
	other->td_proc->p_stats = NULL;
	KHX_EQ(khx_dev_open(dev, FREAD, other), EINVAL);
	other->td_proc->p_stats = saved;
	KHX_EQ(khx_dev_open(dev, FREAD, other), 0);
	KHX_EQ(khx_dev_close(dev, 0, other), 0);
	KHX_EQ(khx_dev_open(dev, FREAD | FWRITE, owner), 0);
}

static void
case_ioctl(void)
{
	struct dtt_vm_identity id;
	struct dtt_cleanup_state st;
	struct proc *p = owner->td_proc;
	pid_t pid;
	time_t sec;
	suseconds_t usec;
	struct pstats *stats;
	char buf[64];

	khx_host_case("ioctl");
	KHX_EQ(khx_dev_ioctl(dev, _IOR('D', 9, int), buf, 0, owner), ENOTTY);
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, other),
	    EBUSY);
	/* Ownership requires the same proc, pid and start time. */
	pid = p->p_pid;
	p->p_pid = pid + 1;
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, owner),
	    EBUSY);
	p->p_pid = pid;
	stats = p->p_stats;
	p->p_stats = NULL;
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, owner),
	    EBUSY);
	p->p_stats = stats;
	sec = stats->p_start.tv_sec;
	stats->p_start.tv_sec = sec + 1;
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, owner),
	    EBUSY);
	stats->p_start.tv_sec = sec;
	usec = stats->p_start.tv_usec;
	stats->p_start.tv_usec = usec + 1;
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, owner),
	    EBUSY);
	stats->p_start.tv_usec = usec;
	{
		struct thread fake = *owner;

		fake.td_proc = NULL;
		KHX_EQ(khx_dev_ioctl(dev, DTT_GET_CLEANUP_STATE, (caddr_t)&st,
		    0, &fake), EBUSY);
	}

	/* Identity: the kernel zeroes the reply before the transport fills it. */
	memset(&id, 0xee, sizeof(id));
	identity_reply = (struct dtt_vm_identity){ .vmid = 7, .old_vmid = 6,
	    .flags = DTT_IDENTITY_REKEY_PENDING, .epoch = 70, .old_epoch = 60 };
	identity_error = 0;
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, owner),
	    0);
	KHX_EQ(identity_calls, 1);
	KHX_CHECK(identity_saw_zero);
	KHX_CHECK(memcmp(&id, &identity_reply, sizeof(id)) == 0);
	identity_error = EAGAIN;
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_VM_IDENTITY, (caddr_t)&id, 0, owner),
	    EAGAIN);

	memset(&st, 0xee, sizeof(st));
	cleanup_reply = (struct dtt_cleanup_state){ .delivery_id = 9,
	    .epoch = 3, .vmid = 2, .flags = DTT_CLEANUP_STATE_PENDING };
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_CLEANUP_STATE, (caddr_t)&st, 0,
	    owner), 0);
	KHX_CHECK(cleanup_saw_zero);
	KHX_CHECK(memcmp(&st, &cleanup_reply, sizeof(st)) == 0);
	cleanup_error = ENXIO;
	KHX_EQ(khx_dev_ioctl(dev, DTT_GET_CLEANUP_STATE, (caddr_t)&st, 0,
	    owner), ENXIO);
	cleanup_error = 0;

	id = (struct dtt_vm_identity){ .vmid = 5, .old_vmid = 4, .epoch = 50,
	    .old_epoch = 40 };
	commit_error = ESTALE;
	KHX_EQ(khx_dev_ioctl(dev, DTT_COMMIT_VM_REKEY, (caddr_t)&id, 0, owner),
	    ESTALE);
	KHX_CHECK(memcmp(&last_commit, &id, sizeof(id)) == 0);
	commit_error = 0;
	KHX_EQ(khx_dev_ioctl(dev, DTT_COMMIT_VM_REKEY, (caddr_t)&id, 0, owner),
	    0);
	KHX_EQ(commit_calls, 2);
}

static void
case_write(void)
{
	dtt_entry_t e = mk(DTT_INSTALLED, 77);

	khx_host_case("write");
	KHX_EQ(do_write(owner, &e, sizeof(e) - 1), EINVAL);
	KHX_EQ(do_write(owner, &e, sizeof(e) + 1), EINVAL);
	KHX_EQ(do_write(other, &e, sizeof(e)), EBUSY);
	khx_host_user_fault_range(&e, 1);
	KHX_EQ(do_write(owner, &e, sizeof(e)), EFAULT);
	khx_host_user_fault_clear();
	KHX_EQ(send_calls, 0);
	send_error = 0;
	KHX_EQ(do_write(owner, &e, sizeof(e)), 0);
	KHX_EQ(send_calls, 1);
	KHX_CHECK(memcmp(&last_sent, &e, sizeof(e)) == 0);
	send_error = ENOBUFS;
	KHX_EQ(do_write(owner, &e, sizeof(e)), ENOBUFS);
	send_error = 0;
}

static void
case_queue_fifo_and_front(void)
{
	dtt_entry_t e, got;
	uint32_t ids[16];
	int n;

	khx_host_case("queue-order");
	KHX_EQ(dtt_queue_enqueue(NULL), ENXIO);
	KHX_EQ(dtt_queue_enqueue_front(NULL), ENXIO);
	for (uint32_t i = 1; i <= 3; i++) {
		e = mk(DTT_ELF, i);
		KHX_EQ(dtt_queue_enqueue(&e), 0);
	}
	e = mk(DTT_VM_REKEY, 10);
	KHX_EQ(dtt_queue_enqueue_front(&e), 0);
	e = mk(DTT_VM_REKEY, 11);
	KHX_EQ(dtt_queue_enqueue_front(&e), 0);
	/* Entries are copied: mutating the caller's buffer has no effect. */
	memset(&e, 0xcc, sizeof(e));
	/* Only full-entry reads are accepted, and only by the owner. */
	KHX_EQ(do_read(owner, &got, sizeof(got) - 1, O_NONBLOCK), EINVAL);
	KHX_EQ(do_read(other, &got, sizeof(got), O_NONBLOCK), EBUSY);
	KHX_EQ(do_read(owner, &got, sizeof(got), 0), 0);
	e = mk(DTT_VM_REKEY, 11);
	KHX_CHECK(memcmp(&got, &e, sizeof(e)) == 0);
	n = drain(owner, ids, 16);
	KHX_EQ(n, 4);
	KHX_EQ(ids[0], 10);
	KHX_EQ(ids[1], 1);
	KHX_EQ(ids[2], 2);
	KHX_EQ(ids[3], 3);
}

static void
case_alloc_failures(void)
{
	dtt_entry_t e = mk(DTT_ELF, 5);
	long live = khx_host_live_allocs();
	uint32_t ids[4];

	khx_host_case("alloc-failure");
	khx_host_fail_alloc(1, "dttransport");
	KHX_EQ(dtt_queue_enqueue(&e), ENOMEM);
	KHX_EQ(khx_host_live_allocs(), live);
	khx_host_fail_alloc(2, "dttransport");
	KHX_EQ(dtt_queue_enqueue(&e), ENOMEM);
	KHX_EQ(khx_host_live_allocs(), live);
	khx_host_fail_alloc(-1, NULL);
	KHX_EQ(drain(owner, ids, 4), 0);
}

static void
case_capacity(void)
{
	dtt_entry_t e;
	uint32_t *ids;
	int n;
	long live = khx_host_live_allocs();

	khx_host_case("capacity");
	for (uint32_t i = 0; i < 4096; i++) {
		e = mk(DTT_ELF, i);
		if (dtt_queue_enqueue(&e) != 0) {
			KHX_CHECK(0);
			break;
		}
	}
	e = mk(DTT_ELF, 9999);
	KHX_EQ(dtt_queue_enqueue(&e), ENOBUFS);
	KHX_EQ(dtt_queue_enqueue_front(&e), ENOBUFS);
	/* The failed attempts must not leak their copies. */
	KHX_EQ(khx_host_live_allocs(), live + 2 * 4096);
	ids = malloc(sizeof(*ids) * 4100, M_TEMP, M_WAITOK);
	n = drain(owner, ids, 4100);
	KHX_EQ(n, 4096);
	for (int i = 0; i < n; i++)
		if (ids[i] != (uint32_t)i) {
			KHX_EQ(ids[i], i);
			break;
		}
	free(ids, M_TEMP);
	KHX_EQ(khx_host_live_allocs(), live);
}

static void
case_session_stop(void)
{
	dtt_entry_t e, bad;
	uint32_t ids[8];

	khx_host_case("session-stop");
	KHX_EQ(dtt_queue_session_stop(NULL), EINVAL);
	bad = mk_stop(1, 2, 3);
	bad.event_kind = DTT_CLEANUP_DTRACED;
	KHX_EQ(dtt_queue_session_stop(&bad), EINVAL);
	bad = mk_stop(1, 0, 3);
	KHX_EQ(dtt_queue_session_stop(&bad), EINVAL);
	bad = mk_stop(1, 2, 0);
	KHX_EQ(dtt_queue_session_stop(&bad), EINVAL);
	bad = mk_stop(0, 2, 3);
	KHX_EQ(dtt_queue_session_stop(&bad), EINVAL);
	/* A full queue is replaced, not refused: old work is discarded. */
	for (uint32_t i = 0; i < 4096; i++) {
		e = mk(DTT_ELF, i);
		(void)dtt_queue_enqueue(&e);
	}
	e = mk_stop(41, 2, 3);
	KHX_EQ(dtt_queue_session_stop(&e), 0);
	e = mk(DTT_ELF, 500);
	KHX_EQ(dtt_queue_enqueue(&e), 0);
	KHX_EQ(drain(owner, ids, 8), 2);
	KHX_EQ(ids[0], 0xffff0000u | 41);
	KHX_EQ(ids[1], 500);
}

/* ---- read blocking interleavings (cooperative scheduler) -------------- */
enum { ACT_ENQUEUE, ACT_EINTR, ACT_CLOSE, ACT_SPURIOUS };
static int sleep_action, sleep_calls;

static int
read_sleep_hook(void *arg __unused, const void *wchan __unused,
    const char *wmesg __unused, int timo, int catch_signals)
{
	dtt_entry_t e;

	sleep_calls++;
	KHX_EQ(timo, 0);
	KHX_CHECK(catch_signals);
	switch (sleep_action) {
	case ACT_ENQUEUE:
		e = mk(DTT_ELF, 321);
		KHX_EQ(dtt_queue_enqueue(&e), 0);
		return (0);
	case ACT_EINTR:
		return (EINTR);
	case ACT_CLOSE:
		KHX_EQ(khx_dev_close(dev, 0, owner), 0);
		return (0);
	case ACT_SPURIOUS:
		if (sleep_calls == 1)
			return (0);	/* spurious wakeup: must sleep again */
		e = mk(DTT_ELF, 654);
		KHX_EQ(dtt_queue_enqueue(&e), 0);
		return (0);
	}
	return (0);
}

static void
case_blocking_read(void)
{
	dtt_entry_t got;

	khx_host_case("blocking-read");
	khx_host_set_sleep_hook(read_sleep_hook, NULL);
	sleep_action = ACT_ENQUEUE;
	sleep_calls = 0;
	KHX_EQ(do_read(owner, &got, sizeof(got), 0), 0);
	KHX_EQ(sleep_calls, 1);
	KHX_EQ(got.u.elf.identifier, 321);

	sleep_action = ACT_SPURIOUS;
	sleep_calls = 0;
	KHX_EQ(do_read(owner, &got, sizeof(got), 0), 0);
	KHX_EQ(sleep_calls, 2);
	KHX_EQ(got.u.elf.identifier, 654);

	sleep_action = ACT_EINTR;
	KHX_EQ(do_read(owner, &got, sizeof(got), 0), EINTR);

	/* Owner closes while a read sleeps: the old generation is refused even
	 * if a new owner opens before the sleeper runs. */
	sleep_action = ACT_CLOSE;
	KHX_EQ(do_read(owner, &got, sizeof(got), 0), EBUSY);
	khx_host_set_sleep_hook(NULL, NULL);
	KHX_EQ(khx_dev_open(dev, FREAD | FWRITE, owner), 0);
}

/* ---- copyout ownership ---------------------------------------------- */
static int uio_action;
static int
copy_hook(void *arg __unused, void *kbuf __unused, int n __unused,
    struct uio *uio)
{
	dtt_entry_t e, got;

	if (uio->uio_rw != UIO_READ)
		return (0);
	switch (uio_action) {
	case 1:
		/* A priority entry may still be inserted ahead of the busy one. */
		e = mk(DTT_VM_REKEY, 900);
		KHX_EQ(dtt_queue_enqueue_front(&e), 0);
		/* A concurrent replacement must not free the busy entry. */
		e = mk_stop(77, 1, 1);
		KHX_EQ(dtt_queue_session_stop(&e), EBUSY);
		/* A second reader waits while the first owns the head. */
		khx_set_uiomove_hook(NULL, NULL);
		KHX_EQ(do_read(owner, &got, sizeof(got), O_NONBLOCK),
		    EWOULDBLOCK);
		khx_set_uiomove_hook(copy_hook, NULL);
		break;
	case 2:
		return (EFAULT);
	}
	return (0);
}

static void
case_copyout(void)
{
	dtt_entry_t e, got;
	uint32_t ids[8];

	khx_host_case("copyout");
	e = mk(DTT_ELF, 800);
	KHX_EQ(dtt_queue_enqueue(&e), 0);
	uio_action = 2;
	khx_set_uiomove_hook(copy_hook, NULL);
	KHX_EQ(do_read(owner, &got, sizeof(got), 0), EFAULT);
	/* A failed copyout leaves the entry queued for the next read. */
	uio_action = 1;
	KHX_EQ(do_read(owner, &got, sizeof(got), 0), 0);
	khx_set_uiomove_hook(NULL, NULL);
	KHX_EQ(got.u.elf.identifier, 800);
	KHX_EQ(drain(owner, ids, 8), 1);
	KHX_EQ(ids[0], 900);
}

/* ---- unload --------------------------------------------------------- */
static void
case_unload(void)
{
	dtt_entry_t e;
	long live;

	khx_host_case("unload");
	KHX_EQ(khx_module_event("dttransport", MOD_QUIESCE), EBUSY);
	KHX_EQ(khx_module_event("dttransport", MOD_UNLOAD), EBUSY);
	KHX_EQ(khx_dev_close(dev, 0, owner), 0);
	/* A registered provider also holds the module. */
	KHX_EQ(khx_module_event("dttransport", MOD_QUIESCE), EBUSY);
	KHX_EQ(khx_module_event("dttransport", MOD_UNLOAD), EBUSY);
	dtt_unregister_transport(&cookie_a);
	KHX_EQ(khx_module_event("dttransport", MOD_QUIESCE), 0);
	/* Unload releases queued entries. */
	for (uint32_t i = 0; i < 5; i++) {
		e = mk(DTT_ELF, i);
		KHX_EQ(dtt_queue_enqueue(&e), 0);
	}
	live = khx_host_live_allocs();
	KHX_EQ(khx_module_event("dttransport", MOD_UNLOAD), 0);
	KHX_CHECK(khx_cdev_find("dttransport") == NULL);
	/* 5 x (qentry + entry) + softc + cdev */
	KHX_EQ(khx_host_live_allocs(), live - 12);
	KHX_EQ(dtt_queue_enqueue(&e), ENXIO);
	KHX_EQ(dtt_queue_enqueue_front(&e), ENXIO);
	e = mk_stop(1, 1, 1);
	KHX_EQ(dtt_queue_session_stop(&e), ENXIO);
	KHX_EQ(khx_module_event("dttransport", MOD_UNLOAD), ENXIO);
	KHX_EQ(khx_module_event("dttransport", MOD_QUIESCE), ENXIO);
	/* No provider may attach once unload began. */
	KHX_EQ(dtt_register_transport(rec_send, rec_identity, rec_commit,
	    rec_cleanup, &cookie_a), ENXIO);
	/* A reload whose node cannot be created leaves nothing behind. */
	live = khx_host_live_allocs();
	khx_fail_make_dev(ENOMEM);
	KHX_EQ(khx_module_event("dttransport", MOD_LOAD), ENOMEM);
	KHX_EQ(khx_host_live_allocs(), live);
	KHX_EQ(dtt_queue_enqueue(&e), ENXIO);
}

/* Re-run MOD_LOAD so the remaining cases have a device.  Module statics
 * persist in the harness (a real kldload starts with fresh module data), so
 * registration remains fenced here; no product claim is made about that. */
static void
case_reload(void)
{
	dtt_entry_t e = mk(DTT_ELF, 1);

	khx_host_case("reload");
	KHX_EQ(khx_module_event("dttransport", MOD_LOAD), 0);
	load();
	KHX_EQ(dtt_queue_enqueue(&e), 0);
}

/* ---- real-thread interleavings ------------------------------------------ */
static volatile int reader_error = -1;
static struct thread *reader_td;

static void
reader_main(void *arg __unused)
{
	dtt_entry_t got;

	khx_pthread_attach(1, reader_td);
	reader_error = do_read(reader_td, &got, sizeof(got), 0);
}

static void
wait_for_sleepers(int n)
{
	for (int i = 0; i < 2000000 && khx_host_sleepers() < n; i++)
		khx_host_yield();
	KHX_EQ(khx_host_sleepers(), n);
}

/* A reader asleep on an empty queue must be released by unload, and the
 * softc must not be freed until that reader leaves the cdev method. */
static void
case_unload_wakes_reader(void)
{
	void *h;

	khx_host_case("unload-wakes-reader");
	/* Fresh module instance: drain the reloaded queue first. */
	reader_td = owner;
	KHX_EQ(khx_dev_open(dev, FREAD, owner), 0);
	{
		uint32_t ids[4];
		KHX_EQ(drain(owner, ids, 4), 1);
	}
	h = khx_host_thread_start(reader_main, NULL);
	wait_for_sleepers(1);
	/* Close changes the generation; the reader must return EBUSY. */
	KHX_EQ(khx_dev_close(dev, 0, owner), 0);
	khx_host_thread_join(h);
	KHX_EQ(reader_error, EBUSY);
}

/* Producer/consumer stress with real threads; every tail entry from each
 * producer must arrive exactly once and in that producer's order. */
#define NPROD 4
#define PER_PROD 3000
static volatile int consumer_done;
static uint32_t seen_next[NPROD];
static int consumed, order_errors, dup_errors;
static struct thread *prod_td[NPROD], *cons_td;

static void
producer_main(void *arg)
{
	int p = (int)(intptr_t)arg;
	dtt_entry_t e;
	int error;

	khx_pthread_attach(2 + (p & 1), prod_td[p]);
	for (uint32_t i = 0; i < PER_PROD; i++) {
		e = mk(DTT_ELF, ((uint32_t)p << 24) | i);
		while ((error = dtt_queue_enqueue(&e)) == ENOBUFS)
			khx_host_yield();
		KHX_EQ(error, 0);
	}
}

static void
consumer_main(void *arg __unused)
{
	dtt_entry_t got;
	int error;

	khx_pthread_attach(1, cons_td);
	while (consumed < NPROD * PER_PROD) {
		error = do_read(cons_td, &got, sizeof(got), O_NONBLOCK);
		if (error == EWOULDBLOCK) {
			khx_host_yield();
			continue;
		}
		if (error != 0) {
			KHX_EQ(error, 0);
			break;
		}
		uint32_t p = got.u.elf.identifier >> 24;
		uint32_t i = got.u.elf.identifier & 0xffffff;
		if (p >= NPROD) {
			dup_errors++;
			continue;
		}
		if (i != seen_next[p])
			order_errors++;
		seen_next[p] = i + 1;
		/* Content must be the producer's exact entry. */
		dtt_entry_t want = mk(DTT_ELF, got.u.elf.identifier);
		if (memcmp(&want, &got, sizeof(got)) != 0)
			dup_errors++;
		consumed++;
	}
	consumer_done = 1;
}

static void
case_stress(void)
{
	void *h[NPROD + 1];

	khx_host_case("stress");
	cons_td = khx_thread_new("consumer", 4242);
	KHX_EQ(khx_dev_open(dev, FREAD, cons_td), 0);
	for (int p = 0; p < NPROD; p++)
		prod_td[p] = khx_thread_new("producer", 0);
	h[NPROD] = khx_host_thread_start(consumer_main, NULL);
	for (int p = 0; p < NPROD; p++)
		h[p] = khx_host_thread_start(producer_main, (void *)(intptr_t)p);
	for (int p = 0; p <= NPROD; p++)
		khx_host_thread_join(h[p]);
	KHX_EQ(consumed, NPROD * PER_PROD);
	KHX_EQ(order_errors, 0);
	KHX_EQ(dup_errors, 0);
	for (int p = 0; p < NPROD; p++)
		KHX_EQ(seen_next[p], PER_PROD);
	KHX_EQ(khx_dev_close(dev, 0, cons_td), 0);
}

/* Unload with an in-flight cdev reader: destroy_dev must wait for it. */
static struct thread *late_td;
static volatile int late_error = -1;
static void
late_reader(void *arg __unused)
{
	dtt_entry_t got;

	khx_pthread_attach(3, late_td);
	late_error = do_read(late_td, &got, sizeof(got), 0);
}

static void *late_handle;
static void *late_asleep, *late_go;
static int hook_open_error = -1, hook_ioctl_error = -1;

/* Threads entering the cdev while unload destroys it find it dying. */
static void
destroy_hook(void *arg __unused, struct cdev *d)
{
	struct dtt_vm_identity id;

	hook_open_error = d->si_devsw->d_open(d, FREAD, S_IFCHR, owner);
	hook_ioctl_error = d->si_devsw->d_ioctl(d, DTT_GET_VM_IDENTITY,
	    (caddr_t)&id, 0, late_td);
	/* Release the sleeping reader only now: unload already set dying. */
	khx_host_sem_post(late_go);
}

/* Holds only the designated reader; other sleeps return immediately. */
static int
late_sleep_hook(void *arg __unused, const void *wchan __unused,
    const char *wmesg __unused, int timo __unused, int catch_signals __unused)
{
	if (curthread == late_td) {
		khx_host_sem_post(late_asleep);
		khx_host_sem_wait(late_go);
	}
	return (0);
}

/* A reader asleep across close and unload reports ENXIO (dying wins over
 * the generation change), and unload's destroy_dev waits for it to leave
 * before the softc is freed. */
static void
case_unload_inflight(void)
{
	khx_host_case("unload-inflight");
	late_td = khx_thread_new("late", 5151);
	late_asleep = khx_host_sem_new(0);
	late_go = khx_host_sem_new(0);
	KHX_EQ(khx_dev_open(dev, FREAD, late_td), 0);
	khx_host_set_sleep_hook(late_sleep_hook, NULL);
	late_handle = khx_host_thread_start(late_reader, NULL);
	khx_host_sem_wait(late_asleep);
	KHX_EQ(khx_dev_close(dev, 0, late_td), 0);
	khx_set_destroy_dev_hook(destroy_hook, NULL);
	KHX_EQ(khx_module_event("dttransport", MOD_UNLOAD), 0);
	khx_set_destroy_dev_hook(NULL, NULL);
	khx_host_thread_join(late_handle);
	khx_host_set_sleep_hook(NULL, NULL);
	KHX_EQ(late_error, ENXIO);
	KHX_EQ(hook_open_error, EBUSY);
	KHX_EQ(hook_ioctl_error, EBUSY);
	KHX_CHECK(khx_cdev_find("dttransport") == NULL);
}

int
khx_test_main(void)
{
	khx_kern_boot();
	owner = khx_thread_new("dtraced", 4100);
	other = khx_thread_new("intruder", 4101);
	case_load_and_node();
	case_no_transport();
	case_invariants();
	case_registration();
	case_open_close();
	case_ioctl();
	case_write();
	case_queue_fifo_and_front();
	case_alloc_failures();
	case_capacity();
	case_session_stop();
	case_blocking_read();
	case_copyout();
	case_unload();
	case_reload();
	case_unload_wakes_reader();
	case_stress();
	case_unload_inflight();
	return (khx_host_finish("dttransport"));
}

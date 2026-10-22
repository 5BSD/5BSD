/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for sys/dev/virtio/dtrace/virtio_dtrace.c compiled unmodified as a
 * kernel translation unit and linked with the real dttransport.c and
 * subr_mbufid.c.  The driver is reached only through its registered entry
 * points: driver methods, virtqueue interrupt handlers, its taskqueue task,
 * its communicator kthread, and the dttransport cdev it serves.
 *
 * Oracles: the host side is a device model that reads and writes the wire
 * structure from virtio_dtrace_wire.h; acceptance is checked through the
 * driver's own failure report ("control receive failed (errno)") and its
 * side effects (entries delivered to the daemon through /dev/dttransport,
 * messages sent to the host, the identity ioctls, mbufid's origin epoch and
 * dtrace_node_id).  Expected outcomes are derived from the wire contract and
 * the fresh-session rules in contrib/hypertrace/README.5BSD, not from the
 * driver's code paths.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbufid.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/hypertrace.h>
#include <sys/dtrace_bsd.h>

#include <dev/dttransport/dttransport.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/dtrace/virtio_dtrace_wire.h>

#include "khx_kern.h"
#include "khx_virtio.h"

#define ALL_FEATURES (VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_CONTINUITY | \
	VTDTR_WIRE_F_SESSION_STOP_V1 | VTDTR_WIRE_F_SESSION_FRESH_V1)

typedef struct vtdtr_wire_control wire_t;

struct env {
	device_t dev;
	struct virtqueue *rxq, *txq;
	struct taskqueue *tq;
	struct khx_kthread *kt;
	struct cdev *dtt;
	int attach_error;
	int stops0;
};

static kobj_class_t drv;
static struct thread *daemon_td;
static int unit;

/* ---- wire helpers -------------------------------------------------------- */
static wire_t
w(uint32_t event)
{
	wire_t c;

	memset(&c, 0, sizeof(c));
	c.event = event;
	return (c);
}

static void
fill_id(uint8_t *id, uint8_t v)
{
	for (int i = 0; i < 16; i++)
		id[i] = (uint8_t)(v + i);
}

static wire_t
w_node(uint16_t id, uint64_t epoch, uint64_t query)
{
	wire_t c = w(VTDTR_WIRE_EVENT_NODE_ID);

	c.uctrl.node_id.id = id;
	c.uctrl.node_id.epoch = epoch;
	c.uctrl.node_id.query_id = query;
	return (c);
}

static wire_t
w_elf(uint16_t vmid, uint64_t epoch, size_t len, size_t total, int more)
{
	wire_t c = w(VTDTR_WIRE_EVENT_ELF);

	c.uctrl.elf.elflen = len;
	c.uctrl.elf.totalelflen = total;
	c.uctrl.elf.identifier = 0x1234;
	c.uctrl.elf.delivery_id = 77;
	c.uctrl.elf.vmid = vmid;
	c.uctrl.elf.epoch = epoch;
	fill_id(c.uctrl.elf.program_id, 1);
	fill_id(c.uctrl.elf.elf_source_id, 2);
	c.uctrl.elf.elfhasmore = more;
	for (size_t i = 0; i < sizeof(c.uctrl.elf.elf); i++)
		c.uctrl.elf.elf[i] = (char)(i * 7 + 3);
	return (c);
}

static wire_t
w_cleanup(uint32_t event, uint16_t vmid, uint64_t epoch, uint64_t delivery)
{
	wire_t c = w(event);

	c.uctrl.cleanup.vmid = vmid;
	c.uctrl.cleanup.epoch = epoch;
	c.uctrl.cleanup.delivery_id = delivery;
	return (c);
}

static wire_t
w_installed(uint32_t event, uint16_t vmid, uint64_t epoch)
{
	wire_t c = w(event);

	c.uctrl.installed.delivery_id = 5;
	c.uctrl.installed.vmid = vmid;
	c.uctrl.installed.epoch = epoch;
	fill_id(c.uctrl.installed.program_id, 3);
	fill_id(c.uctrl.installed.source_id, 4);
	return (c);
}

static wire_t
w_kill(uint32_t event, uint16_t vmid, uint64_t epoch, pid_t pid)
{
	wire_t c = w(event);

	c.uctrl.kill.pid = pid;
	c.uctrl.kill.vmid = vmid;
	c.uctrl.kill.epoch = epoch;
	fill_id(c.uctrl.kill.source_id, 9);
	return (c);
}

static wire_t
w_rekey(uint32_t event, uint16_t oid, uint64_t oep, uint16_t nid, uint64_t nep)
{
	wire_t c = w(event);

	c.uctrl.node_rekey.old_id = oid;
	c.uctrl.node_rekey.old_epoch = oep;
	c.uctrl.node_rekey.new_id = nid;
	c.uctrl.node_rekey.new_epoch = nep;
	return (c);
}

static wire_t
w_prep(uint32_t event, uint64_t token, uint16_t oid, uint64_t oep, uint16_t nid,
    uint64_t nep)
{
	wire_t c = w(event);

	c.uctrl.session_prepare.stop_token = token;
	c.uctrl.session_prepare.old_id = oid;
	c.uctrl.session_prepare.old_epoch = oep;
	c.uctrl.session_prepare.new_id = nid;
	c.uctrl.session_prepare.new_epoch = nep;
	return (c);
}

/* ---- daemon side (/dev/dttransport) ------------------------------------- */
static int
dread(struct env *e, dtt_entry_t *out)
{
	struct uio uio;
	struct iovec iov;

	khx_uio_init(&uio, &iov, out, sizeof(*out), UIO_READ, UIO_SYSSPACE,
	    daemon_td);
	return (khx_dev_read(e->dtt, &uio, O_NONBLOCK));
}

static int
dwrite(struct env *e, dtt_entry_t *in)
{
	struct uio uio;
	struct iovec iov;

	khx_uio_init(&uio, &iov, in, sizeof(*in), UIO_WRITE, UIO_SYSSPACE,
	    daemon_td);
	return (khx_dev_write(e->dtt, &uio, 0));
}

static int
dcount(struct env *e)
{
	dtt_entry_t x;
	int n = 0;

	while (dread(e, &x) == 0)
		n++;
	return (n);
}

static int
identity(struct env *e, struct dtt_vm_identity *id)
{
	return (khx_dev_ioctl(e->dtt, DTT_GET_VM_IDENTITY, (caddr_t)id, 0,
	    daemon_td));
}

static int
cleanup_state(struct env *e, struct dtt_cleanup_state *st)
{
	return (khx_dev_ioctl(e->dtt, DTT_GET_CLEANUP_STATE, (caddr_t)st, 0,
	    daemon_td));
}

static int
commit_rekey(struct env *e, struct dtt_vm_identity *id)
{
	return (khx_dev_ioctl(e->dtt, DTT_COMMIT_VM_REKEY, (caddr_t)id, 0,
	    daemon_td));
}

/* ---- host side ------------------------------------------------------------ */
/* Deliver controls into RX buffers, interrupt, and run the RX task. */
static void
host_send_n(struct env *e, const wire_t *c, int n, uint32_t len)
{
	for (int i = 0; i < n; i++) {
		int r, wr;
		size_t rb, wb;
		void *buf = khx_vq_take(e->rxq, &r, &wr, &rb, &wb);

		KHX_CHECK(buf != NULL);
		if (buf == NULL)
			return;
		KHX_EQ(r, 0);
		KHX_CHECK(wr >= 1);
		KHX_EQ(wb, sizeof(wire_t));
		memcpy(buf, &c[i], sizeof(wire_t));
		khx_vq_complete(e->rxq, buf, len);
	}
	khx_vq_interrupt(e->rxq);
	khx_taskqueue_run(e->tq);
}

static void
host_send(struct env *e, wire_t c)
{
	host_send_n(e, &c, 1, sizeof(wire_t));
}

/* Collect TX messages the driver made available. */
static int
host_recv(struct env *e, wire_t *out, int max)
{
	int n = 0, r, wr;
	size_t rb, wb;
	void *buf;

	while ((buf = khx_vq_take(e->txq, &r, &wr, &rb, &wb)) != NULL) {
		KHX_CHECK(r >= 1);
		KHX_EQ(wr, 0);
		KHX_EQ(rb, sizeof(wire_t));
		if (n < max)
			memcpy(&out[n], buf, sizeof(wire_t));
		n++;
		khx_vq_complete(e->txq, buf, 0);
	}
	return (n);
}

static int
host_recv_events(struct env *e, uint32_t *events, int max)
{
	wire_t m[64];
	int n = host_recv(e, m, 64);

	for (int i = 0; i < n && i < max; i++)
		events[i] = m[i].event;
	return (n);
}

static int
step(struct env *e)
{
	return (khx_kthread_step(e->kt, EWOULDBLOCK));
}

static int
stopped(struct env *e)
{
	return (khx_vdev_stop_count(e->dev) > e->stops0);
}

static int
failed_with(int error)
{
	char needle[64];

	snprintf(needle, sizeof(needle), "control receive failed (%d)", error);
	return (khx_printf_seen(needle));
}

/* ---- lifecycle ------------------------------------------------------------ */
static void
env_create(struct env *e, uint64_t features)
{
	char name[16];

	memset(e, 0, sizeof(*e));
	snprintf(name, sizeof(name), "vtdtr%d", unit++);
	e->dev = khx_vdev_create(name, VIRTIO_ID_DTRACE, features, drv->size);
	e->dtt = khx_cdev_find("dttransport");
	khx_printf_reset();
}

static int
env_attach(struct env *e)
{
	char prefix[32];

	e->attach_error = khx_driver_call(drv, "attach", e->dev);
	e->rxq = khx_vdev_vq(e->dev, 0);
	e->txq = khx_vdev_vq(e->dev, 1);
	snprintf(prefix, sizeof(prefix), "%s-rx", device_get_nameunit(e->dev));
	e->tq = khx_taskqueue_find(prefix);
	e->kt = e->attach_error == 0 ? khx_kthread_last() : NULL;
	e->stops0 = khx_vdev_stop_count(e->dev);
	return (e->attach_error);
}

/* Attach and complete the startup handshake to a known identity. */
static void
env_up(struct env *e, uint64_t features, uint16_t id, uint64_t epoch)
{
	uint32_t ev[8];
	int n;

	env_create(e, features);
	KHX_EQ(env_attach(e), 0);
	KHX_EQ(step(e), KHX_KT_PARKED);
	n = host_recv_events(e, ev, 8);
	KHX_EQ(n, 3);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_READY);
	KHX_EQ(ev[1], VTDTR_WIRE_EVENT_NODE_ID);
	KHX_EQ(ev[2], VTDTR_WIRE_EVENT_EOF);
	if (id != 0) {
		host_send(e, w_node(id, epoch, 0));
		host_send(e, w(VTDTR_WIRE_EVENT_READY));
		/* Reap completed TX buffers and send the post-batch READY. */
		step(e);
		(void)host_recv(e, NULL, 0);
	}
	KHX_EQ(dcount(e), 0);
	e->stops0 = khx_vdev_stop_count(e->dev);
	khx_printf_reset();
}

static void
env_down(struct env *e)
{
	long live_dev;

	if (e->attach_error == 0)
		KHX_EQ(khx_driver_call(drv, "detach", e->dev), 0);
	if (e->kt != NULL)
		KHX_EQ(khx_kthread_state(e->kt), KHX_KT_EXITED);
	(void)dcount(e);
	khx_vdev_destroy(e->dev);
	live_dev = khx_host_live_allocs();
	(void)live_dev;
}

/* Allocations owned by the measured code: malloc(9) types it uses. */
static long
live_tag(void)
{
	return (khx_host_live_tag("devbuf") + khx_host_live_tag("vtdtr") +
	    khx_host_live_tag("temp") + khx_host_live_tag("dttransport"));
}

/* ---- attach / detach -------------------------------------------------- */
static void
case_probe(void)
{
	struct env e;
	device_t other;

	khx_host_case("probe");
	env_create(&e, ALL_FEATURES);
	KHX_EQ(khx_driver_call(drv, "probe", e.dev), BUS_PROBE_DEFAULT);
	KHX_CHECK(strcmp(khx_vdev_desc(e.dev), "VirtIO DTrace driver") == 0);
	other = khx_vdev_create("vtnet9", VIRTIO_ID_NETWORK, 0, 16);
	KHX_EQ(khx_driver_call(drv, "probe", other), ENXIO);
	khx_vdev_destroy(other);
	KHX_EQ(khx_driver_call(drv, "config_change", e.dev), 0);
	khx_vdev_destroy(e.dev);
}

static void
attach_fails(const char *name, uint64_t features, void (*arm)(struct env *),
    int expect, const char *message)
{
	struct env e;
	long live;

	khx_host_case(name);
	live = live_tag();
	env_create(&e, features);
	if (arm != NULL)
		arm(&e);
	KHX_EQ(env_attach(&e), expect);
	if (message != NULL)
		KHX_CHECK(khx_printf_seen(message));
	/* A failed attach detaches itself; nothing remains registered. */
	KHX_CHECK(e.kt == NULL || khx_kthread_state(e.kt) == KHX_KT_EXITED);
	e.attach_error = 1;
	env_down(&e);
	KHX_EQ(live_tag(), live);
}

static void arm_finalize(struct env *e) { khx_vdev_fail(e->dev, KHX_VF_FINALIZE, ENXIO); }
static void arm_allocvq(struct env *e) { khx_vdev_fail(e->dev, KHX_VF_ALLOC_VQS, ENOMEM); }
static void arm_intr(struct env *e) { khx_vdev_fail(e->dev, KHX_VF_SETUP_INTR, EIO); }
static void arm_populate(struct env *e) { khx_vdev_fail_vq_enqueue(e->dev, 0, 1, EIO); }
static void arm_tq(struct env *e __unused) { khx_fail_taskqueue_start(ENOMEM); }
static void arm_kthread(struct env *e __unused) { khx_fail_kthread_add(EAGAIN); }
static void arm_ready_alloc(struct env *e __unused) { khx_host_fail_alloc(1, "devbuf"); }

static void
case_attach_failures(void)
{
	long live = live_tag();
	int kts = khx_kthread_count();

	attach_fails("attach-features", VTDTR_WIRE_F_CONTROL_V1, NULL, ENOTSUP,
	    "host lacks required control wire feature");
	attach_fails("attach-finalize", ALL_FEATURES, arm_finalize, ENXIO,
	    "host lacks required control wire feature");
	attach_fails("attach-allocvq", ALL_FEATURES, arm_allocvq, ENOMEM,
	    "cannot allocate virtqueues");
	attach_fails("attach-populate", ALL_FEATURES, arm_populate, EIO,
	    "cannot populate");
	attach_fails("attach-intr", ALL_FEATURES, arm_intr, EIO,
	    "cannot set up virtio interrupts");
	attach_fails("attach-taskqueue", ALL_FEATURES, arm_tq, ENOMEM, NULL);
	attach_fails("attach-kthread", ALL_FEATURES, arm_kthread, EAGAIN, NULL);
	KHX_EQ(khx_kthread_count(), kts);
	/* READY cannot be queued: no kthread work survives the failure. */
	attach_fails("attach-ready-alloc", ALL_FEATURES, arm_ready_alloc, ENOMEM,
	    NULL);
	khx_host_fail_alloc(-1, NULL);
	KHX_EQ(live_tag(), live);
}

/* A second device may not claim the sole transport or the node identity. */
static void
case_second_attach(void)
{
	struct env a, b;
	struct dtt_vm_identity id;

	khx_host_case("second-attach");
	env_up(&a, ALL_FEATURES, 7, 700);
	env_create(&b, ALL_FEATURES);
	KHX_EQ(env_attach(&b), EBUSY);
	b.attach_error = 1;
	env_down(&b);
	/* The first device still serves identity and the node ID survives. */
	KHX_EQ(identity(&a, &id), 0);
	KHX_EQ(id.vmid, 7);
	KHX_EQ(id.epoch, 700);
	KHX_EQ(dtrace_node_id, 7);
	env_down(&a);
	/* Detach of the owner clears the published node identity. */
	KHX_EQ(dtrace_node_id, 0);
	KHX_EQ(mbufid_origin_epoch(), 0);
}

static void
case_partial_populate(void)
{
	struct env e;

	khx_host_case("partial-populate");
	env_create(&e, ALL_FEATURES);
	khx_vdev_fail_vq_enqueue(e.dev, 0, 3, ENOSPC);
	KHX_EQ(env_attach(&e), 0);
	/* Two buffers were posted before the ring refused the third. */
	KHX_EQ(khx_vq_avail(e.rxq), 2);
	KHX_CHECK(khx_vq_notifies(e.rxq) >= 1);
	env_down(&e);
}

/* Detach must reclaim every control buffer, including TX descriptors the
 * device has not completed. */
static void
case_detach_reclaims_tx(void)
{
	struct env e;
	long live;

	khx_host_case("detach-reclaims-tx");
	live = live_tag();
	env_create(&e, ALL_FEATURES);
	KHX_EQ(env_attach(&e), 0);
	/* kthread_add(9) takes a printf format, not a process name. */
	KHX_CHECK(strcmp(khx_kthread_td(e.kt)->td_name,
	    "vtdtr_communicator") == 0);
	KHX_EQ(step(&e), KHX_KT_PARKED);
	/* READY, NODE_ID query and EOF are now owned by the TX ring. */
	KHX_EQ(khx_vq_avail(e.txq), 3);
	env_down(&e);
	KHX_EQ(live_tag(), live);
}

/* ---- identity ---------------------------------------------------------- */
static void
case_node_id(void)
{
	struct env e;
	struct dtt_vm_identity id;
	struct dtt_cleanup_state st;
	dtt_entry_t x;
	long rv;

	khx_host_case("node-id");
	env_up(&e, ALL_FEATURES, 0, 0);
	/* Before NODE_ID the daemon learns that identity is not yet known. */
	KHX_EQ(identity(&e, &id), EAGAIN);
	KHX_EQ(cleanup_state(&e, &st), EAGAIN);
	host_send(&e, w_node(0, 5, 0));
	KHX_CHECK(failed_with(EINVAL));
	env_down(&e);

	env_up(&e, ALL_FEATURES, 0, 0);
	host_send(&e, w_node(HYPERTRACE_MAX_VMS, 5, 0));
	KHX_CHECK(failed_with(EINVAL));
	env_down(&e);

	env_up(&e, ALL_FEATURES, 0, 0);
	host_send(&e, w_node(3, 0, 0));
	KHX_CHECK(failed_with(EINVAL));
	env_down(&e);

	env_up(&e, ALL_FEATURES, 0, 0);
	rv = khx_rendezvous_count();
	host_send(&e, w_node(3, 30, 99));
	KHX_CHECK(!stopped(&e));
	KHX_EQ(dtrace_node_id, 3);
	KHX_EQ(mbufid_origin_epoch(), 30);
	KHX_CHECK(mbufid_origin_ready());
	KHX_CHECK(khx_rendezvous_count() > rv);
	KHX_CHECK(khx_printf_seen("Set DTrace node ID to 3"));
	KHX_EQ(dread(&e, &x), 0);
	KHX_EQ(x.event_kind, DTT_VM_IDENTITY);
	KHX_EQ(x.u.installed.vmid, 3);
	KHX_EQ(x.u.installed.epoch, 30);
	KHX_EQ(x.u.installed.query_id, 99);
	KHX_EQ(identity(&e, &id), 0);
	KHX_EQ(id.vmid, 3);
	KHX_EQ(id.epoch, 30);
	KHX_EQ(id.flags, 0);
	KHX_EQ(cleanup_state(&e, &st), 0);
	KHX_EQ(st.flags, 0);
	/* A repeat of the same identity is idempotent and answers the query. */
	rv = khx_rendezvous_count();
	host_send(&e, w_node(3, 30, 100));
	KHX_CHECK(!stopped(&e));
	KHX_EQ(khx_rendezvous_count(), rv);
	KHX_EQ(dread(&e, &x), 0);
	KHX_EQ(x.u.installed.query_id, 100);
	/* A different identity for a live driver is stale. */
	host_send(&e, w_node(4, 30, 0));
	KHX_CHECK(failed_with(ESTALE));
	KHX_EQ(dtrace_node_id, 3);
	env_down(&e);

	env_up(&e, ALL_FEATURES, 3, 30);
	host_send(&e, w_node(3, 31, 0));
	KHX_CHECK(failed_with(ESTALE));
	env_down(&e);
}

/* ---- ELF delivery ------------------------------------------------------ */
static void
elf_rejected(const char *name, wire_t c)
{
	struct env e;

	khx_host_case(name);
	env_up(&e, ALL_FEATURES, 5, 50);
	host_send(&e, c);
	KHX_CHECK(failed_with(EINVAL));
	KHX_CHECK(stopped(&e));
	KHX_EQ(dcount(&e), 0);
	env_down(&e);
}

static void
case_elf(void)
{
	struct env e;
	wire_t c;
	dtt_entry_t x;
	uint32_t ev[8];

	c = w_elf(5, 50, 10, 10, 0);
	memset(c.uctrl.elf.program_id, 0, 16);
	elf_rejected("elf-zero-program", c);
	c = w_elf(5, 50, 10, 10, 0);
	memset(c.uctrl.elf.elf_source_id, 0, 16);
	elf_rejected("elf-zero-source", c);
	c = w_elf(5, 50, 10, 10, 0);
	c.uctrl.elf.delivery_id = 0;
	elf_rejected("elf-zero-delivery", c);
	elf_rejected("elf-zero-vmid", w_elf(0, 50, 10, 10, 0));
	elf_rejected("elf-big-vmid", w_elf(HYPERTRACE_MAX_VMS, 50, 10, 10, 0));
	elf_rejected("elf-zero-epoch", w_elf(5, 0, 10, 10, 0));
	elf_rejected("elf-other-vmid", w_elf(6, 50, 10, 10, 0));
	elf_rejected("elf-other-epoch", w_elf(5, 51, 10, 10, 0));
	elf_rejected("elf-len-zero", w_elf(5, 50, 0, 10, 1));
	elf_rejected("elf-len-big", w_elf(5, 50, VTDTR_WIRE_MAXELFLEN + 1,
	    VTDTR_WIRE_MAXELFLEN + 1, 0));
	elf_rejected("elf-total-short", w_elf(5, 50, 10, 9, 0));
	elf_rejected("elf-total-big", w_elf(5, 50, 10, 64U * 1024 * 1024 - 4095,
	    1));
	elf_rejected("elf-more-bad", w_elf(5, 50, 10, 20, 2));
	elf_rejected("elf-more-last", w_elf(5, 50, 10, 10, 1));

	khx_host_case("elf-accept");
	env_up(&e, ALL_FEATURES, 5, 50);
	c = w_elf(5, 50, VTDTR_WIRE_MAXELFLEN, 64U * 1024 * 1024 - 4096, 1);
	host_send(&e, c);
	KHX_CHECK(!stopped(&e));
	KHX_EQ(dread(&e, &x), 0);
	KHX_EQ(x.event_kind, DTT_ELF);
	KHX_EQ(x.u.elf.len, VTDTR_WIRE_MAXELFLEN);
	KHX_EQ(x.u.elf.totallen, 64U * 1024 * 1024 - 4096);
	KHX_EQ(x.u.elf.identifier, 0x1234);
	KHX_EQ(x.u.elf.delivery_id, 77);
	KHX_EQ(x.u.elf.vmid, 5);
	KHX_EQ(x.u.elf.epoch, 50);
	KHX_EQ(x.u.elf.hasmore, 1);
	KHX_CHECK(memcmp(x.u.elf.program_id, c.uctrl.elf.program_id, 16) == 0);
	KHX_CHECK(memcmp(x.u.elf.source_id, c.uctrl.elf.elf_source_id, 16) == 0);
	KHX_CHECK(memcmp(x.u.elf.data, c.uctrl.elf.elf, VTDTR_WIRE_MAXELFLEN) == 0);
	/* The RX buffer was recycled; after the batch the driver re-arms READY
	 * because accepting an ELF clears its ready state. */
	KHX_EQ(khx_vq_avail(e.rxq), khx_vq_size(e.rxq));
	step(&e);
	KHX_EQ(host_recv_events(&e, ev, 8), 2);
	KHX_EQ(ev[0], VTDTR_WIRE_EVENT_READY);
	KHX_EQ(ev[1], VTDTR_WIRE_EVENT_EOF);
	/* Final fragment: len == total, no more. */
	host_send(&e, w_elf(5, 50, 1, 1, 0));
	KHX_EQ(dread(&e, &x), 0);
	KHX_EQ(x.u.elf.len, 1);
	KHX_EQ(x.u.elf.hasmore, 0);
	env_down(&e);
}

/* A short RX descriptor invalidates the stream. */
static void
case_short_rx(void)
{
	struct env e;
	wire_t c = w(VTDTR_WIRE_EVENT_READY);

	khx_host_case("short-rx");
	env_up(&e, ALL_FEATURES, 5, 50);
	host_send_n(&e, &c, 1, sizeof(wire_t) - 1);
	KHX_CHECK(failed_with(EINVAL));
	KHX_CHECK(stopped(&e));
	env_down(&e);

	khx_host_case("unknown-event");
	env_up(&e, ALL_FEATURES, 5, 50);
	host_send(&e, w(0x7f));
	KHX_CHECK(khx_printf_seen("Wrong control event: 7f"));
	KHX_CHECK(failed_with(EINVAL));
	env_down(&e);
}

#include "t_virtio_dtrace_proto.inc"
#include "t_virtio_dtrace_paths.inc"

int
khx_test_main(void)
{
	khx_kern_boot();
	khx_run_sysinits();
	drv = khx_driver_find("vtdtr");
	KHX_CHECK(drv != NULL);
	daemon_td = khx_thread_new("dtraced", 4300);
	KHX_EQ(khx_dev_open(khx_cdev_find("dttransport"), FREAD | FWRITE,
	    daemon_td), 0);
	khx_coop_install();
	case_probe();
	case_attach_failures();
	case_second_attach();
	case_partial_populate();
	case_detach_reclaims_tx();
	case_node_id();
	case_elf();
	case_short_rx();
	case_gates();
	case_kill();
	case_host_installed();
	case_host_status();
	case_cleanup();
	case_session_stop();
	case_prepare();
	case_ready_and_commit();
	case_stop_activation_race();
	case_rekey();
	case_receipts();
	case_daemon_validation();
	case_daemon_translation();
	case_capacity();
	case_rx_task();
	case_detach_race();
	case_lifecycle();
	case_more_paths();
	case_fuzz();
	return (khx_host_finish("virtio_dtrace"));
}

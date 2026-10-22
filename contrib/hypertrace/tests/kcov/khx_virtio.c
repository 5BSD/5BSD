/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Kernel-ABI models of newbus devices, the VirtIO transport and split
 * virtqueues, taskqueue(9) and kthread(9), for running unmodified drivers in
 * the userland harness.  The virtqueue model mirrors sys/dev/virtio/
 * virtqueue.c where drivers can observe it: descriptor accounting (full,
 * empty, free counts), errno results of virtqueue_enqueue, completion order,
 * virtqueue_drain's index cursor, and enable_intr's coalesced-completion
 * report.  Not production code.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sglist.h>
#include <sys/taskqueue.h>
#include <sys/sysctl.h>
#include <sys/sdt.h>
#include <sys/dtrace_bsd.h>
#include <sys/mbufid.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/stdarg.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>

#include "khx_kern.h"
#include "khx_virtio.h"

/* KOBJ method descriptors referenced by DEVMETHOD tables. */
struct kobjop_desc device_probe_desc;
struct kobjop_desc device_attach_desc;
struct kobjop_desc device_detach_desc;
struct kobjop_desc virtio_config_change_desc;

/* ---- newbus device ------------------------------------------------------ */
#define KHX_MAX_VQS 4
struct _device {
	char nameunit[32];
	char desc[96];
	uint16_t devtype;
	uint64_t host_features, negotiated;
	void *softc;
	size_t softc_size;
	int fail[KHX_VF_NFAILS];
	int stops, teardowns, intr_setup;
	struct virtqueue *vqs[KHX_MAX_VQS];
	int nvqs;
	uintptr_t feature_desc;
	int vq_race[KHX_MAX_VQS];
	long vq_fail_nth[KHX_MAX_VQS];
	int vq_fail_error[KHX_MAX_VQS];
};

void
khx_vdev_vq_race(device_t dev, int index, int count)
{
	dev->vq_race[index] = count;
}

void
khx_vdev_fail_vq_enqueue(device_t dev, int index, long nth, int error)
{
	dev->vq_fail_nth[index] = nth;
	dev->vq_fail_error[index] = error;
}

device_t
khx_vdev_create(const char *nameunit, uint16_t devtype, uint64_t features,
    size_t softc_size)
{
	device_t dev;

	dev = khx_host_alloc(sizeof(*dev), 1, 0, "khx-device");
	strlcpy(dev->nameunit, nameunit, sizeof(dev->nameunit));
	dev->devtype = devtype;
	dev->host_features = features;
	dev->softc_size = softc_size;
	dev->softc = khx_host_alloc(softc_size, 1, 0, "khx-softc");
	return (dev);
}

static void khx_vq_destroy(struct virtqueue *vq);

void
khx_vdev_destroy(device_t dev)
{
	for (int i = 0; i < dev->nvqs; i++)
		khx_vq_destroy(dev->vqs[i]);
	khx_host_free(dev->softc, "khx-softc");
	khx_host_free(dev, "khx-device");
}

void *
khx_vdev_softc(device_t dev)
{
	return (dev->softc);
}

uint64_t
khx_vdev_negotiated(device_t dev)
{
	return (dev->negotiated);
}

const char *
khx_vdev_desc(device_t dev)
{
	return (dev->desc);
}

void
khx_vdev_fail(device_t dev, enum khx_vfail what, int error)
{
	dev->fail[what] = error;
}

int
khx_vdev_stop_count(device_t dev)
{
	return (dev->stops);
}

int
khx_vdev_teardown_count(device_t dev)
{
	return (dev->teardowns);
}

int
khx_vdev_intr_setup(device_t dev)
{
	return (dev->intr_setup);
}

struct virtqueue *
khx_vdev_vq(device_t dev, int index)
{
	return (index < dev->nvqs ? dev->vqs[index] : NULL);
}

int
khx_vdev_nvqs(device_t dev)
{
	return (dev->nvqs);
}

void *
device_get_softc(device_t dev)
{
	return (dev->softc);
}

const char *
device_get_nameunit(device_t dev)
{
	return (dev->nameunit);
}

void
device_set_desc(device_t dev, const char *desc)
{
	strlcpy(dev->desc, desc, sizeof(dev->desc));
}

int
device_printf(device_t dev, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	printf("%s: %s", dev->nameunit, buf);
	return (0);
}

/* ---- driver modules ----------------------------------------------------- */
#define KHX_MAX_DRIVERS 8
static kobj_class_t khx_drivers[KHX_MAX_DRIVERS];

int
driver_module_handler(module_t mod, int what, void *arg)
{
	struct driver_module_data *dmd = arg;
	int i;

	if (what == MOD_LOAD) {
		for (i = 0; i < KHX_MAX_DRIVERS; i++)
			if (khx_drivers[i] == NULL ||
			    khx_drivers[i] == dmd->dmd_driver) {
				khx_drivers[i] = dmd->dmd_driver;
				break;
			}
	}
	return (dmd->dmd_chainevh != NULL ?
	    dmd->dmd_chainevh(mod, what, dmd->dmd_chainarg) : 0);
}

kobj_class_t
khx_driver_find(const char *name)
{
	for (int i = 0; i < KHX_MAX_DRIVERS; i++)
		if (khx_drivers[i] != NULL &&
		    strcmp(khx_drivers[i]->name, name) == 0)
			return (khx_drivers[i]);
	return (NULL);
}

int
khx_driver_call(kobj_class_t drv, const char *method, device_t dev)
{
	struct kobjop_desc *want;
	kobj_method_t *m;

	if (strcmp(method, "probe") == 0)
		want = &device_probe_desc;
	else if (strcmp(method, "attach") == 0)
		want = &device_attach_desc;
	else if (strcmp(method, "detach") == 0)
		want = &device_detach_desc;
	else if (strcmp(method, "config_change") == 0)
		want = &virtio_config_change_desc;
	else
		panic("unknown method %s", method);
	for (m = drv->methods; m->desc != NULL; m++)
		if (m->desc == want)
			return (((int (*)(device_t))m->func)(dev));
	return (ENXIO);
}

/* ---- virtio bus interface ----------------------------------------------- */
void
virtio_read_ivar(device_t dev, int ivar, uintptr_t *val)
{
	switch (ivar) {
	case VIRTIO_IVAR_DEVTYPE:
		*val = dev->devtype;
		break;
	case VIRTIO_IVAR_FEATURE_DESC:
		*val = dev->feature_desc;
		break;
	default:
		*val = 0;
	}
}

void
virtio_write_ivar(device_t dev, int ivar, uintptr_t val)
{
	if (ivar == VIRTIO_IVAR_FEATURE_DESC)
		dev->feature_desc = val;
}

uint64_t
virtio_negotiate_features(device_t dev, uint64_t child_features)
{
	dev->negotiated = dev->host_features & child_features;
	return (dev->negotiated);
}

int
virtio_finalize_features(device_t dev)
{
	return (dev->fail[KHX_VF_FINALIZE]);
}

static int khx_vq_size_default = KHX_VQ_DEFAULT_SIZE;

void
khx_vq_default_size(int size)
{
	khx_vq_size_default = size;
}

#define KHX_VQ_MAX 64
struct khx_desc {
	void *cookie;
	int ndescs, readable, writable;
	size_t rbytes, wbytes;
	int state;		/* 0 free head, 1 avail, 2 taken, 3 used */
	uint32_t len;
	long seq;
};
struct virtqueue {
	device_t dev;
	int index;
	int size, free;
	char inuse[KHX_VQ_MAX];
	struct khx_desc d[KHX_VQ_MAX];
	long seq;
	virtqueue_intr_t *intr;
	void *intr_arg;
	long notifies;
	int intr_enabled;
	long fail_nth;
	int fail_error;
	int race;
	char name[VIRTQUEUE_MAX_NAME_SZ];
};

int
virtio_alloc_virtqueues(device_t dev, int nvqs, struct vq_alloc_info *info)
{
	struct virtqueue *vq;
	int i;

	if (dev->fail[KHX_VF_ALLOC_VQS] != 0)
		return (dev->fail[KHX_VF_ALLOC_VQS]);
	if (nvqs > KHX_MAX_VQS || dev->nvqs != 0)
		return (EINVAL);
	for (i = 0; i < nvqs; i++) {
		vq = khx_host_alloc(sizeof(*vq), 1, 0, "khx-vq");
		vq->dev = dev;
		vq->index = i;
		vq->size = vq->free = khx_vq_size_default;
		vq->intr = info[i].vqai_intr;
		vq->intr_arg = info[i].vqai_intr_arg;
		vq->fail_nth = dev->vq_fail_nth[i] > 0 ? dev->vq_fail_nth[i] : -1;
		vq->fail_error = dev->vq_fail_error[i];
		vq->race = dev->vq_race[i];
		strlcpy(vq->name, info[i].vqai_name, sizeof(vq->name));
		*info[i].vqai_vq = vq;
		dev->vqs[i] = vq;
	}
	dev->nvqs = nvqs;
	return (0);
}

static void
khx_vq_destroy(struct virtqueue *vq)
{
	khx_host_free(vq, "khx-vq");
}

int
virtio_setup_intr(device_t dev, enum intr_type type __unused)
{
	if (dev->fail[KHX_VF_SETUP_INTR] != 0)
		return (dev->fail[KHX_VF_SETUP_INTR]);
	dev->intr_setup = 1;
	return (0);
}

void
virtio_teardown_intr(device_t dev)
{
	dev->teardowns++;
	dev->intr_setup = 0;
}

static void (*khx_stop_hook)(void *, device_t);
static void *khx_stop_arg;

void
khx_set_virtio_stop_hook(void (*hook)(void *, device_t), void *arg)
{
	khx_stop_hook = hook;
	khx_stop_arg = arg;
}

void
virtio_stop(device_t dev)
{
	dev->stops++;
	if (khx_stop_hook != NULL)
		khx_stop_hook(khx_stop_arg, dev);
}

/* ---- virtqueue ------------------------------------------------------- */
int
khx_vq_size(struct virtqueue *vq)
{
	return (vq->size);
}

int
khx_vq_free(struct virtqueue *vq)
{
	return (vq->free);
}

static int
khx_vq_count(struct virtqueue *vq, int state)
{
	int i, n = 0;

	for (i = 0; i < vq->size; i++)
		n += vq->d[i].cookie != NULL && vq->d[i].state == state;
	return (n);
}

int
khx_vq_avail(struct virtqueue *vq)
{
	return (khx_vq_count(vq, 1));
}

int
khx_vq_used(struct virtqueue *vq)
{
	return (khx_vq_count(vq, 3));
}

long
khx_vq_notifies(struct virtqueue *vq)
{
	return (vq->notifies);
}

int
khx_vq_intr_enabled(struct virtqueue *vq)
{
	return (vq->intr_enabled);
}

void
khx_vq_interrupt(struct virtqueue *vq)
{
	vq->intr(vq->intr_arg);
}

void
khx_vq_fail_enqueue(struct virtqueue *vq, long nth, int error)
{
	vq->fail_nth = nth;
	vq->fail_error = error;
}

void
khx_vq_enable_intr_race(struct virtqueue *vq, int count)
{
	vq->race = count;
}

int
virtqueue_enqueue(struct virtqueue *vq, void *cookie, struct sglist *sg,
    int readable, int writable)
{
	struct khx_desc *dx;
	int needed, head = -1, i, got;

	if (readable < 0 || writable < 0 || readable > INT_MAX - writable)
		return (EINVAL);
	needed = readable + writable;
	if (cookie == NULL)
		panic("virtqueue_enqueue: enqueuing with no cookie");
	if (needed != sg->sg_nseg)
		panic("virtqueue_enqueue: segment count mismatch %d %d", needed,
		    sg->sg_nseg);
	if (needed < 1)
		return (EINVAL);
	if (vq->fail_nth > 0 && --vq->fail_nth == 0) {
		vq->fail_nth = -1;
		return (vq->fail_error);
	}
	if (vq->free == 0)
		return (ENOSPC);
	if (vq->free < needed)
		return (EMSGSIZE);
	for (i = 0, got = 0; i < vq->size && got < needed; i++) {
		if (!vq->inuse[i]) {
			vq->inuse[i] = 1;
			if (head < 0)
				head = i;
			else
				vq->inuse[i] = 2;	/* chained, not a head */
			got++;
		}
	}
	dx = &vq->d[head];
	if (dx->cookie != NULL)
		panic("cookie already exists for index %d", head);
	memset(dx, 0, sizeof(*dx));
	dx->cookie = cookie;
	dx->ndescs = needed;
	dx->readable = readable;
	dx->writable = writable;
	for (i = 0; i < sg->sg_nseg; i++) {
		if (i < readable)
			dx->rbytes += sg->sg_segs[i].ss_len;
		else
			dx->wbytes += sg->sg_segs[i].ss_len;
	}
	dx->state = 1;
	dx->seq = ++vq->seq;
	vq->free -= needed;
	return (0);
}

static void
khx_vq_free_chain(struct virtqueue *vq, int head)
{
	int need = vq->d[head].ndescs - 1, i;

	vq->inuse[head] = 0;
	for (i = 0; i < vq->size && need > 0; i++) {
		if (vq->inuse[i] == 2) {
			vq->inuse[i] = 0;
			need--;
		}
	}
	vq->free += vq->d[head].ndescs;
	vq->d[head].cookie = NULL;
	vq->d[head].state = 0;
}

void *
khx_vq_take(struct virtqueue *vq, int *readable, int *writable,
    size_t *rbytes, size_t *wbytes)
{
	int i, best = -1;

	for (i = 0; i < vq->size; i++)
		if (vq->d[i].cookie != NULL && vq->d[i].state == 1 &&
		    (best < 0 || vq->d[i].seq < vq->d[best].seq))
			best = i;
	if (best < 0)
		return (NULL);
	vq->d[best].state = 2;
	if (readable)
		*readable = vq->d[best].readable;
	if (writable)
		*writable = vq->d[best].writable;
	if (rbytes)
		*rbytes = vq->d[best].rbytes;
	if (wbytes)
		*wbytes = vq->d[best].wbytes;
	return (vq->d[best].cookie);
}

void
khx_vq_complete(struct virtqueue *vq, void *cookie, uint32_t len)
{
	int i;

	for (i = 0; i < vq->size; i++) {
		if (vq->d[i].cookie == cookie && vq->d[i].state == 2) {
			vq->d[i].state = 3;
			vq->d[i].len = len;
			vq->d[i].seq = ++vq->seq;
			return;
		}
	}
	panic("khx_vq_complete: cookie not taken");
}

void *
virtqueue_dequeue(struct virtqueue *vq, uint32_t *len)
{
	int i, best = -1;
	void *cookie;

	for (i = 0; i < vq->size; i++)
		if (vq->d[i].cookie != NULL && vq->d[i].state == 3 &&
		    (best < 0 || vq->d[i].seq < vq->d[best].seq))
			best = i;
	if (best < 0)
		return (NULL);
	cookie = vq->d[best].cookie;
	if (len != NULL)
		*len = vq->d[best].len;
	khx_vq_free_chain(vq, best);
	return (cookie);
}

void *
virtqueue_drain(struct virtqueue *vq, int *last)
{
	void *cookie = NULL;
	int idx = *last;

	while (idx < vq->size && cookie == NULL) {
		if ((cookie = vq->d[idx].cookie) != NULL)
			khx_vq_free_chain(vq, idx);
		idx++;
	}
	*last = idx;
	return (cookie);
}

bool
virtqueue_empty(struct virtqueue *vq)
{
	return (vq->free == vq->size);
}

bool
virtqueue_full(struct virtqueue *vq)
{
	return (vq->free == 0);
}

void
virtqueue_notify(struct virtqueue *vq)
{
	vq->notifies++;
}

int
virtqueue_enable_intr(struct virtqueue *vq)
{
	vq->intr_enabled = 1;
	if (vq->race > 0) {
		vq->race--;
		return (1);
	}
	return (khx_vq_used(vq) > 0);
}

void
virtqueue_disable_intr(struct virtqueue *vq)
{
	vq->intr_enabled = 0;
}

/* ---- pmap for sglist(9) ------------------------------------------------ */
static int khx_scatter;

void
khx_pmap_scatter(int on)
{
	khx_scatter = on;
}

vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	/* Identity "physical" addresses; scatter mode makes each page
	 * discontiguous so a buffer crossing a page needs two segments. */
	return (khx_scatter ? va + (va >> PAGE_SHIFT) * PAGE_SIZE : va);
}

vm_paddr_t
pmap_extract(pmap_t pmap __unused, vm_offset_t va)
{
	return (pmap_kextract(va));
}

/* ---- taskqueue(9) ------------------------------------------------------ */
struct taskqueue {
	char name[64];
	STAILQ_HEAD(, task) q;
	int threads;
	int live;
	struct taskqueue *next;
};
static struct taskqueue *khx_tqs;
static int khx_tq_fail_create, khx_tq_fail_start;

void
khx_fail_taskqueue_create(int on)
{
	khx_tq_fail_create = on;
}

void
khx_fail_taskqueue_start(int error)
{
	khx_tq_fail_start = error;
}

struct taskqueue *
taskqueue_create(const char *name, int mflags, taskqueue_enqueue_fn enqueue
    __unused, void *context __unused)
{
	struct taskqueue *tq;

	/* M_WAITOK creation cannot fail in the kernel. */
	if (khx_tq_fail_create && (mflags & M_NOWAIT) != 0)
		return (NULL);
	tq = khx_host_alloc(sizeof(*tq), 1, 0, "khx-taskqueue");
	strlcpy(tq->name, name, sizeof(tq->name));
	STAILQ_INIT(&tq->q);
	tq->live = 1;
	tq->next = khx_tqs;
	khx_tqs = tq;
	return (tq);
}

int
taskqueue_start_threads(struct taskqueue **tqp, int count, int pri __unused,
    const char *name __unused, ...)
{
	int error = khx_tq_fail_start;

	khx_tq_fail_start = 0;
	if (error == 0)
		(*tqp)->threads += count;
	return (error);
}

void
taskqueue_thread_enqueue(void *context __unused)
{
}

int
taskqueue_enqueue(struct taskqueue *tq, struct task *task)
{
	if (task->ta_pending == 0)
		STAILQ_INSERT_TAIL(&tq->q, task, ta_link);
	if (task->ta_pending < USHRT_MAX)
		task->ta_pending++;
	return (0);
}

static struct task *volatile khx_task_running;

static void
khx_task_run(struct taskqueue *tq, struct task *task)
{
	int pending = task->ta_pending;

	STAILQ_REMOVE(&tq->q, task, task, ta_link);
	task->ta_pending = 0;
	khx_task_running = task;
	task->ta_func(task->ta_context, pending);
	khx_task_running = NULL;
}

void
taskqueue_drain(struct taskqueue *tq, struct task *task)
{
	/* Drain returns once the task is neither pending nor running: wait
	 * for a run in progress on another thread, then run a pending one. */
	while (khx_task_running == task)
		khx_host_yield();
	if (task->ta_pending != 0)
		khx_task_run(tq, task);
}

void
taskqueue_free(struct taskqueue *tq)
{
	struct taskqueue **pp;

	for (pp = &khx_tqs; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == tq) {
			*pp = tq->next;
			break;
		}
	}
	khx_host_free(tq, "khx-taskqueue");
}

struct taskqueue *
khx_taskqueue_find(const char *prefix)
{
	for (struct taskqueue *tq = khx_tqs; tq != NULL; tq = tq->next)
		if (strncmp(tq->name, prefix, strlen(prefix)) == 0)
			return (tq);
	return (NULL);
}

int
khx_taskqueue_run(struct taskqueue *tq)
{
	int n = 0;

	while (!STAILQ_EMPTY(&tq->q)) {
		khx_task_run(tq, STAILQ_FIRST(&tq->q));
		n++;
	}
	return (n);
}

int
khx_taskqueue_run_one(struct taskqueue *tq)
{
	if (STAILQ_EMPTY(&tq->q))
		return (0);
	khx_task_run(tq, STAILQ_FIRST(&tq->q));
	return (1);
}

int
khx_taskqueue_pending(struct taskqueue *tq)
{
	int n = 0;
	struct task *t;

	STAILQ_FOREACH(t, &tq->q, ta_link)
		n++;
	return (n);
}

int
khx_taskqueue_threads(struct taskqueue *tq)
{
	return (tq->threads);
}

int
khx_taskqueue_live(void)
{
	int n = 0;

	for (struct taskqueue *tq = khx_tqs; tq != NULL; tq = tq->next)
		n++;
	return (n);
}

/* ---- coroutine kthreads ------------------------------------------------ */
struct khx_kthread {
	struct thread *td;
	void (*fn)(void *);
	void *arg;
	volatile int state;
	void *go, *idle;
	void *handle;
	int wake;
	int exited_cleanly;
	long sleeps;
	const void *wchan;
};
#define KHX_MAX_KT 1024
static struct khx_kthread *khx_kts[KHX_MAX_KT];
static int khx_nkt;
static int khx_kt_fail;

void
khx_fail_kthread_add(int error)
{
	khx_kt_fail = error;
}

int
kthread_add(void (*func)(void *), void *arg, struct proc *p __unused,
    struct thread **newtdp, int flags __unused, int pages __unused,
    const char *fmt, ...)
{
	struct khx_kthread *kt;
	char name[MAXCOMLEN + 1];
	va_list ap;
	int error = khx_kt_fail;

	khx_kt_fail = 0;
	if (error != 0)
		return (error);
	if (khx_nkt == KHX_MAX_KT)
		panic("too many kthreads");
	/* kvprintf(9) substitutes this text for a NULL format. */
	if (fmt == NULL)
		strlcpy(name, "(fmt null)\n", sizeof(name));
	else {
		va_start(ap, fmt);
		vsnprintf(name, sizeof(name), fmt, ap);
		va_end(ap);
	}
	kt = khx_host_alloc(sizeof(*kt), 1, 0, "khx-kthread");
	kt->td = khx_thread_new(name, 0);
	kt->fn = func;
	kt->arg = arg;
	kt->go = khx_host_sem_new(0);
	kt->idle = khx_host_sem_new(0);
	khx_kts[khx_nkt++] = kt;
	if (newtdp != NULL)
		*newtdp = kt->td;
	return (0);
}

static struct khx_kthread *
khx_kthread_current(void)
{
	for (int i = 0; i < khx_nkt; i++)
		if (khx_kts[i]->td == curthread)
			return (khx_kts[i]);
	return (NULL);
}

void
kthread_exit(void)
{
	struct khx_kthread *kt = khx_kthread_current();

	if (kt == NULL)
		panic("kthread_exit outside a kthread");
	kt->exited_cleanly = 1;
	khx_host_unwind();
}

static void
khx_kthread_body(void *p)
{
	struct khx_kthread *kt = p;

	kt->fn(kt->arg);
	/* Returning from a kthread function without kthread_exit() is
	 * permitted in FreeBSD (it calls kthread_exit()); record it. */
	kt->exited_cleanly = 1;
}

static void
khx_kthread_main(void *p)
{
	struct khx_kthread *kt = p;

	khx_pthread_attach(1, kt->td);
	if (khx_host_try(khx_kthread_body, kt) && !kt->exited_cleanly) {
		khx_host_log("kthread %s panicked: %s\n", kt->td->td_name,
		    khx_host_last_panic());
		KHX_CHECK(!"kthread panicked");
	}
	KHX_EQ(khx_host_locks_held_by(kt->td), 0);
	kt->state = KHX_KT_EXITED;
	khx_host_sem_post(kt->idle);
}

struct khx_kthread *
khx_kthread_last(void)
{
	return (khx_nkt ? khx_kts[khx_nkt - 1] : NULL);
}

int
khx_kthread_count(void)
{
	return (khx_nkt);
}

int
khx_kthread_state(struct khx_kthread *kt)
{
	return (kt->state);
}

struct thread *
khx_kthread_td(struct khx_kthread *kt)
{
	return (kt->td);
}

long
khx_kthread_sleeps(struct khx_kthread *kt)
{
	return (kt->sleeps);
}

const void *
khx_kthread_wchan(struct khx_kthread *kt)
{
	return (kt->wchan);
}

int
khx_kthread_step(struct khx_kthread *kt, int wake)
{
	if (kt->state == KHX_KT_EXITED)
		return (KHX_KT_EXITED);
	if (kt->state == KHX_KT_NEW) {
		kt->state = KHX_KT_PARKED;	/* running until it parks */
		kt->handle = khx_host_thread_start(khx_kthread_main, kt);
	} else {
		kt->wake = wake;
		khx_host_sem_post(kt->go);
	}
	khx_host_sem_wait(kt->idle);
	if (kt->state == KHX_KT_EXITED && kt->handle != NULL) {
		khx_host_thread_join(kt->handle);
		kt->handle = NULL;
	}
	return (kt->state);
}

static int (*khx_waiter_hook)(void *, const void *);
static void *khx_waiter_arg;

void
khx_coop_set_waiter_hook(int (*hook)(void *, const void *), void *arg)
{
	khx_waiter_hook = hook;
	khx_waiter_arg = arg;
}

static int
khx_coop_hook(void *arg __unused, const void *wchan, const char *wmesg
    __unused, int timo __unused, int catch_signals __unused)
{
	struct khx_kthread *kt = khx_kthread_current();
	int i, stepped = 0;

	if (kt != NULL) {
		kt->wchan = wchan;
		kt->sleeps++;
		kt->state = KHX_KT_PARKED;
		khx_host_sem_post(kt->idle);
		khx_host_sem_wait(kt->go);
		kt->wchan = NULL;
		return (kt->wake);
	}
	if (khx_waiter_hook != NULL && khx_waiter_hook(khx_waiter_arg, wchan))
		return (0);
	/* An ordinary thread is waiting for a kthread: let each run once. */
	for (i = 0; i < khx_nkt; i++) {
		if (khx_kts[i]->state != KHX_KT_EXITED) {
			khx_kthread_step(khx_kts[i], 0);
			stepped++;
		}
	}
	if (stepped == 0)
		panic("harness deadlock: sleeper on %p with no runnable kthread",
		    wchan);
	return (0);
}

void
khx_coop_install(void)
{
	khx_host_set_sleep_hook(khx_coop_hook, NULL);
}

void
khx_coop_uninstall(void)
{
	khx_host_set_sleep_hook(NULL, NULL);
}

/* ---- miscellaneous kernel services used by the guest driver ----------- */

struct mbuf;
mbufid_t *m_mbufid(struct mbuf *m __unused);
mbufid_t *
m_mbufid(struct mbuf *m __unused)
{
	panic("m_mbufid not modelled");
}

static long khx_sdt_count;

void
sdt_probe(uint32_t id __unused, uintptr_t a0 __unused, uintptr_t a1 __unused,
    uintptr_t a2 __unused, uintptr_t a3 __unused, uintptr_t a4 __unused)
{
	khx_sdt_count++;
}

long
khx_sdt_fires(const char *name __unused)
{
	return (khx_sdt_count);
}

/* Provider object for the provenance tracepoint in subr_mbufid.c. */
#include <sys/ddtrace.h>
struct sdt_probe sdt_ddtrace__pkttag_gen;

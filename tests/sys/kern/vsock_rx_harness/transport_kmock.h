/*
 * Additional kernel/virtio shims for compiling virtio_vsock.c in userspace.
 *
 * The queue model keeps descriptor accounting and ownership explicit: an
 * enqueue consumes sg_nseg descriptors, completion returns them, dequeue only
 * exposes completed cookies, and drain returns every outstanding cookie.
 */
#ifndef VSOCK_TRANSPORT_KMOCK_H
#define VSOCK_TRANSPORT_KMOCK_H

#include "kmock.h"
#include <kern/uipc_vsock.h>

#include <stdatomic.h>

#define PAGE_SIZE	4096
#define howmany(x, y)	(((x) + ((y) - 1)) / (y))
#define atomic_load_ptr(p)	atomic_load(p)
#define atomic_store_ptr(p, v)	atomic_store((p), (v))

/* ---- device/bus ---- */
struct fake_device {
	void		*softc;
	uint64_t	 config_cid;
	uint64_t	 offered_features;
	int		 type;
	int		 finalize_error;
	int		 alloc_error;
	int		 setup_intr_error;
	int		 stop_calls;
	int		 printf_calls;
	const char	*desc;
};
typedef struct fake_device *device_t;

static inline void *device_get_softc(device_t d) { return (d->softc); }
static inline const char *device_get_nameunit(device_t d __unused)
{ return ("vtvsock0"); }
static inline void device_set_desc(device_t d, const char *s) { d->desc = s; }
static inline int
device_printf(device_t d, const char *fmt __unused, ...)
{
	d->printf_calls++;
	return (0);
}

#define BUS_PROBE_DEFAULT	0
#define INTR_TYPE_MISC		0x01
#define INTR_MPSAFE		0x02

/* ---- scatter/gather ---- */
struct sglist_seg { uintptr_t ss_paddr; size_t ss_len; };
struct sglist {
	struct sglist_seg *sg_segs;
	int sg_maxseg;
	int sg_nseg;
};

static inline void
sglist_init(struct sglist *sg, int maxseg, struct sglist_seg *segs)
{
	sg->sg_segs = segs;
	sg->sg_maxseg = maxseg;
	sg->sg_nseg = 0;
}

static inline void sglist_reset(struct sglist *sg) { sg->sg_nseg = 0; }

static inline int
sglist_append(struct sglist *sg, const void *buf, size_t len)
{
	uintptr_t start;
	int nseg;

	if (len == 0)
		return (EINVAL);
	start = (uintptr_t)buf;
	nseg = (int)howmany((start & (PAGE_SIZE - 1)) + len, PAGE_SIZE);
	if (nseg > sg->sg_maxseg)
		return (EFBIG);
	for (int i = 0; i < nseg; i++) {
		sg->sg_segs[i].ss_paddr = start;
		sg->sg_segs[i].ss_len = len;
	}
	sg->sg_nseg = nseg;
	return (0);
}

/* ---- deterministic virtqueue model ---- */
#define MOCK_VQ_MAX	1024
struct mock_vq_entry {
	void *cookie;
	uint32_t len;
	int ndesc;
	bool complete;
};
struct virtqueue {
	int size;
	int nfree;
	struct mock_vq_entry entries[MOCK_VQ_MAX];
	int entry_count;
	int notify_count;
	int enable_result;
	int enable_count;
	int disable_count;
	void *enqueue_order[MOCK_VQ_MAX];
	int enqueue_count;
	void (*dequeue_hook)(struct virtqueue *, void *);
	void *dequeue_hook_arg;
};

static inline void
mock_vq_init(struct virtqueue *vq, int size)
{
	memset(vq, 0, sizeof(*vq));
	vq->size = size;
	vq->nfree = size;
}

static inline int virtqueue_size(struct virtqueue *vq) { return (vq->size); }
static inline int virtqueue_nfree(struct virtqueue *vq) { return (vq->nfree); }
static inline bool virtqueue_full(struct virtqueue *vq) { return (vq->nfree == 0); }
static inline bool virtqueue_empty(struct virtqueue *vq)
{ return (vq->entry_count == 0); }
static inline void virtqueue_notify(struct virtqueue *vq) { vq->notify_count++; }
static inline void virtqueue_disable_intr(struct virtqueue *vq)
{ vq->disable_count++; }
static inline int virtqueue_enable_intr(struct virtqueue *vq)
{ vq->enable_count++; return (vq->enable_result); }

static inline int
virtqueue_enqueue(struct virtqueue *vq, void *cookie, struct sglist *sg,
    int readable, int writable)
{
	int needed;

	needed = readable + writable;
	if (cookie == NULL || needed != sg->sg_nseg || needed < 1)
		return (EINVAL);
	if (needed > vq->size)
		return (EMSGSIZE);
	if (vq->nfree == 0)
		return (ENOSPC);
	if (vq->nfree < needed)
		return (EMSGSIZE);
	if (vq->entry_count >= MOCK_VQ_MAX)
		return (ENOSPC);
	vq->entries[vq->entry_count++] = (struct mock_vq_entry) {
		.cookie = cookie, .ndesc = needed
	};
	vq->nfree -= needed;
	if (vq->enqueue_count < MOCK_VQ_MAX)
		vq->enqueue_order[vq->enqueue_count++] = cookie;
	return (0);
}

static inline bool
mock_vq_complete(struct virtqueue *vq, void *cookie, uint32_t len)
{
	for (int i = 0; i < vq->entry_count; i++) {
		if (vq->entries[i].cookie == cookie && !vq->entries[i].complete) {
			vq->entries[i].complete = true;
			vq->entries[i].len = len;
			return (true);
		}
	}
	return (false);
}

static inline void *
virtqueue_dequeue(struct virtqueue *vq, uint32_t *len)
{
	struct mock_vq_entry e;

	if (vq->dequeue_hook != NULL)
		vq->dequeue_hook(vq, vq->dequeue_hook_arg);

	for (int i = 0; i < vq->entry_count; i++) {
		if (!vq->entries[i].complete)
			continue;
		e = vq->entries[i];
		memmove(&vq->entries[i], &vq->entries[i + 1],
		    (size_t)(vq->entry_count - i - 1) * sizeof(vq->entries[0]));
		vq->entry_count--;
		vq->nfree += e.ndesc;
		if (len != NULL)
			*len = e.len;
		return (e.cookie);
	}
	return (NULL);
}

static inline void *
virtqueue_drain(struct virtqueue *vq, int *last __unused)
{
	struct mock_vq_entry e;

	if (vq->entry_count == 0)
		return (NULL);
	e = vq->entries[0];
	memmove(&vq->entries[0], &vq->entries[1],
	    (size_t)(vq->entry_count - 1) * sizeof(vq->entries[0]));
	vq->entry_count--;
	vq->nfree += e.ndesc;
	return (e.cookie);
}

/* ---- virtio bus ---- */
typedef void virtqueue_intr_t(void *);
struct vq_alloc_info {
	virtqueue_intr_t *vqai_intr;
	void *vqai_intr_arg;
	struct virtqueue **vqai_vq;
};
#define VQ_ALLOC_INFO_INIT(i, n, intr, arg, vqp, fmt, ...) do { \
	(i)->vqai_intr = (intr); (i)->vqai_intr_arg = (arg); \
	(i)->vqai_vq = (vqp); \
} while (0)

struct virtio_feature_desc { uint64_t value; const char *desc; };
#define VIRTIO_ID_VSOCK	19
static inline int virtio_get_device_type(device_t d) { return (d->type); }
static inline void virtio_set_feature_desc(device_t d __unused,
    struct virtio_feature_desc *f __unused) {}
static inline uint64_t virtio_negotiate_features(device_t d, uint64_t wanted)
{ return (d->offered_features & wanted); }
static inline int virtio_finalize_features(device_t d)
{ return (d->finalize_error); }
static inline int virtio_alloc_virtqueues(device_t d, int n,
    struct vq_alloc_info *info)
{
	if (d->alloc_error != 0)
		return (d->alloc_error);
	for (int i = 0; i < n; i++) {
		struct virtqueue *vq = calloc(1, sizeof(*vq));
		if (vq == NULL)
			return (ENOMEM);
		mock_vq_init(vq, 256);
		*info[i].vqai_vq = vq;
	}
	return (0);
}
static inline int virtio_setup_intr(device_t d, int flags __unused)
{ return (d->setup_intr_error); }
static inline void virtio_read_device_config(device_t d, int off __unused,
    void *buf, size_t len)
{ memcpy(buf, &d->config_cid, MIN(len, sizeof(d->config_cid))); }
static inline void virtio_stop(device_t d) { d->stop_calls++; }

/* ---- source-only helpers and module declarations ---- */
static inline void
m_copydata(struct mbuf *m, int off, int len, void *dst)
{
	char *out = dst;
	while (m != NULL && off >= m->m_len) { off -= m->m_len; m = m->m_next; }
	while (m != NULL && len > 0) {
		int n = MIN(len, m->m_len - off);
		memcpy(out, m->m_data + off, (size_t)n);
		out += n; len -= n; off = 0; m = m->m_next;
	}
}

typedef int device_method_t;
typedef struct { const char *name; device_method_t *methods; size_t size; } driver_t;
#define DEVMETHOD(a, b)	0
#define DEVMETHOD_END	0
#define VIRTIO_DRIVER_MODULE(...)
#define MODULE_DEPEND(...)
#define VIRTIO_SIMPLE_PNPINFO(...)

#define SDT_PROVIDER_DECLARE(p)

static inline void
soisdisconnecting(struct socket *so)
{
	so->so_state &= ~SS_ISCONNECTED;
	so->so_state |= SS_ISDISCONNECTING;
}

extern void *transport_last_wakeup;
#ifndef VSOCK_REAL_SLEEP
#undef wakeup
#define wakeup(chan)	(transport_last_wakeup = (chan))
#endif

#endif /* VSOCK_TRANSPORT_KMOCK_H */

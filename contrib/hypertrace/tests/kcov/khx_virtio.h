/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Device-side model of a VirtIO transport for running unmodified VirtIO
 * drivers.  Not production code.
 */
#ifndef KHX_VIRTIO_H
#define KHX_VIRTIO_H

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/taskqueue.h>

struct virtqueue;
struct khx_kthread;

/* ---- device ------------------------------------------------------------ */
device_t khx_vdev_create(const char *nameunit, uint16_t devtype,
    uint64_t host_features, size_t softc_size);
void khx_vdev_destroy(device_t dev);
void *khx_vdev_softc(device_t dev);
uint64_t khx_vdev_negotiated(device_t dev);
const char *khx_vdev_desc(device_t dev);
/* Driver method dispatch through the registered driver's method table. */
kobj_class_t khx_driver_find(const char *name);
int khx_driver_call(kobj_class_t drv, const char *method, device_t dev);

enum khx_vfail {
	KHX_VF_FINALIZE,
	KHX_VF_ALLOC_VQS,
	KHX_VF_SETUP_INTR,
	KHX_VF_NFAILS
};
void khx_vdev_fail(device_t dev, enum khx_vfail what, int error);
/* Queue `index` reports `count` coalesced completions at enable once
 * allocated. */
void khx_vdev_vq_race(device_t dev, int index, int count);
/* Fail the nth virtqueue_enqueue on queue `index` once it is allocated. */
void khx_vdev_fail_vq_enqueue(device_t dev, int index, long nth, int error);
int khx_vdev_stop_count(device_t dev);
/* Runs inside virtio_stop() (after the driver set its shutdown state). */
void khx_set_virtio_stop_hook(void (*hook)(void *, device_t), void *arg);
int khx_vdev_teardown_count(device_t dev);
int khx_vdev_intr_setup(device_t dev);
struct virtqueue *khx_vdev_vq(device_t dev, int index);
int khx_vdev_nvqs(device_t dev);

/* ---- virtqueue (device side) ----------------------------------------- */
#define KHX_VQ_DEFAULT_SIZE 8
void khx_vq_default_size(int size);
int khx_vq_size(struct virtqueue *vq);
int khx_vq_free(struct virtqueue *vq);
int khx_vq_avail(struct virtqueue *vq);	/* exposed to device, not taken */
int khx_vq_used(struct virtqueue *vq);	/* completed, not yet dequeued */
/* Device takes the oldest available buffer; returns cookie. */
void *khx_vq_take(struct virtqueue *vq, int *readable, int *writable,
    size_t *readable_bytes, size_t *writable_bytes);
/* Device completes a taken buffer with `len` bytes written. */
void khx_vq_complete(struct virtqueue *vq, void *cookie, uint32_t len);
long khx_vq_notifies(struct virtqueue *vq);
int khx_vq_intr_enabled(struct virtqueue *vq);
/* Invoke the interrupt handler the driver registered for this queue. */
void khx_vq_interrupt(struct virtqueue *vq);
/* Fail the nth subsequent virtqueue_enqueue with error. */
void khx_vq_fail_enqueue(struct virtqueue *vq, long nth, int error);
/* Make the next virtqueue_enable_intr report a coalesced completion. */
void khx_vq_enable_intr_race(struct virtqueue *vq, int count);
/* Force every page to be physically discontiguous in pmap_kextract. */
void khx_pmap_scatter(int on);

/* ---- taskqueues -------------------------------------------------------- */
struct taskqueue *khx_taskqueue_find(const char *prefix);
int khx_taskqueue_run(struct taskqueue *tq);	/* runs all pending */
int khx_taskqueue_run_one(struct taskqueue *tq);	/* one task run */
int khx_taskqueue_pending(struct taskqueue *tq);
int khx_taskqueue_threads(struct taskqueue *tq);
void khx_fail_taskqueue_create(int on);
void khx_fail_taskqueue_start(int error);
int khx_taskqueue_live(void);

/* ---- coroutine kthreads ------------------------------------------------ */
/* kthread_add records the thread; it runs on a dedicated pthread one step
 * at a time.  A step runs until the kthread sleeps or exits. */
#define KHX_KT_NEW 0
#define KHX_KT_PARKED 1
#define KHX_KT_EXITED 2
struct khx_kthread *khx_kthread_last(void);
int khx_kthread_count(void);
void khx_fail_kthread_add(int error);
int khx_kthread_state(struct khx_kthread *kt);
struct thread *khx_kthread_td(struct khx_kthread *kt);
/* Start (first call) or resume the kthread; returns its new state.
 * wake: the value its sleep returns (0 or EWOULDBLOCK). */
int khx_kthread_step(struct khx_kthread *kt, int wake);
long khx_kthread_sleeps(struct khx_kthread *kt);
const void *khx_kthread_wchan(struct khx_kthread *kt);
/* Install the cooperative scheduler as the sleep hook.  Non-kthread
 * sleepers step every parked kthread (bounded) and then return 0. */
void khx_coop_install(void);
void khx_coop_uninstall(void);
/* Optional per-step callback run by non-kthread sleepers before stepping. */
void khx_coop_set_waiter_hook(int (*hook)(void *, const void *), void *arg);

/* ---- provenance hooks -------------------------------------------------- */
long khx_sdt_fires(const char *name);

#endif

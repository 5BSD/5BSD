/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Kernel-ABI harness API.  Included by kernel-mode test translation units
 * (compiled with -D_KERNEL against the source tree headers).  Not production.
 */
#ifndef KHX_KERN_H
#define KHX_KERN_H

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/uio.h>

#include "khx_host.h"

#define KHX_NCPU 4

/* Boot the harness on the calling pthread as CPU 0 with a thread of pid 100. */
void khx_kern_boot(void);
/* Allocate a kernel thread/proc pair. pid==0 shares the boot process. */
struct thread *khx_thread_new(const char *name, pid_t pid);
void khx_thread_free(struct thread *td);
/* Switch the calling pthread's current kernel thread; returns previous. */
struct thread *khx_set_curthread(struct thread *td);
/* Attach a new pthread as CPU cpu running td (call first in that pthread). */
void khx_pthread_attach(int cpu, struct thread *td);
/* Change the current CPU number of the calling pthread. */
void khx_set_curcpu(int cpu);

void khx_run_sysinits(void);
void khx_run_sysuninits(void);
int khx_module_event(const char *name, int what);
int khx_module_loaded(const char *name);

struct cdev *khx_cdev_find(const char *name);
int khx_cdev_count(void);
/* cdevsw entry with devfs thread accounting (destroy_dev waits for it). */
int khx_dev_open(struct cdev *dev, int flags, struct thread *td);
int khx_dev_close(struct cdev *dev, int flags, struct thread *td);
int khx_dev_read(struct cdev *dev, struct uio *uio, int flags);
int khx_dev_write(struct cdev *dev, struct uio *uio, int flags);
int khx_dev_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td);
/* Runs at the start of destroy_dev (simulates threads entering the cdev). */
void khx_set_destroy_dev_hook(void (*hook)(void *, struct cdev *), void *arg);
/* destroy_dev_sched_cb() requests, run on demand (destroy_dev_tq). */
int khx_destroy_dev_sched_pending(void);
void khx_destroy_dev_sched_run(void);
struct vm_object;
int khx_dev_mmap_single(struct cdev *dev, vm_ooffset_t *offset,
    vm_size_t size, struct vm_object **objp, int nprot);
/* Make make_dev_s fail once with this error (0 disables). */
void khx_fail_make_dev(int error);

void khx_uio_init(struct uio *uio, struct iovec *iov, void *buf, size_t len,
    enum uio_rw rw, enum uio_seg seg, struct thread *td);
/* Called by uiomove before copying; may simulate concurrent activity. */
typedef int (*khx_uiomove_hook_t)(void *arg, void *kbuf, int n,
    struct uio *uio);
void khx_set_uiomove_hook(khx_uiomove_hook_t hook, void *arg);

/* sysctl(9): find a static OID and call its handler with kernel buffers. */
struct sysctl_oid;
struct sysctl_oid *khx_sysctl_find(const char *parent, const char *name);
int khx_sysctl_call(struct sysctl_oid *oid, struct thread *td, void *old,
    size_t *oldlen, const void *new, size_t newlen);

/* Called at the start of each copyin (out=0) / copyout (out=1) with the
 * user address; a nonzero return makes that copy fail with EFAULT.  Runs
 * where the copy runs, so it can model activity concurrent with it. */
void khx_set_copy_hook(int (*hook)(void *, int, const void *, size_t),
    void *arg);

/* Kernel printf capture. */
void khx_printf_reset(void);
int khx_printf_seen(const char *needle);
const char *khx_printf_buffer(void);

/* Make the next n arc4random_buf() calls return all-zero bytes. */
void khx_random_zero_next(int n);

/* smp_rendezvous accounting (rendezvous functions run synchronously). */
long khx_rendezvous_count(void);
/* Called at the start of every smp_rendezvous (simulates a concurrent CPU). */
struct mtx;
void khx_set_mtx_hook(void (*hook)(void *, struct mtx *, const char *, int),
    void *arg);
void khx_set_rendezvous_hook(void (*hook)(void *), void *arg);

/* Release locks a panicking (unwound) thread left held; returns count. */
int khx_release_locks_after_panic(struct thread *td);

/* Expected panic: evaluates to 1 when fn(arg) panicked. */
#define KHX_PANICS(fn, arg) khx_host_try((void (*)(void *))(fn), (arg))

#endif

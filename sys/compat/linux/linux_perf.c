/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux perf_event_open(2), software counting subset.
 */
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/user.h>

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif

#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_ioctl.h>
#include <compat/linux/linux_util.h>

#define LINUX_PERF_TYPE_SOFTWARE 1
#define LINUX_PERF_COUNT_SW_TASK_CLOCK 1
#define LINUX_PERF_COUNT_SW_PAGE_FAULTS 2
#define LINUX_PERF_COUNT_SW_CONTEXT_SWITCHES 3
#define LINUX_PERF_COUNT_SW_PAGE_FAULTS_MIN 5
#define LINUX_PERF_COUNT_SW_PAGE_FAULTS_MAJ 6
#define LINUX_PERF_COUNT_SW_DUMMY 9

#define LINUX_PERF_FORMAT_TOTAL_TIME_ENABLED (1ULL << 0)
#define LINUX_PERF_FORMAT_TOTAL_TIME_RUNNING (1ULL << 1)
#define LINUX_PERF_FORMAT_ID (1ULL << 2)
#define LINUX_PERF_FORMAT_GROUP (1ULL << 3)
#define LINUX_PERF_FORMAT_LOST (1ULL << 4)
#define LINUX_PERF_FORMAT_SUPPORTED (LINUX_PERF_FORMAT_TOTAL_TIME_ENABLED | \
    LINUX_PERF_FORMAT_TOTAL_TIME_RUNNING | LINUX_PERF_FORMAT_ID)

#define LINUX_PERF_ATTR_DISABLED (1ULL << 0)
#define LINUX_PERF_ATTR_SIZE_VER0 64
#define LINUX_PERF_ATTR_SIZE_CURRENT 144

#define LINUX_PERF_FLAG_FD_NO_GROUP (1UL << 0)
#define LINUX_PERF_FLAG_FD_OUTPUT (1UL << 1)
#define LINUX_PERF_FLAG_PID_CGROUP (1UL << 2)
#define LINUX_PERF_FLAG_FD_CLOEXEC (1UL << 3)
#define LINUX_PERF_FLAG_FD_OUTPUT_FORWARD (1UL << 4)
#define LINUX_PERF_FLAG_FD_CLOEXEC64 (1UL << 5)
#define LINUX_PERF_FLAG_KNOWN (LINUX_PERF_FLAG_FD_NO_GROUP | \
    LINUX_PERF_FLAG_FD_OUTPUT | LINUX_PERF_FLAG_PID_CGROUP | \
    LINUX_PERF_FLAG_FD_CLOEXEC | LINUX_PERF_FLAG_FD_OUTPUT_FORWARD | \
    LINUX_PERF_FLAG_FD_CLOEXEC64)

#define LINUX_PERF_IOC_ENABLE 0x2400
#define LINUX_PERF_IOC_DISABLE 0x2401
#define LINUX_PERF_IOC_RESET 0x2403
#define LINUX_PERF_IOC_ID 0x80082407U
#define LINUX_PERF_IOC_FLAG_GROUP 1UL

struct linux_perf_attr {
	uint32_t type;
	uint32_t size;
	uint64_t config;
	uint64_t sample_period;
	uint64_t sample_type;
	uint64_t read_format;
	uint64_t bits;
	uint32_t wakeup_events;
	uint32_t bp_type;
	uint64_t config1;
	uint64_t config2;
	uint64_t branch_sample_type;
	uint64_t sample_regs_user;
	uint32_t sample_stack_user;
	int32_t clockid;
	uint64_t sample_regs_intr;
	uint32_t aux_watermark;
	uint16_t sample_max_stack;
	uint16_t reserved2;
	uint32_t aux_sample_size;
	uint32_t aux_action;
	uint64_t sig_data;
	uint64_t config3;
	uint64_t config4;
};
_Static_assert(sizeof(struct linux_perf_attr) == LINUX_PERF_ATTR_SIZE_CURRENT,
    "Linux perf_event_attr size");

struct linux_perf_raw {
	uint64_t task_clock;
	uint64_t faults;
	uint64_t context_switches;
	uint64_t minflt;
	uint64_t majflt;
};

struct linux_perf_event {
	LIST_ENTRY(linux_perf_event) link;
	struct thread *target;
	pid_t pid;
	lwpid_t tid;
	uint64_t cookie;
	uint64_t config;
	uint64_t read_format;
	uint64_t id;
	uint64_t value;
	uint64_t enabled_ns;
	uint64_t start_value;
	uint64_t start_ns;
	bool enabled;
	bool detached;
};

static LIST_HEAD(, linux_perf_event) linux_perf_events =
    LIST_HEAD_INITIALIZER(linux_perf_events);
static struct mtx linux_perf_mtx;
static uint64_t linux_perf_next_id;
static eventhandler_tag linux_perf_detach_tag;

static fo_rdwr_t linux_perf_read;
static fo_rdwr_t linux_perf_write;
static fo_poll_t linux_perf_poll;
static fo_stat_t linux_perf_stat;
static fo_close_t linux_perf_close;
static fo_fill_kinfo_t linux_perf_fill_kinfo;

static const struct fileops linux_perf_ops = {
	.fo_read = linux_perf_read,
	.fo_write = linux_perf_write,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = invfo_ioctl,
	.fo_poll = linux_perf_poll,
	.fo_kqfilter = invfo_kqfilter,
	.fo_stat = linux_perf_stat,
	.fo_close = linux_perf_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = linux_perf_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

static uint64_t
linux_perf_now(void)
{
	struct timespec ts;

	nanouptime(&ts);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

static void
linux_perf_snapshot_current(struct linux_perf_raw *raw)
{
	struct timespec ts;
	struct rusage *ru;

	bzero(raw, sizeof(*raw));
	kern_thread_cputime(NULL, &ts);
	raw->task_clock = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	ru = &curthread->td_ru;
	raw->faults = (uint64_t)ru->ru_minflt + ru->ru_majflt;
	raw->context_switches = (uint64_t)ru->ru_nvcsw + ru->ru_nivcsw;
	raw->minflt = ru->ru_minflt;
	raw->majflt = ru->ru_majflt;
}

static int
linux_perf_snapshot_target(struct linux_perf_event *pe,
    struct linux_perf_raw *raw)
{
	struct linux_emuldata *em;
	struct thread *td;
	struct proc *p;
	struct rusage ru;

	td = tdfind(pe->tid, pe->pid);
	if (td == NULL)
		return (ESRCH);
	p = td->td_proc;
	em = em_find(td);
	if (td != pe->target || em == NULL || em->em_proc_cookie != pe->cookie) {
		PROC_UNLOCK(p);
		return (ESRCH);
	}
	PROC_STATLOCK(p);
	thread_lock(td);
	rufetchtd(td, &ru);
	thread_unlock(td);
	PROC_STATUNLOCK(p);
	PROC_UNLOCK(p);

	raw->task_clock = ((uint64_t)ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) *
	    1000000000ULL + ((uint64_t)ru.ru_utime.tv_usec +
	    ru.ru_stime.tv_usec) * 1000ULL;
	raw->faults = (uint64_t)ru.ru_minflt + ru.ru_majflt;
	raw->context_switches = (uint64_t)ru.ru_nvcsw + ru.ru_nivcsw;
	raw->minflt = ru.ru_minflt;
	raw->majflt = ru.ru_majflt;
	return (0);
}

static uint64_t
linux_perf_raw_value(uint64_t config, const struct linux_perf_raw *raw)
{
	switch (config) {
	case LINUX_PERF_COUNT_SW_TASK_CLOCK:
		return (raw->task_clock);
	case LINUX_PERF_COUNT_SW_PAGE_FAULTS:
		return (raw->faults);
	case LINUX_PERF_COUNT_SW_CONTEXT_SWITCHES:
		return (raw->context_switches);
	case LINUX_PERF_COUNT_SW_PAGE_FAULTS_MIN:
		return (raw->minflt);
	case LINUX_PERF_COUNT_SW_PAGE_FAULTS_MAJ:
		return (raw->majflt);
	case LINUX_PERF_COUNT_SW_DUMMY:
		return (0);
	default:
		panic("bad Linux perf software event");
	}
}

static void
linux_perf_values_locked(struct linux_perf_event *pe,
    const struct linux_perf_raw *raw, uint64_t now, uint64_t *value,
    uint64_t *enabled)
{
	uint64_t current;

	mtx_assert(&linux_perf_mtx, MA_OWNED);
	*value = pe->value;
	*enabled = pe->enabled_ns;
	if (pe->enabled && !pe->detached) {
		current = linux_perf_raw_value(pe->config, raw);
		if (current >= pe->start_value)
			*value += current - pe->start_value;
		if (now >= pe->start_ns)
			*enabled += now - pe->start_ns;
	}
}

static int
linux_perf_read(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct linux_perf_event *pe;
	struct linux_perf_raw raw;
	uint64_t values[4], now, value, enabled;
	size_t n;
	int error;

	pe = fp->f_data;
	n = 1;
	if ((pe->read_format & LINUX_PERF_FORMAT_TOTAL_TIME_ENABLED) != 0)
		n++;
	if ((pe->read_format & LINUX_PERF_FORMAT_TOTAL_TIME_RUNNING) != 0)
		n++;
	if ((pe->read_format & LINUX_PERF_FORMAT_ID) != 0)
		n++;
	if (uio->uio_resid < n * sizeof(uint64_t))
		return (ENOSPC);

	error = linux_perf_snapshot_target(pe, &raw);
	now = linux_perf_now();
	mtx_lock(&linux_perf_mtx);
	if (pe->detached)
		bzero(&raw, sizeof(raw));
	else if (error != 0) {
		mtx_unlock(&linux_perf_mtx);
		return (error);
	}
	linux_perf_values_locked(pe, &raw, now, &value, &enabled);
	n = 0;
	values[n++] = value;
	if ((pe->read_format & LINUX_PERF_FORMAT_TOTAL_TIME_ENABLED) != 0)
		values[n++] = enabled;
	if ((pe->read_format & LINUX_PERF_FORMAT_TOTAL_TIME_RUNNING) != 0)
		values[n++] = enabled;
	if ((pe->read_format & LINUX_PERF_FORMAT_ID) != 0)
		values[n++] = pe->id;
	mtx_unlock(&linux_perf_mtx);
	return (uiomove(values, n * sizeof(uint64_t), uio));
}

static int
linux_perf_write(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	return (EINVAL);
}

static int
linux_perf_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	return (0);
}

static int
linux_perf_stat(struct file *fp, struct stat *sb, struct ucred *active_cred)
{
	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFREG | S_IRUSR;
	sb->st_nlink = 1;
	return (0);
}

static int
linux_perf_close(struct file *fp, struct thread *td)
{
	struct linux_perf_event *pe;

	pe = fp->f_data;
	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	mtx_lock(&linux_perf_mtx);
	LIST_REMOVE(pe, link);
	mtx_unlock(&linux_perf_mtx);
	free(pe, M_LINUX);
	return (0);
}

static int
linux_perf_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{
	kif->kf_type = KF_TYPE_UNKNOWN;
	return (0);
}

bool
linux_perf_inuse(void)
{
	bool inuse;

	mtx_lock(&linux_perf_mtx);
	inuse = !LIST_EMPTY(&linux_perf_events);
	mtx_unlock(&linux_perf_mtx);
	return (inuse);
}

void
linux_perf_thread_detach(struct thread *td)
{
	struct linux_perf_event *pe;
	struct linux_perf_raw raw;
	uint64_t now, value, enabled;

	linux_perf_snapshot_current(&raw);
	now = linux_perf_now();
	mtx_lock(&linux_perf_mtx);
	LIST_FOREACH(pe, &linux_perf_events, link) {
		if (pe->target != td || pe->detached)
			continue;
		linux_perf_values_locked(pe, &raw, now, &value, &enabled);
		pe->value = value;
		pe->enabled_ns = enabled;
		pe->enabled = false;
		pe->detached = true;
		pe->target = NULL;
	}
	mtx_unlock(&linux_perf_mtx);
}

static int
linux_perf_ioctl(struct thread *td, struct linux_ioctl_args *args)
{
	struct linux_perf_event *pe;
	struct linux_perf_raw raw;
	struct file *fp;
	uint64_t now, value, enabled, id;
	int error;

	error = fget(td, args->fd, &cap_ioctl_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_ops != &linux_perf_ops) {
		fdrop(fp, td);
		return (ENOIOCTL);
	}
	pe = fp->f_data;
	if (args->cmd != LINUX_PERF_IOC_ENABLE &&
	    args->cmd != LINUX_PERF_IOC_DISABLE &&
	    args->cmd != LINUX_PERF_IOC_RESET &&
	    args->cmd != LINUX_PERF_IOC_ID) {
		fdrop(fp, td);
		return (EINVAL);
	}
	if (args->cmd != LINUX_PERF_IOC_ID &&
	    ((l_ulong)args->arg & ~LINUX_PERF_IOC_FLAG_GROUP) != 0) {
		fdrop(fp, td);
		return (EINVAL);
	}

	error = linux_perf_snapshot_target(pe, &raw);
	now = linux_perf_now();
	mtx_lock(&linux_perf_mtx);
	if (!pe->detached && error != 0) {
		mtx_unlock(&linux_perf_mtx);
		fdrop(fp, td);
		return (error);
	}
	switch (args->cmd) {
	case LINUX_PERF_IOC_ENABLE:
		if (!pe->enabled && !pe->detached) {
			pe->start_value = linux_perf_raw_value(pe->config, &raw);
			pe->start_ns = now;
			pe->enabled = true;
		}
		break;
	case LINUX_PERF_IOC_DISABLE:
		if (pe->enabled && !pe->detached) {
			linux_perf_values_locked(pe, &raw, now, &value, &enabled);
			pe->value = value;
			pe->enabled_ns = enabled;
			pe->enabled = false;
		}
		break;
	case LINUX_PERF_IOC_RESET:
		pe->value = 0;
		if (pe->enabled && !pe->detached) {
			pe->start_value = linux_perf_raw_value(pe->config, &raw);
			pe->start_ns = now;
		}
		break;
	case LINUX_PERF_IOC_ID:
		id = pe->id;
		mtx_unlock(&linux_perf_mtx);
		error = copyout(&id, (void *)(uintptr_t)args->arg, sizeof(id));
		fdrop(fp, td);
		return (error);
	}
	mtx_unlock(&linux_perf_mtx);
	fdrop(fp, td);
	return (0);
}

LINUX_IOCTL_SET(perf, 0x2400, 0x240b);
static int
perf_linux_ioctl(struct thread *td, struct linux_ioctl_args *args)
{
	return (linux_perf_ioctl(td, args));
}

static int
linux_perf_copy_attr(void *uattr, struct linux_perf_attr *attr)
{
	uint32_t size;
	char tail[64];
	size_t done, n;
	int error;

	error = copyin((char *)uattr + offsetof(struct linux_perf_attr, size),
	    &size, sizeof(size));
	if (error != 0)
		return (error);
	if (size == 0)
		size = LINUX_PERF_ATTR_SIZE_VER0;
	if (size > PAGE_SIZE)
		return (E2BIG);
	if (size < LINUX_PERF_ATTR_SIZE_VER0) {
		uint32_t current = LINUX_PERF_ATTR_SIZE_CURRENT;
		(void)copyout(&current,
		    (char *)uattr + offsetof(struct linux_perf_attr, size),
		    sizeof(current));
		return (E2BIG);
	}
	bzero(attr, sizeof(*attr));
	n = MIN((size_t)size, sizeof(*attr));
	error = copyin(uattr, attr, n);
	if (error != 0)
		return (error);
	for (done = sizeof(*attr); done < size; done += n) {
		n = MIN(sizeof(tail), (size_t)size - done);
		error = copyin((char *)uattr + done, tail, n);
		if (error != 0)
			return (error);
		for (size_t i = 0; i < n; i++)
			if (tail[i] != 0)
				return (E2BIG);
	}
	return (0);
}

int
linux_perf_event_open(struct thread *td, struct linux_perf_event_open_args *args)
{
	struct linux_perf_event *pe;
	struct linux_perf_attr attr;
	struct linux_perf_raw raw;
	struct linux_emuldata *em;
	struct file *fp, *gfp;
	int error, fd, oflags;

	if (((l_ulong)args->flags & ~LINUX_PERF_FLAG_KNOWN) != 0)
		return (EINVAL);
	if (((l_ulong)args->flags & ~LINUX_PERF_FLAG_FD_CLOEXEC) != 0)
		return (EOPNOTSUPP);
	error = linux_perf_copy_attr(args->attr, &attr);
	if (error != 0)
		return (error);
	if (attr.type != LINUX_PERF_TYPE_SOFTWARE)
		return (ENOENT);
	switch (attr.config) {
	case LINUX_PERF_COUNT_SW_TASK_CLOCK:
	case LINUX_PERF_COUNT_SW_PAGE_FAULTS:
	case LINUX_PERF_COUNT_SW_CONTEXT_SWITCHES:
	case LINUX_PERF_COUNT_SW_PAGE_FAULTS_MIN:
	case LINUX_PERF_COUNT_SW_PAGE_FAULTS_MAJ:
	case LINUX_PERF_COUNT_SW_DUMMY:
		break;
	default:
		return (ENOENT);
	}
	if ((attr.read_format & ~LINUX_PERF_FORMAT_SUPPORTED) != 0 ||
	    attr.sample_period != 0 || attr.sample_type != 0 ||
	    (attr.bits & ~LINUX_PERF_ATTR_DISABLED) != 0 ||
	    attr.wakeup_events != 0 || attr.bp_type != 0 || attr.config1 != 0 ||
	    attr.config2 != 0 || attr.branch_sample_type != 0 ||
	    attr.sample_regs_user != 0 || attr.sample_stack_user != 0 ||
	    attr.clockid != 0 || attr.sample_regs_intr != 0 ||
	    attr.aux_watermark != 0 || attr.sample_max_stack != 0 ||
	    attr.reserved2 != 0 || attr.aux_sample_size != 0 ||
	    attr.aux_action != 0 || attr.sig_data != 0 || attr.config3 != 0 ||
	    attr.config4 != 0)
		return (EOPNOTSUPP);
	if (args->group_fd != -1) {
		error = fget(td, args->group_fd, &cap_no_rights, &gfp);
		if (error != 0)
			return (error);
		fdrop(gfp, td);
		return (EOPNOTSUPP);
	}
	em = em_find(td);
	if (args->pid == -1 && args->cpu == -1)
		return (EINVAL);
	if (args->pid != 0 && args->pid != em->em_tid)
		return (EOPNOTSUPP);
	if (args->cpu != -1)
		return (EOPNOTSUPP);

	pe = malloc(sizeof(*pe), M_LINUX, M_WAITOK | M_ZERO);
	pe->target = td;
	pe->pid = td->td_proc->p_pid;
	pe->tid = td->td_tid;
	pe->cookie = em->em_proc_cookie;
	pe->config = attr.config;
	pe->read_format = attr.read_format;
	pe->id = atomic_fetchadd_64(&linux_perf_next_id, 1) + 1;
	pe->enabled = (attr.bits & LINUX_PERF_ATTR_DISABLED) == 0;
	linux_perf_snapshot_current(&raw);
	pe->start_value = linux_perf_raw_value(pe->config, &raw);
	pe->start_ns = linux_perf_now();

	oflags = ((l_ulong)args->flags & LINUX_PERF_FLAG_FD_CLOEXEC) != 0 ?
	    O_CLOEXEC : 0;
	error = falloc(td, &fp, &fd, oflags);
	if (error != 0) {
		free(pe, M_LINUX);
		return (error);
	}
	mtx_lock(&linux_perf_mtx);
	LIST_INSERT_HEAD(&linux_perf_events, pe, link);
	mtx_unlock(&linux_perf_mtx);
	finit(fp, FREAD, DTYPE_LINUXPERF, pe, &linux_perf_ops);
	fdrop(fp, td);
	td->td_retval[0] = fd;
	return (0);
}

static void
linux_perf_detach(void *arg __unused, struct thread *td)
{
	linux_perf_thread_detach(td);
}

static void
linux_perf_init(void *arg __unused)
{
	mtx_init(&linux_perf_mtx, "linux perf", NULL, MTX_DEF);
	linux_perf_detach_tag = EVENTHANDLER_REGISTER(linux_perf_detach_event,
	    linux_perf_detach, NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(linux_perf, SI_SUB_LOCK, SI_ORDER_ANY, linux_perf_init, NULL);

static void
linux_perf_uninit(void *arg __unused)
{
	KASSERT(LIST_EMPTY(&linux_perf_events), ("Linux perf events remain"));
	EVENTHANDLER_DEREGISTER(linux_perf_detach_event, linux_perf_detach_tag);
	mtx_destroy(&linux_perf_mtx);
}
SYSUNINIT(linux_perf, SI_SUB_LOCK, SI_ORDER_ANY, linux_perf_uninit, NULL);

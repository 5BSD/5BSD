/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 1994-1995 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/jail.h>
#include <sys/imgact.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/membarrier.h>
#include <sys/msgbuf.h>
#include <sys/mqueue.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/mman.h>
#include <sys/procctl.h>
#include <sys/sbuf.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/random.h>
#include <sys/resourcevar.h>
#include <sys/rtprio.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/swap_pager.h>

#ifdef COMPAT_LINUX32
#include <compat/freebsd32/freebsd32_misc.h>
#include <compat/freebsd32/freebsd32_util.h>
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif

#include <compat/linux/linux_common.h>
#include <compat/linux/linux_dtrace.h>
#include <compat/linux/linux_file.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_mmap.h>
#include <compat/linux/linux_pidfd.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_time.h>
#include <compat/linux/linux_util.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_persona.h>

int stclohz;				/* Statistics clock frequency */

static unsigned int linux_to_bsd_resource[LINUX_RLIM_NLIMITS] = {
	RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK,
	RLIMIT_CORE, RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE,
	RLIMIT_MEMLOCK, RLIMIT_AS
};

struct l_sysinfo {
	l_long		uptime;		/* Seconds since boot */
	l_ulong		loads[3];	/* 1, 5, and 15 minute load averages */
#define LINUX_SYSINFO_LOADS_SCALE 65536
	l_ulong		totalram;	/* Total usable main memory size */
	l_ulong		freeram;	/* Available memory size */
	l_ulong		sharedram;	/* Amount of shared memory */
	l_ulong		bufferram;	/* Memory used by buffers */
	l_ulong		totalswap;	/* Total swap space size */
	l_ulong		freeswap;	/* swap space still available */
	l_ushort	procs;		/* Number of current processes */
	l_ushort	pads;
	l_ulong		totalhigh;
	l_ulong		freehigh;
	l_uint		mem_unit;
	char		_f[20-2*sizeof(l_long)-sizeof(l_int)];	/* padding */
};

struct l_pselect6arg {
	l_uintptr_t	ss;
	l_size_t	ss_len;
};

static int	linux_utimensat_lts_to_ts(struct l_timespec *,
			struct timespec *);
#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
static int	linux_utimensat_lts64_to_ts(struct l_timespec64 *,
			struct timespec *);
#endif
static int	linux_common_utimensat(struct thread *, int,
			const char *, struct timespec *, int);
static int	linux_common_pselect6(struct thread *, l_int,
			l_fd_set *, l_fd_set *, l_fd_set *,
			struct timespec *, l_uintptr_t *);
static int	linux_common_ppoll(struct thread *, struct pollfd *,
			uint32_t, struct timespec *, l_sigset_t *,
			l_size_t);
static int	linux_pollin(struct thread *, struct pollfd *,
			struct pollfd *, u_int);
static int	linux_pollout(struct thread *, struct pollfd *,
			struct pollfd *, u_int);

int
linux_sysinfo(struct thread *td, struct linux_sysinfo_args *args)
{
	struct l_sysinfo sysinfo;
	int i, j;
	struct timespec ts;

	bzero(&sysinfo, sizeof(sysinfo));
	getnanouptime(&ts);
	if (ts.tv_nsec != 0)
		ts.tv_sec++;
	sysinfo.uptime = ts.tv_sec;

	/* Use the information from the mib to get our load averages */
	for (i = 0; i < 3; i++)
		sysinfo.loads[i] = averunnable.ldavg[i] *
		    LINUX_SYSINFO_LOADS_SCALE / averunnable.fscale;

	sysinfo.totalram = physmem * PAGE_SIZE;
	sysinfo.freeram = (u_long)vm_free_count() * PAGE_SIZE;

	/*
	 * sharedram counts pages allocated to named, swap-backed objects such
	 * as shared memory segments and tmpfs files.  There is no cheap way to
	 * compute this, so just leave the field unpopulated.  Linux itself only
	 * started setting this field in the 3.x timeframe.
	 */
	sysinfo.sharedram = 0;
	sysinfo.bufferram = 0;

	swap_pager_status(&i, &j);
	sysinfo.totalswap = i * PAGE_SIZE;
	sysinfo.freeswap = (i - j) * PAGE_SIZE;

	sysinfo.procs = nprocs;

	/*
	 * Platforms supported by the emulation layer do not have a notion of
	 * high memory.
	 */
	sysinfo.totalhigh = 0;
	sysinfo.freehigh = 0;

	sysinfo.mem_unit = 1;

	return (copyout(&sysinfo, args->info, sizeof(sysinfo)));
}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_alarm(struct thread *td, struct linux_alarm_args *args)
{
	struct itimerval it, old_it;
	u_int secs;
	int error __diagused;

	secs = args->secs;
	/*
	 * Linux alarm() is always successful. Limit secs to INT32_MAX / 2
	 * to match kern_setitimer()'s limit to avoid error from it.
	 *
	 * XXX. Linux limit secs to INT_MAX on 32 and does not limit on 64-bit
	 * platforms.
	 */
	if (secs > INT32_MAX / 2)
		secs = INT32_MAX / 2;

	it.it_value.tv_sec = secs;
	it.it_value.tv_usec = 0;
	timevalclear(&it.it_interval);
	error = kern_setitimer(td, ITIMER_REAL, &it, &old_it);
	KASSERT(error == 0, ("kern_setitimer returns %d", error));

	if ((old_it.it_value.tv_sec == 0 && old_it.it_value.tv_usec > 0) ||
	    old_it.it_value.tv_usec >= 500000)
		old_it.it_value.tv_sec++;
	td->td_retval[0] = old_it.it_value.tv_sec;
	return (0);
}
#endif

int
linux_brk(struct thread *td, struct linux_brk_args *args)
{
	struct vmspace *vm = td->td_proc->p_vmspace;
	uintptr_t new, old;

	old = (uintptr_t)vm->vm_daddr + ctob(vm->vm_dsize);
	new = (uintptr_t)args->dsend;
	if ((caddr_t)new > vm->vm_daddr && !kern_break(td, &new))
		td->td_retval[0] = (register_t)new;
	else
		td->td_retval[0] = (register_t)old;

	return (0);
}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_select(struct thread *td, struct linux_select_args *args)
{
	l_timeval ltv;
	struct timeval tv0, tv1, utv, *tvp;
	int error;

	/*
	 * Store current time for computation of the amount of
	 * time left.
	 */
	if (args->timeout) {
		if ((error = copyin(args->timeout, &ltv, sizeof(ltv))))
			goto select_out;
		utv.tv_sec = ltv.tv_sec;
		utv.tv_usec = ltv.tv_usec;

		if (itimerfix(&utv)) {
			/*
			 * The timeval was invalid.  Convert it to something
			 * valid that will act as it does under Linux.
			 */
			utv.tv_sec += utv.tv_usec / 1000000;
			utv.tv_usec %= 1000000;
			if (utv.tv_usec < 0) {
				utv.tv_sec -= 1;
				utv.tv_usec += 1000000;
			}
			if (utv.tv_sec < 0)
				timevalclear(&utv);
		}
		microtime(&tv0);
		tvp = &utv;
	} else
		tvp = NULL;

	error = kern_select(td, args->nfds, args->readfds, args->writefds,
	    args->exceptfds, tvp, LINUX_NFDBITS);
	if (error)
		goto select_out;

	if (args->timeout) {
		if (td->td_retval[0]) {
			/*
			 * Compute how much time was left of the timeout,
			 * by subtracting the current time and the time
			 * before we started the call, and subtracting
			 * that result from the user-supplied value.
			 */
			microtime(&tv1);
			timevalsub(&tv1, &tv0);
			timevalsub(&utv, &tv1);
			if (utv.tv_sec < 0)
				timevalclear(&utv);
		} else
			timevalclear(&utv);
		ltv.tv_sec = utv.tv_sec;
		ltv.tv_usec = utv.tv_usec;
		if ((error = copyout(&ltv, args->timeout, sizeof(ltv))))
			goto select_out;
	}

select_out:
	return (error);
}
#endif

/*
 * Describe the mapping at [addr, addr + len): it must be a single private
 * anonymous entry (what malloc hands to mremap).  Returns its protection
 * or -1 when it is anything else (file-backed, shared, several entries).
 */
static int
linux_mremap_probe(struct thread *td, uintptr_t addr, size_t len)
{
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t obj;
	int prot;

	map = &td->td_proc->p_vmspace->vm_map;
	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, addr, &entry) ||
	    entry->end < addr + len ||
	    (entry->eflags & (MAP_ENTRY_IS_SUB_MAP | MAP_ENTRY_GUARD)) != 0 ||
	    entry->inheritance == VM_INHERIT_SHARE) {
		vm_map_unlock_read(map);
		return (-1);
	}
	obj = entry->object.vm_object;
	if (obj != NULL && (obj->type != OBJT_SWAP || (obj->flags &
	    OBJ_ANON) == 0)) {
		vm_map_unlock_read(map);
		return (-1);
	}
	prot = 0;
	if ((entry->protection & VM_PROT_READ) != 0)
		prot |= PROT_READ;
	if ((entry->protection & VM_PROT_WRITE) != 0)
		prot |= PROT_WRITE;
	if ((entry->protection & VM_PROT_EXECUTE) != 0)
		prot |= PROT_EXEC;
	vm_map_unlock_read(map);
	return (prot);
}

/*
 * mremap(2) growth and MREMAP_FIXED for private anonymous memory: extend in
 * place when the pages after the mapping are free, otherwise (with
 * MREMAP_MAYMOVE) map a new area, copy the old contents and unmap the old
 * area.  Without page migration this costs a copy; malloc's large-chunk
 * realloc is the caller that matters and it is correct either way.  Other
 * kinds of mapping (file-backed, shared) report ENOMEM, as a Linux kernel
 * that cannot find room would.
 */
static int
linux_mremap_grow(struct thread *td, struct linux_mremap_args *args)
{
	struct mmap_req mr;
	char *buf;
	uintptr_t newaddr;
	size_t done, chunk;
	int error, prot;

	prot = linux_mremap_probe(td, args->addr, args->old_len);
	if (prot < 0) {
		td->td_retval[0] = 0;
		return (ENOMEM);
	}
	if ((args->flags & LINUX_MREMAP_FIXED) == 0 &&
	    args->new_len > args->old_len) {
		/* Try to grow in place. */
		mr = (struct mmap_req) {
			.mr_hint = args->addr + args->old_len,
			.mr_len = args->new_len - args->old_len,
			.mr_prot = prot,
			.mr_flags = MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_EXCL,
			.mr_fd = -1,
		};
		error = kern_mmap(td, &mr);
		if (error == 0) {
			td->td_retval[0] = args->addr;
			return (0);
		}
		if ((args->flags & LINUX_MREMAP_MAYMOVE) == 0) {
			td->td_retval[0] = 0;
			return (ENOMEM);
		}
	}
	/* Move: new area, copy, unmap the old one. */
	mr = (struct mmap_req) {
		.mr_hint = (args->flags & LINUX_MREMAP_FIXED) != 0 ?
		    args->new_addr : 0,
		.mr_len = args->new_len,
		.mr_prot = prot | PROT_WRITE,	/* for the copy */
		.mr_flags = MAP_PRIVATE | MAP_ANON |
		    ((args->flags & LINUX_MREMAP_FIXED) != 0 ? MAP_FIXED : 0),
		.mr_fd = -1,
	};
	error = kern_mmap(td, &mr);
	if (error != 0) {
		td->td_retval[0] = 0;
		return (ENOMEM);
	}
	newaddr = td->td_retval[0];
	buf = malloc(LINUX_MREMAP_CHUNK, M_LINUX, M_WAITOK);
	for (done = 0; done < MIN(args->old_len, args->new_len);
	    done += chunk) {
		chunk = MIN(LINUX_MREMAP_CHUNK,
		    MIN(args->old_len, args->new_len) - done);
		error = copyin((void *)(args->addr + done), buf, chunk);
		if (error == 0)
			error = copyout(buf, (void *)(newaddr + done), chunk);
		if (error != 0)
			break;
	}
	free(buf, M_LINUX);
	if (error != 0) {
		(void)kern_munmap(td, newaddr, args->new_len);
		td->td_retval[0] = 0;
		return (EFAULT);
	}
	if ((prot & PROT_WRITE) == 0)
		(void)kern_mprotect(td, newaddr, args->new_len, prot, 0);
	(void)kern_munmap(td, args->addr, args->old_len);
	td->td_retval[0] = newaddr;
	return (0);
}

int
linux_mseal(struct thread *td, struct linux_mseal_args *args)
{

	return (linux_mseal_common(td, args->addr, args->len, args->flags));
}

int
linux_munmap(struct thread *td, struct linux_munmap_args *args)
{

	return (linux_munmap_common(td, args->addr, args->len));
}

int
linux_mremap(struct thread *td, struct linux_mremap_args *args)
{
	uintptr_t addr;
	size_t len;
	int error = 0;

	if (args->flags & ~(LINUX_MREMAP_FIXED | LINUX_MREMAP_MAYMOVE)) {
		td->td_retval[0] = 0;
		return (EINVAL);
	}

	/*
	 * Check for the page alignment.
	 * Linux defines PAGE_MASK to be FreeBSD ~PAGE_MASK.
	 */
	if (args->addr & PAGE_MASK) {
		td->td_retval[0] = 0;
		return (EINVAL);
	}

	args->new_len = round_page(args->new_len);
	args->old_len = round_page(args->old_len);
	if (linux_range_sealed(td, args->addr, args->old_len) ||
	    ((args->flags & LINUX_MREMAP_FIXED) != 0 &&
	    linux_range_sealed(td, args->new_addr, args->new_len))) {
		td->td_retval[0] = 0;
		return (EPERM);
	}
	if (args->new_len == 0 || args->old_len == 0) {
		/* old_len 0 duplicates a shared mapping on Linux: not here. */
		td->td_retval[0] = 0;
		return (EINVAL);
	}
	if ((args->flags & LINUX_MREMAP_FIXED) != 0) {
		if ((args->flags & LINUX_MREMAP_MAYMOVE) == 0 ||
		    (args->new_addr & PAGE_MASK) != 0 ||
		    (args->new_addr < args->addr + args->old_len &&
		    args->addr < args->new_addr + args->new_len)) {
			td->td_retval[0] = 0;
			return (EINVAL);
		}
	}

	if (args->new_len > args->old_len ||
	    (args->flags & LINUX_MREMAP_FIXED) != 0)
		return (linux_mremap_grow(td, args));

	if (args->new_len < args->old_len) {
		addr = args->addr + args->new_len;
		len = args->old_len - args->new_len;
		error = kern_munmap(td, addr, len);
	}

	td->td_retval[0] = error ? 0 : (uintptr_t)args->addr;
	return (error);
}

#define LINUX_MS_ASYNC       0x0001
#define LINUX_MS_INVALIDATE  0x0002
#define LINUX_MS_SYNC        0x0004

int
linux_msync(struct thread *td, struct linux_msync_args *args)
{
	int flags;

	/* Linux: unknown bits, or MS_SYNC with MS_ASYNC, are EINVAL. */
	if ((args->fl & ~(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE |
	    LINUX_MS_SYNC)) != 0)
		return (EINVAL);
	if ((args->fl & (LINUX_MS_SYNC | LINUX_MS_ASYNC)) ==
	    (LINUX_MS_SYNC | LINUX_MS_ASYNC))
		return (EINVAL);
	if ((args->addr & PAGE_MASK) != 0)
		return (EINVAL);
	flags = 0;
	if ((args->fl & LINUX_MS_ASYNC) != 0)
		flags |= MS_ASYNC;
	if ((args->fl & LINUX_MS_INVALIDATE) != 0)
		flags |= MS_INVALIDATE;
	return (kern_msync(td, args->addr, args->len, flags));
}

int
linux_mprotect(struct thread *td, struct linux_mprotect_args *uap)
{

	return (linux_mprotect_common(td, PTROUT(uap->addr), uap->len,
	    uap->prot));
}

int
linux_madvise(struct thread *td, struct linux_madvise_args *uap)
{

	return (linux_madvise_common(td, PTROUT(uap->addr), uap->len,
	    uap->behav));
}

int
linux_mlock2(struct thread *td, struct linux_mlock2_args *args)
{

	if ((args->flags & ~LINUX_MLOCK_ONFAULT) != 0)
		return (EINVAL);
	/*
	 * MLOCK_ONFAULT asks to lock pages only once they are faulted in;
	 * eagerly wiring the whole range is a strict superset of that
	 * guarantee, so the flag is honoured by plain kern_mlock().
	 */
	return (kern_mlock(td->td_proc, td->td_ucred, args->start,
	    args->len));
}

int
linux_mmap2(struct thread *td, struct linux_mmap2_args *uap)
{
#if defined(LINUX_ARCHWANT_MMAP2PGOFF)
	/*
	 * For architectures with sizeof (off_t) < sizeof (loff_t) mmap is
	 * implemented with mmap2 syscall and the offset is represented in
	 * multiples of page size.
	 */
	return (linux_mmap_common(td, PTROUT(uap->addr), uap->len, uap->prot,
	    uap->flags, uap->fd, (uint64_t)(uint32_t)uap->pgoff * PAGE_SIZE));
#else
	return (linux_mmap_common(td, PTROUT(uap->addr), uap->len, uap->prot,
	    uap->flags, uap->fd, uap->pgoff));
#endif
}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_time(struct thread *td, struct linux_time_args *args)
{
	struct timeval tv;
	l_time_t tm;
	int error;

	microtime(&tv);
	tm = tv.tv_sec;
	if (args->tm && (error = copyout(&tm, args->tm, sizeof(tm))))
		return (error);
	td->td_retval[0] = tm;
	return (0);
}
#endif

struct l_times_argv {
	l_clock_t	tms_utime;
	l_clock_t	tms_stime;
	l_clock_t	tms_cutime;
	l_clock_t	tms_cstime;
};

/*
 * Glibc versions prior to 2.2.1 always use hard-coded CLK_TCK value.
 * Since 2.2.1 Glibc uses value exported from kernel via AT_CLKTCK
 * auxiliary vector entry.
 */
#define	CLK_TCK		100

#define	CONVOTCK(r)	(r.tv_sec * CLK_TCK + r.tv_usec / (1000000 / CLK_TCK))
#define	CONVNTCK(r)	(r.tv_sec * stclohz + r.tv_usec / (1000000 / stclohz))

#define	CONVTCK(r)	(linux_kernver(td) >= LINUX_KERNVER(2,4,0) ?	\
			    CONVNTCK(r) : CONVOTCK(r))

int
linux_times(struct thread *td, struct linux_times_args *args)
{
	struct timeval tv, utime, stime, cutime, cstime;
	struct l_times_argv tms;
	struct proc *p;
	int error;

	if (args->buf != NULL) {
		p = td->td_proc;
		PROC_LOCK(p);
		PROC_STATLOCK(p);
		calcru(p, &utime, &stime);
		PROC_STATUNLOCK(p);
		calccru(p, &cutime, &cstime);
		PROC_UNLOCK(p);

		tms.tms_utime = CONVTCK(utime);
		tms.tms_stime = CONVTCK(stime);

		tms.tms_cutime = CONVTCK(cutime);
		tms.tms_cstime = CONVTCK(cstime);

		if ((error = copyout(&tms, args->buf, sizeof(tms))))
			return (error);
	}

	microuptime(&tv);
	td->td_retval[0] = (int)CONVTCK(tv);
	return (0);
}

int
linux_newuname(struct thread *td, struct linux_newuname_args *args)
{
	struct l_new_utsname utsname;
	char osname[LINUX_MAX_UTSNAME];
	char osrelease[LINUX_MAX_UTSNAME];
	char *p;

	linux_get_osname(td, osname);
	linux_get_osrelease(td, osrelease);

	bzero(&utsname, sizeof(utsname));
	strlcpy(utsname.sysname, osname, LINUX_MAX_UTSNAME);
	getcredhostname(td->td_ucred, utsname.nodename, LINUX_MAX_UTSNAME);
	getcreddomainname(td->td_ucred, utsname.domainname, LINUX_MAX_UTSNAME);
	strlcpy(utsname.release, osrelease, LINUX_MAX_UTSNAME);
	strlcpy(utsname.version, version, LINUX_MAX_UTSNAME);
	for (p = utsname.version; *p != '\0'; ++p)
		if (*p == '\n') {
			*p = '\0';
			break;
		}
#if defined(__amd64__)
	/*
	 * On amd64, Linux uname(2) needs to return "x86_64"
	 * for both 64-bit and 32-bit applications.  On 32-bit,
	 * the string returned by getauxval(AT_PLATFORM) needs
	 * to remain "i686", though.
	 */
#if defined(COMPAT_LINUX32)
	if (linux32_emulate_i386)
		strlcpy(utsname.machine, "i686", LINUX_MAX_UTSNAME);
	else
#endif
	strlcpy(utsname.machine, "x86_64", LINUX_MAX_UTSNAME);
#elif defined(__aarch64__)
	strlcpy(utsname.machine, "aarch64", LINUX_MAX_UTSNAME);
#elif defined(__i386__)
	strlcpy(utsname.machine, "i686", LINUX_MAX_UTSNAME);
#endif

	return (copyout(&utsname, args->buf, sizeof(utsname)));
}

struct l_utimbuf {
	l_time_t l_actime;
	l_time_t l_modtime;
};

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_utime(struct thread *td, struct linux_utime_args *args)
{
	struct timeval tv[2], *tvp;
	struct l_utimbuf lut;
	int error;

	if (args->times) {
		if ((error = copyin(args->times, &lut, sizeof lut)) != 0)
			return (error);
		tv[0].tv_sec = lut.l_actime;
		tv[0].tv_usec = 0;
		tv[1].tv_sec = lut.l_modtime;
		tv[1].tv_usec = 0;
		tvp = tv;
	} else
		tvp = NULL;

	return (kern_utimesat(td, AT_FDCWD, args->fname, UIO_USERSPACE,
	    tvp, UIO_SYSSPACE));
}
#endif

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_utimes(struct thread *td, struct linux_utimes_args *args)
{
	l_timeval ltv[2];
	struct timeval tv[2], *tvp = NULL;
	int error;

	if (args->tptr != NULL) {
		if ((error = copyin(args->tptr, ltv, sizeof ltv)) != 0)
			return (error);
		tv[0].tv_sec = ltv[0].tv_sec;
		tv[0].tv_usec = ltv[0].tv_usec;
		tv[1].tv_sec = ltv[1].tv_sec;
		tv[1].tv_usec = ltv[1].tv_usec;
		tvp = tv;
	}

	return (kern_utimesat(td, AT_FDCWD, args->fname, UIO_USERSPACE,
	    tvp, UIO_SYSSPACE));
}
#endif

static int
linux_utimensat_lts_to_ts(struct l_timespec *l_times, struct timespec *times)
{

	if (l_times->tv_nsec != LINUX_UTIME_OMIT &&
	    l_times->tv_nsec != LINUX_UTIME_NOW &&
	    (l_times->tv_nsec < 0 || l_times->tv_nsec > 999999999))
		return (EINVAL);

	times->tv_sec = l_times->tv_sec;
	switch (l_times->tv_nsec)
	{
	case LINUX_UTIME_OMIT:
		times->tv_nsec = UTIME_OMIT;
		break;
	case LINUX_UTIME_NOW:
		times->tv_nsec = UTIME_NOW;
		break;
	default:
		times->tv_nsec = l_times->tv_nsec;
	}

	return (0);
}

static int
linux_common_utimensat(struct thread *td, int ldfd, const char *pathname,
    struct timespec *timesp, int lflags)
{
	int dfd, flags = 0;

	dfd = (ldfd == LINUX_AT_FDCWD) ? AT_FDCWD : ldfd;

	if (lflags & ~(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH))
		return (EINVAL);

	if (timesp != NULL) {
		/* This breaks POSIX, but is what the Linux kernel does
		 * _on purpose_ (documented in the man page for utimensat(2)),
		 * so we must follow that behaviour. */
		if (timesp[0].tv_nsec == UTIME_OMIT &&
		    timesp[1].tv_nsec == UTIME_OMIT)
			return (0);
	}

	if (lflags & LINUX_AT_SYMLINK_NOFOLLOW)
		flags |= AT_SYMLINK_NOFOLLOW;
	if (lflags & LINUX_AT_EMPTY_PATH)
		flags |= AT_EMPTY_PATH;

	if (pathname != NULL)
		return (kern_utimensat(td, dfd, pathname,
		    UIO_USERSPACE, timesp, UIO_SYSSPACE, flags));

	if (lflags != 0)
		return (EINVAL);

	return (kern_futimens(td, dfd, timesp, UIO_SYSSPACE));
}

int
linux_utimensat(struct thread *td, struct linux_utimensat_args *args)
{
	struct l_timespec l_times[2];
	struct timespec times[2], *timesp;
	int error;

	if (args->times != NULL) {
		error = copyin(args->times, l_times, sizeof(l_times));
		if (error != 0)
			return (error);

		error = linux_utimensat_lts_to_ts(&l_times[0], &times[0]);
		if (error != 0)
			return (error);
		error = linux_utimensat_lts_to_ts(&l_times[1], &times[1]);
		if (error != 0)
			return (error);
		timesp = times;
	} else
		timesp = NULL;

	return (linux_common_utimensat(td, args->dfd, args->pathname,
	    timesp, args->flags));
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
static int
linux_utimensat_lts64_to_ts(struct l_timespec64 *l_times, struct timespec *times)
{

	/* Zero out the padding in compat mode. */
	l_times->tv_nsec &= 0xFFFFFFFFUL;

	if (l_times->tv_nsec != LINUX_UTIME_OMIT &&
	    l_times->tv_nsec != LINUX_UTIME_NOW &&
	    (l_times->tv_nsec < 0 || l_times->tv_nsec > 999999999))
		return (EINVAL);

	times->tv_sec = l_times->tv_sec;
	switch (l_times->tv_nsec)
	{
	case LINUX_UTIME_OMIT:
		times->tv_nsec = UTIME_OMIT;
		break;
	case LINUX_UTIME_NOW:
		times->tv_nsec = UTIME_NOW;
		break;
	default:
		times->tv_nsec = l_times->tv_nsec;
	}

	return (0);
}

int
linux_utimensat_time64(struct thread *td, struct linux_utimensat_time64_args *args)
{
	struct l_timespec64 l_times[2];
	struct timespec times[2], *timesp;
	int error;

	if (args->times64 != NULL) {
		error = copyin(args->times64, l_times, sizeof(l_times));
		if (error != 0)
			return (error);

		error = linux_utimensat_lts64_to_ts(&l_times[0], &times[0]);
		if (error != 0)
			return (error);
		error = linux_utimensat_lts64_to_ts(&l_times[1], &times[1]);
		if (error != 0)
			return (error);
		timesp = times;
	} else
		timesp = NULL;

	return (linux_common_utimensat(td, args->dfd, args->pathname,
	    timesp, args->flags));
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_futimesat(struct thread *td, struct linux_futimesat_args *args)
{
	l_timeval ltv[2];
	struct timeval tv[2], *tvp = NULL;
	int error, dfd;

	dfd = (args->dfd == LINUX_AT_FDCWD) ? AT_FDCWD : args->dfd;

	if (args->utimes != NULL) {
		if ((error = copyin(args->utimes, ltv, sizeof ltv)) != 0)
			return (error);
		tv[0].tv_sec = ltv[0].tv_sec;
		tv[0].tv_usec = ltv[0].tv_usec;
		tv[1].tv_sec = ltv[1].tv_sec;
		tv[1].tv_usec = ltv[1].tv_usec;
		tvp = tv;
	}

	return (kern_utimesat(td, dfd, args->filename, UIO_USERSPACE,
	    tvp, UIO_SYSSPACE));
}
#endif

static int
linux_common_wait(struct thread *td, idtype_t idtype, int id, int *statusp,
    int options, void *rup, l_siginfo_t *infop)
{
	l_siginfo_t lsi;
	siginfo_t siginfo;
	struct __wrusage wru;
	int error, status, tmpstat, sig;

	error = kern_wait6(td, idtype, id, &status, options,
	    rup != NULL ? &wru : NULL, &siginfo);

	if (error == 0 && statusp) {
		tmpstat = status & 0xffff;
		if (WIFSIGNALED(tmpstat)) {
			tmpstat = (tmpstat & 0xffffff80) |
			    bsd_to_linux_signal(WTERMSIG(tmpstat));
		} else if (WIFSTOPPED(tmpstat)) {
			tmpstat = (tmpstat & 0xffff00ff) |
			    (bsd_to_linux_signal(WSTOPSIG(tmpstat)) << 8);
#if defined(__aarch64__) || (defined(__amd64__) && !defined(COMPAT_LINUX32))
			if (WSTOPSIG(status) == SIGTRAP) {
				tmpstat = linux_ptrace_status(td,
				    siginfo.si_pid, tmpstat);
			}
#endif
		} else if (WIFCONTINUED(tmpstat)) {
			tmpstat = 0xffff;
		}
		error = copyout(&tmpstat, statusp, sizeof(int));
	}
	if (error == 0 && rup != NULL)
		error = linux_copyout_rusage(&wru.wru_self, rup);
	if (error == 0 && infop != NULL && td->td_retval[0] != 0) {
		sig = bsd_to_linux_signal(siginfo.si_signo);
		memset(&lsi, 0, sizeof(lsi));
		siginfo_to_lsiginfo(&siginfo, &lsi, sig);
		error = copyout(&lsi, infop, sizeof(lsi));
	}

	return (error);
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_waitpid(struct thread *td, struct linux_waitpid_args *args)
{
	struct linux_wait4_args wait4_args = {
		.pid = args->pid,
		.status = args->status,
		.options = args->options,
		.rusage = NULL,
	};

	return (linux_wait4(td, &wait4_args));
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

int
linux_wait4(struct thread *td, struct linux_wait4_args *args)
{
	struct proc *p;
	int options, id, idtype;

	if (args->options & ~(LINUX_WUNTRACED | LINUX_WNOHANG |
	    LINUX_WCONTINUED | __WCLONE | __WNOTHREAD | __WALL))
		return (EINVAL);

	/* -INT_MIN is not defined. */
	if (args->pid == INT_MIN)
		return (ESRCH);

	options = 0;
	linux_to_bsd_waitopts(args->options, &options);

	/*
	 * For backward compatibility we implicitly add flags WEXITED
	 * and WTRAPPED here.
	 */
	options |= WEXITED | WTRAPPED;

	if (args->pid == WAIT_ANY) {
		idtype = P_ALL;
		id = 0;
	} else if (args->pid < 0) {
		idtype = P_PGID;
		id = (id_t)-args->pid;
	} else if (args->pid == 0) {
		idtype = P_PGID;
		p = td->td_proc;
		PROC_LOCK(p);
		id = p->p_pgid;
		PROC_UNLOCK(p);
	} else {
		idtype = P_PID;
		id = (id_t)args->pid;
	}

	return (linux_common_wait(td, idtype, id, args->status, options,
	    args->rusage, NULL));
}

int
linux_waitid(struct thread *td, struct linux_waitid_args *args)
{
	idtype_t idtype;
	int error, options;
	struct proc *p;
	pid_t id;

	if (args->options & ~(LINUX_WNOHANG | LINUX_WNOWAIT | LINUX_WEXITED |
	    LINUX_WSTOPPED | LINUX_WCONTINUED | __WCLONE | __WNOTHREAD | __WALL))
		return (EINVAL);

	options = 0;
	linux_to_bsd_waitopts(args->options, &options);

	id = args->id;
	switch (args->idtype) {
	case LINUX_P_ALL:
		idtype = P_ALL;
		break;
	case LINUX_P_PID:
		if (args->id <= 0)
			return (EINVAL);
		idtype = P_PID;
		break;
	case LINUX_P_PGID:
		if (linux_kernver(td) >= LINUX_KERNVER(5,4,0) && args->id == 0) {
			p = td->td_proc;
			PROC_LOCK(p);
			id = p->p_pgid;
			PROC_UNLOCK(p);
		} else if (args->id <= 0)
			return (EINVAL);
		idtype = P_PGID;
		break;
	case LINUX_P_PIDFD:
		/*
		 * Linux: id is a pidfd; EBADF if it is not one.  A pidfd of
		 * an already-reaped child yields ECHILD from the wait itself,
		 * as on Linux.
		 */
		error = linux_pidfd_topid(td, args->id, &id);
		if (error != 0)
			return (error);
		idtype = P_PID;
		break;
	default:
		return (EINVAL);
	}

	error = linux_common_wait(td, idtype, id, NULL, options,
	    args->rusage, args->info);
	td->td_retval[0] = 0;

	return (error);
}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_mknod(struct thread *td, struct linux_mknod_args *args)
{
	int error;

	switch (args->mode & S_IFMT) {
	case S_IFIFO:
	case S_IFSOCK:
		error = kern_mkfifoat(td, AT_FDCWD, args->path, UIO_USERSPACE,
		    args->mode);
		break;

	case S_IFCHR:
	case S_IFBLK:
		error = kern_mknodat(td, AT_FDCWD, args->path, UIO_USERSPACE,
		    args->mode, linux_decode_dev(args->dev));
		break;

	case S_IFDIR:
		error = EPERM;
		break;

	case 0:
		args->mode |= S_IFREG;
		/* FALLTHROUGH */
	case S_IFREG:
		error = kern_openat(td, AT_FDCWD, args->path, UIO_USERSPACE,
		    O_WRONLY | O_CREAT | O_TRUNC, args->mode);
		if (error == 0)
			kern_close(td, td->td_retval[0]);
		break;

	default:
		error = EINVAL;
		break;
	}
	return (error);
}
#endif

int
linux_mknodat(struct thread *td, struct linux_mknodat_args *args)
{
	int error, dfd;

	dfd = (args->dfd == LINUX_AT_FDCWD) ? AT_FDCWD : args->dfd;

	switch (args->mode & S_IFMT) {
	case S_IFIFO:
	case S_IFSOCK:
		error = kern_mkfifoat(td, dfd, args->filename, UIO_USERSPACE,
		    args->mode);
		break;

	case S_IFCHR:
	case S_IFBLK:
		error = kern_mknodat(td, dfd, args->filename, UIO_USERSPACE,
		    args->mode, linux_decode_dev(args->dev));
		break;

	case S_IFDIR:
		error = EPERM;
		break;

	case 0:
		args->mode |= S_IFREG;
		/* FALLTHROUGH */
	case S_IFREG:
		error = kern_openat(td, dfd, args->filename, UIO_USERSPACE,
		    O_WRONLY | O_CREAT | O_TRUNC, args->mode);
		if (error == 0)
			kern_close(td, td->td_retval[0]);
		break;

	default:
		error = EINVAL;
		break;
	}
	return (error);
}

/*
 * UGH! This is just about the dumbest idea I've ever heard!!
 */
int
linux_personality(struct thread *td, struct linux_personality_args *args)
{
	struct linux_pemuldata *pem;
	struct proc *p = td->td_proc;
	uint32_t old;
	int aslr;

	PROC_LOCK(p);
	pem = pem_find(p);
	old = pem->persona;
	if (args->per != 0xffffffff)
		pem->persona = args->per;
	PROC_UNLOCK(p);

	/*
	 * ADDR_NO_RANDOMIZE takes effect at the next execve(2), which is
	 * exactly what PROC_ASLR_CTL controls (setarch -R, debuggers).
	 * The other bug-emulation bits are no-ops on Linux/x86-64 as well.
	 */
	if (args->per != 0xffffffff &&
	    ((old ^ args->per) & LINUX_ADDR_NO_RANDOMIZE) != 0) {
		aslr = (args->per & LINUX_ADDR_NO_RANDOMIZE) != 0 ?
		    PROC_ASLR_FORCE_DISABLE : PROC_ASLR_NOFORCE;
		(void)kern_procctl(td, P_PID, p->p_pid, PROC_ASLR_CTL, &aslr);
	}

	td->td_retval[0] = old;
	return (0);
}

struct l_itimerval {
	l_timeval it_interval;
	l_timeval it_value;
};

#define	B2L_ITIMERVAL(bip, lip)						\
	(bip)->it_interval.tv_sec = (lip)->it_interval.tv_sec;		\
	(bip)->it_interval.tv_usec = (lip)->it_interval.tv_usec;	\
	(bip)->it_value.tv_sec = (lip)->it_value.tv_sec;		\
	(bip)->it_value.tv_usec = (lip)->it_value.tv_usec;

int
linux_setitimer(struct thread *td, struct linux_setitimer_args *uap)
{
	int error;
	struct l_itimerval ls;
	struct itimerval aitv, oitv;

	if (uap->itv == NULL) {
		uap->itv = uap->oitv;
		return (linux_getitimer(td, (struct linux_getitimer_args *)uap));
	}

	error = copyin(uap->itv, &ls, sizeof(ls));
	if (error != 0)
		return (error);
	B2L_ITIMERVAL(&aitv, &ls);
	error = kern_setitimer(td, uap->which, &aitv, &oitv);
	if (error != 0 || uap->oitv == NULL)
		return (error);
	B2L_ITIMERVAL(&ls, &oitv);

	return (copyout(&ls, uap->oitv, sizeof(ls)));
}

int
linux_getitimer(struct thread *td, struct linux_getitimer_args *uap)
{
	int error;
	struct l_itimerval ls;
	struct itimerval aitv;

	error = kern_getitimer(td, uap->which, &aitv);
	if (error != 0)
		return (error);
	B2L_ITIMERVAL(&ls, &aitv);
	return (copyout(&ls, uap->itv, sizeof(ls)));
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_nice(struct thread *td, struct linux_nice_args *args)
{

	return (kern_setpriority(td, PRIO_PROCESS, 0, args->inc));
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

int
linux_setgroups(struct thread *td, struct linux_setgroups_args *args)
{
	const int ngrp = args->gidsetsize;
	struct ucred *newcred, *oldcred;
	l_gid_t *linux_gidset;
	int error;
	struct proc *p;

	if (ngrp < 0 || ngrp > ngroups_max)
		return (EINVAL);
	linux_gidset = malloc(ngrp * sizeof(*linux_gidset), M_LINUX, M_WAITOK);
	error = copyin(args->grouplist, linux_gidset, ngrp * sizeof(l_gid_t));
	if (error)
		goto out;

	newcred = crget();
	crextend(newcred, ngrp);
	p = td->td_proc;
	PROC_LOCK(p);
	oldcred = crcopysafe(p, newcred);

	if ((error = priv_check_cred(oldcred, PRIV_CRED_SETGROUPS)) != 0) {
		PROC_UNLOCK(p);
		crfree(newcred);
		goto out;
	}

	newcred->cr_ngroups = ngrp;
	for (int i = 0; i < ngrp; i++)
		newcred->cr_groups[i] = linux_gidset[i];
	newcred->cr_flags |= CRED_FLAG_GROUPSET;

	setsugid(p);
	proc_set_cred(p, newcred);
	PROC_UNLOCK(p);
	crfree(oldcred);
	error = 0;
out:
	free(linux_gidset, M_LINUX);
	return (error);
}

int
linux_getgroups(struct thread *td, struct linux_getgroups_args *args)
{
	const struct ucred *const cred = td->td_ucred;
	l_gid_t *linux_gidset;
	int ngrp, error;

	ngrp = args->gidsetsize;

	if (ngrp == 0) {
		td->td_retval[0] = cred->cr_ngroups;
		return (0);
	}
	if (ngrp < cred->cr_ngroups)
		return (EINVAL);

	ngrp = cred->cr_ngroups;

	linux_gidset = malloc(ngrp * sizeof(*linux_gidset), M_LINUX, M_WAITOK);
	for (int i = 0; i < ngrp; ++i)
		linux_gidset[i] = cred->cr_groups[i];

	error = copyout(linux_gidset, args->grouplist, ngrp * sizeof(l_gid_t));
	free(linux_gidset, M_LINUX);

	if (error != 0)
		return (error);

	td->td_retval[0] = ngrp;
	return (0);
}

static bool
linux_get_dummy_limit(struct thread *td, l_uint resource, struct rlimit *rlim)
{
	ssize_t size;
	int res, error;

	if (linux_dummy_rlimits == 0)
		return (false);
	size = sizeof(res);

	switch (resource) {
	case LINUX_RLIMIT_LOCKS:
	case LINUX_RLIMIT_RTTIME:
		rlim->rlim_cur = LINUX_RLIM_INFINITY;
		rlim->rlim_max = LINUX_RLIM_INFINITY;
		return (true);
	case LINUX_RLIMIT_NICE:
	case LINUX_RLIMIT_RTPRIO:
		rlim->rlim_cur = 0;
		rlim->rlim_max = 0;
		return (true);
	case LINUX_RLIMIT_SIGPENDING:
		error = kernel_sysctlbyname(td,
		    "kern.sigqueue.max_pending_per_proc",
		    &res, &size, 0, 0, 0, 0);
		if (error != 0)
			return (false);
		rlim->rlim_cur = res;
		rlim->rlim_max = res;
		return (true);
	case LINUX_RLIMIT_MSGQUEUE:
		error = kernel_sysctlbyname(td,
		    "kern.ipc.msgmnb", &res, &size, 0, 0, 0, 0);
		if (error != 0)
			return (false);
		rlim->rlim_cur = res;
		rlim->rlim_max = res;
		return (true);
	default:
		return (false);
	}
}

/*
 * Setting one of the limits FreeBSD does not have.  NICE and RTPRIO have
 * a hard limit of 0 (nothing may be raised without privilege here, which
 * is what that value means on Linux), LOCKS/RTTIME are unlimited, and
 * SIGPENDING/MSGQUEUE report the system-wide values.  The Linux rules
 * apply: soft <= hard is EINVAL otherwise, raising the hard limit needs
 * CAP_SYS_RESOURCE (EPERM); a value at or below the current one is
 * accepted (the effective limit does not change).
 */
static bool
linux_set_dummy_limit(struct thread *td, l_uint resource,
    const struct rlimit *nrlim, int *error)
{
	struct rlimit cur;

	if (!linux_get_dummy_limit(td, resource, &cur))
		return (false);
	/* Compare in the unsigned Linux domain (RLIM_INFINITY is ~0). */
	if ((uint64_t)nrlim->rlim_cur > (uint64_t)nrlim->rlim_max) {
		*error = EINVAL;
		return (true);
	}
	if ((uint64_t)nrlim->rlim_max > (uint64_t)cur.rlim_max &&
	    priv_check(td, PRIV_PROC_SETRLIMIT) != 0) {
		*error = EPERM;
		return (true);
	}
	*error = 0;
	return (true);
}

int
linux_setrlimit(struct thread *td, struct linux_setrlimit_args *args)
{
	struct rlimit bsd_rlim;
	struct l_rlimit rlim;
	u_int which;
	int error;

	error = copyin(args->rlim, &rlim, sizeof(rlim));
	if (error)
		return (error);

	bsd_rlim.rlim_cur = (rlim_t)rlim.rlim_cur;
	bsd_rlim.rlim_max = (rlim_t)rlim.rlim_max;
	/* The Linux-only resources sit above the native table. */
	if (linux_set_dummy_limit(td, args->resource, &bsd_rlim, &error))
		return (error);

	if (args->resource >= LINUX_RLIM_NLIMITS)
		return (EINVAL);

	which = linux_to_bsd_resource[args->resource];
	if (which == -1)
		return (EINVAL);

	return (kern_setrlimit(td, which, &bsd_rlim));
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_old_getrlimit(struct thread *td, struct linux_old_getrlimit_args *args)
{
	struct l_rlimit rlim;
	struct rlimit bsd_rlim;
	u_int which;

	if (linux_get_dummy_limit(td, args->resource, &bsd_rlim)) {
		rlim.rlim_cur = bsd_rlim.rlim_cur;
		rlim.rlim_max = bsd_rlim.rlim_max;
		return (copyout(&rlim, args->rlim, sizeof(rlim)));
	}

	if (args->resource >= LINUX_RLIM_NLIMITS)
		return (EINVAL);

	which = linux_to_bsd_resource[args->resource];
	if (which == -1)
		return (EINVAL);

	lim_rlimit(td, which, &bsd_rlim);

#ifdef COMPAT_LINUX32
	rlim.rlim_cur = (unsigned int)bsd_rlim.rlim_cur;
	if (rlim.rlim_cur == UINT_MAX)
		rlim.rlim_cur = INT_MAX;
	rlim.rlim_max = (unsigned int)bsd_rlim.rlim_max;
	if (rlim.rlim_max == UINT_MAX)
		rlim.rlim_max = INT_MAX;
#else
	rlim.rlim_cur = (unsigned long)bsd_rlim.rlim_cur;
	if (rlim.rlim_cur == ULONG_MAX)
		rlim.rlim_cur = LONG_MAX;
	rlim.rlim_max = (unsigned long)bsd_rlim.rlim_max;
	if (rlim.rlim_max == ULONG_MAX)
		rlim.rlim_max = LONG_MAX;
#endif
	return (copyout(&rlim, args->rlim, sizeof(rlim)));
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

int
linux_getrlimit(struct thread *td, struct linux_getrlimit_args *args)
{
	struct l_rlimit rlim;
	struct rlimit bsd_rlim;
	u_int which;

	if (linux_get_dummy_limit(td, args->resource, &bsd_rlim)) {
		rlim.rlim_cur = bsd_rlim.rlim_cur;
		rlim.rlim_max = bsd_rlim.rlim_max;
		return (copyout(&rlim, args->rlim, sizeof(rlim)));
	}

	if (args->resource >= LINUX_RLIM_NLIMITS)
		return (EINVAL);

	which = linux_to_bsd_resource[args->resource];
	if (which == -1)
		return (EINVAL);

	lim_rlimit(td, which, &bsd_rlim);

	rlim.rlim_cur = (l_ulong)bsd_rlim.rlim_cur;
	rlim.rlim_max = (l_ulong)bsd_rlim.rlim_max;
	return (copyout(&rlim, args->rlim, sizeof(rlim)));
}

int
linux_sched_setscheduler(struct thread *td,
    struct linux_sched_setscheduler_args *args)
{
	struct sched_param sched_param;
	struct thread *tdt;
	int error, policy;

	switch (args->policy) {
	case LINUX_SCHED_OTHER:
		policy = SCHED_OTHER;
		break;
	case LINUX_SCHED_FIFO:
		policy = SCHED_FIFO;
		break;
	case LINUX_SCHED_RR:
		policy = SCHED_RR;
		break;
	default:
		return (EINVAL);
	}

	error = copyin(args->param, &sched_param, sizeof(sched_param));
	if (error)
		return (error);

	if (linux_map_sched_prio) {
		switch (policy) {
		case SCHED_OTHER:
			if (sched_param.sched_priority != 0)
				return (EINVAL);

			sched_param.sched_priority =
			    PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE;
			break;
		case SCHED_FIFO:
		case SCHED_RR:
			if (sched_param.sched_priority < 1 ||
			    sched_param.sched_priority >= LINUX_MAX_RT_PRIO)
				return (EINVAL);

			/*
			 * Map [1, LINUX_MAX_RT_PRIO - 1] to
			 * [0, RTP_PRIO_MAX - RTP_PRIO_MIN] (rounding down).
			 */
			sched_param.sched_priority =
			    (sched_param.sched_priority - 1) *
			    (RTP_PRIO_MAX - RTP_PRIO_MIN + 1) /
			    (LINUX_MAX_RT_PRIO - 1);
			break;
		}
	}

	tdt = linux_tdfind(td, args->pid, -1);
	if (tdt == NULL)
		return (ESRCH);

	error = kern_sched_setscheduler(td, tdt, policy, &sched_param);
	PROC_UNLOCK(tdt->td_proc);
	return (error);
}

int
linux_sched_getscheduler(struct thread *td,
    struct linux_sched_getscheduler_args *args)
{
	struct thread *tdt;
	int error, policy;

	tdt = linux_tdfind(td, args->pid, -1);
	if (tdt == NULL)
		return (ESRCH);

	error = kern_sched_getscheduler(td, tdt, &policy);
	PROC_UNLOCK(tdt->td_proc);

	switch (policy) {
	case SCHED_OTHER:
		td->td_retval[0] = LINUX_SCHED_OTHER;
		break;
	case SCHED_FIFO:
		td->td_retval[0] = LINUX_SCHED_FIFO;
		break;
	case SCHED_RR:
		td->td_retval[0] = LINUX_SCHED_RR;
		break;
	}
	return (error);
}

int
linux_sched_get_priority_max(struct thread *td,
    struct linux_sched_get_priority_max_args *args)
{
	struct sched_get_priority_max_args bsd;

	if (linux_map_sched_prio) {
		switch (args->policy) {
		case LINUX_SCHED_OTHER:
			td->td_retval[0] = 0;
			return (0);
		case LINUX_SCHED_FIFO:
		case LINUX_SCHED_RR:
			td->td_retval[0] = LINUX_MAX_RT_PRIO - 1;
			return (0);
		default:
			return (EINVAL);
		}
	}

	switch (args->policy) {
	case LINUX_SCHED_OTHER:
		bsd.policy = SCHED_OTHER;
		break;
	case LINUX_SCHED_FIFO:
		bsd.policy = SCHED_FIFO;
		break;
	case LINUX_SCHED_RR:
		bsd.policy = SCHED_RR;
		break;
	default:
		return (EINVAL);
	}
	return (sys_sched_get_priority_max(td, &bsd));
}

int
linux_sched_get_priority_min(struct thread *td,
    struct linux_sched_get_priority_min_args *args)
{
	struct sched_get_priority_min_args bsd;

	if (linux_map_sched_prio) {
		switch (args->policy) {
		case LINUX_SCHED_OTHER:
			td->td_retval[0] = 0;
			return (0);
		case LINUX_SCHED_FIFO:
		case LINUX_SCHED_RR:
			td->td_retval[0] = 1;
			return (0);
		default:
			return (EINVAL);
		}
	}

	switch (args->policy) {
	case LINUX_SCHED_OTHER:
		bsd.policy = SCHED_OTHER;
		break;
	case LINUX_SCHED_FIFO:
		bsd.policy = SCHED_FIFO;
		break;
	case LINUX_SCHED_RR:
		bsd.policy = SCHED_RR;
		break;
	default:
		return (EINVAL);
	}
	return (sys_sched_get_priority_min(td, &bsd));
}

#define REBOOT_CAD_ON	0x89abcdef
#define REBOOT_CAD_OFF	0
#define REBOOT_HALT	0xcdef0123
#define REBOOT_RESTART	0x01234567
#define REBOOT_RESTART2	0xA1B2C3D4
#define REBOOT_POWEROFF	0x4321FEDC
#define REBOOT_MAGIC1	0xfee1dead
#define REBOOT_MAGIC2	0x28121969
#define REBOOT_MAGIC2A	0x05121996
#define REBOOT_MAGIC2B	0x16041998

int
linux_reboot(struct thread *td, struct linux_reboot_args *args)
{
	struct reboot_args bsd_args;

	if (args->magic1 != REBOOT_MAGIC1)
		return (EINVAL);

	switch (args->magic2) {
	case REBOOT_MAGIC2:
	case REBOOT_MAGIC2A:
	case REBOOT_MAGIC2B:
		break;
	default:
		return (EINVAL);
	}

	switch (args->cmd) {
	case REBOOT_CAD_ON:
	case REBOOT_CAD_OFF:
		return (priv_check(td, PRIV_REBOOT));
	case REBOOT_HALT:
		bsd_args.opt = RB_HALT;
		break;
	case REBOOT_RESTART:
	case REBOOT_RESTART2:
		bsd_args.opt = 0;
		break;
	case REBOOT_POWEROFF:
		bsd_args.opt = RB_POWEROFF;
		break;
	default:
		return (EINVAL);
	}
	return (sys_reboot(td, &bsd_args));
}

int
linux_getpid(struct thread *td, struct linux_getpid_args *args)
{

	td->td_retval[0] = td->td_proc->p_pid;

	return (0);
}

int
linux_gettid(struct thread *td, struct linux_gettid_args *args)
{
	struct linux_emuldata *em;

	em = em_find(td);
	KASSERT(em != NULL, ("gettid: emuldata not found.\n"));

	td->td_retval[0] = em->em_tid;

	return (0);
}

int
linux_getppid(struct thread *td, struct linux_getppid_args *args)
{

	td->td_retval[0] = kern_getppid(td);
	return (0);
}

int
linux_getgid(struct thread *td, struct linux_getgid_args *args)
{

	td->td_retval[0] = td->td_ucred->cr_rgid;
	return (0);
}

int
linux_getuid(struct thread *td, struct linux_getuid_args *args)
{

	td->td_retval[0] = td->td_ucred->cr_ruid;
	return (0);
}

int
linux_getsid(struct thread *td, struct linux_getsid_args *args)
{

	return (kern_getsid(td, args->pid));
}

int
linux_getpriority(struct thread *td, struct linux_getpriority_args *args)
{
	int error;

	error = kern_getpriority(td, args->which, args->who);
	td->td_retval[0] = 20 - td->td_retval[0];
	return (error);
}

int
linux_sethostname(struct thread *td, struct linux_sethostname_args *args)
{
	int name[2];

	name[0] = CTL_KERN;
	name[1] = KERN_HOSTNAME;
	return (userland_sysctl(td, name, 2, 0, 0, 0, args->hostname,
	    args->len, 0, 0));
}

int
linux_setdomainname(struct thread *td, struct linux_setdomainname_args *args)
{
	int name[2];

	name[0] = CTL_KERN;
	name[1] = KERN_NISDOMAINNAME;
	return (userland_sysctl(td, name, 2, 0, 0, 0, args->name,
	    args->len, 0, 0));
}

int
linux_exit_group(struct thread *td, struct linux_exit_group_args *args)
{

	LINUX_CTR2(exit_group, "thread(%d) (%d)", td->td_tid,
	    args->error_code);

	/*
	 * XXX: we should send a signal to the parent if
	 * SIGNAL_EXIT_GROUP is set. We ignore that (temporarily?)
	 * as it doesnt occur often.
	 */
	exit1(td, args->error_code, 0);
		/* NOTREACHED */
}

#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026
#define _LINUX_CAPABILITY_VERSION_3  0x20080522

struct l_user_cap_header {
	l_int	version;
	l_int	pid;
};

struct l_user_cap_data {
	l_int	effective;
	l_int	permitted;
	l_int	inheritable;
};

int
linux_capget(struct thread *td, struct linux_capget_args *uap)
{
	struct l_user_cap_header luch;
	struct l_user_cap_data lucd[2];
	int error, u32s;

	if (uap->hdrp == NULL)
		return (EFAULT);

	error = copyin(uap->hdrp, &luch, sizeof(luch));
	if (error != 0)
		return (error);

	switch (luch.version) {
	case _LINUX_CAPABILITY_VERSION_1:
		u32s = 1;
		break;
	case _LINUX_CAPABILITY_VERSION_2:
	case _LINUX_CAPABILITY_VERSION_3:
		u32s = 2;
		break;
	default:
		luch.version = _LINUX_CAPABILITY_VERSION_1;
		error = copyout(&luch, uap->hdrp, sizeof(luch));
		if (error)
			return (error);
		return (EINVAL);
	}

	if (luch.pid)
		return (EPERM);

	if (uap->datap) {
		/*
		 * The current implementation doesn't support setting
		 * a capability (it's essentially a stub) so indicate
		 * that no capabilities are currently set or available
		 * to request.
		 */
		memset(&lucd, 0, u32s * sizeof(lucd[0]));
		error = copyout(&lucd, uap->datap, u32s * sizeof(lucd[0]));
	}

	return (error);
}

int
linux_capset(struct thread *td, struct linux_capset_args *uap)
{
	struct l_user_cap_header luch;
	struct l_user_cap_data lucd[2];
	int error, i, u32s;

	if (uap->hdrp == NULL || uap->datap == NULL)
		return (EFAULT);

	error = copyin(uap->hdrp, &luch, sizeof(luch));
	if (error != 0)
		return (error);

	switch (luch.version) {
	case _LINUX_CAPABILITY_VERSION_1:
		u32s = 1;
		break;
	case _LINUX_CAPABILITY_VERSION_2:
	case _LINUX_CAPABILITY_VERSION_3:
		u32s = 2;
		break;
	default:
		luch.version = _LINUX_CAPABILITY_VERSION_1;
		error = copyout(&luch, uap->hdrp, sizeof(luch));
		if (error)
			return (error);
		return (EINVAL);
	}

	if (luch.pid)
		return (EPERM);

	error = copyin(uap->datap, &lucd, u32s * sizeof(lucd[0]));
	if (error != 0)
		return (error);

	/* We currently don't support setting any capabilities. */
	for (i = 0; i < u32s; i++) {
		if (lucd[i].effective || lucd[i].permitted ||
		    lucd[i].inheritable) {
			linux_msg(td,
			    "capset[%d] effective=0x%x, permitted=0x%x, "
			    "inheritable=0x%x is not implemented", i,
			    (int)lucd[i].effective, (int)lucd[i].permitted,
			    (int)lucd[i].inheritable);
			return (EPERM);
		}
	}

	return (0);
}

/*
 * PR_GET_AUXV: copy the process auxiliary vector into (buf, size); the
 * return value is the full size of the vector, whatever was copied.  The
 * Linux auxv layout is the same Elf64_Auxinfo pairs the stack holds.
 */
static int
linux_prctl_get_auxv(struct thread *td, void *ubuf, l_ulong size,
    l_ulong arg4, l_ulong arg5)
{
	struct sbuf *sb;
	int error;
	size_t len;

	if (arg4 != 0 || arg5 != 0)
		return (EINVAL);
	sb = sbuf_new_auto();
	error = proc_getauxv(td, td->td_proc, sb);
	if (error == 0)
		error = sbuf_finish(sb);
	if (error == 0) {
		len = sbuf_len(sb);
		if (size > len)
			size = len;
		if (size > 0)
			error = copyout(sbuf_data(sb), ubuf, size);
		if (error == 0)
			td->td_retval[0] = len;
	}
	sbuf_delete(sb);
	return (error);
}

int
linux_prctl(struct thread *td, struct linux_prctl_args *args)
{
	int error = 0, max_size, arg;
	struct proc *p = td->td_proc;
	struct linux_pemuldata *pem;
	char comm[LINUX_MAX_COMM_LEN];
	int pdeath_signal, trace_state;

	switch (args->option) {
	case LINUX_PR_SET_PDEATHSIG:
		if (!LINUX_SIG_VALID(args->arg2))
			return (EINVAL);
		pdeath_signal = linux_to_bsd_signal(args->arg2);
		return (kern_procctl(td, P_PID, 0, PROC_PDEATHSIG_CTL,
		    &pdeath_signal));
	case LINUX_PR_GET_PDEATHSIG:
		error = kern_procctl(td, P_PID, 0, PROC_PDEATHSIG_STATUS,
		    &pdeath_signal);
		if (error != 0)
			return (error);
		pdeath_signal = bsd_to_linux_signal(pdeath_signal);
		return (copyout(&pdeath_signal,
		    (void *)(register_t)args->arg2,
		    sizeof(pdeath_signal)));
	/*
	 * In Linux, this flag controls if set[gu]id processes can coredump.
	 * There are additional semantics imposed on processes that cannot
	 * coredump:
	 * - Such processes can not be ptraced.
	 * - There are some semantics around ownership of process-related files
	 *   in the /proc namespace.
	 *
	 * In FreeBSD, we can (and by default, do) disable setuid coredump
	 * system-wide with 'sugid_coredump.'  We control tracability on a
	 * per-process basis with the procctl PROC_TRACE (=> P2_NOTRACE flag).
	 * By happy coincidence, P2_NOTRACE also prevents coredumping.  So the
	 * procctl is roughly analogous to Linux's DUMPABLE.
	 *
	 * So, proxy these knobs to the corresponding PROC_TRACE setting.
	 */
	case LINUX_PR_GET_DUMPABLE:
		error = kern_procctl(td, P_PID, p->p_pid, PROC_TRACE_STATUS,
		    &trace_state);
		if (error != 0)
			return (error);
		td->td_retval[0] = (trace_state != -1);
		return (0);
	case LINUX_PR_SET_DUMPABLE:
		/*
		 * It is only valid for userspace to set one of these two
		 * flags, and only one at a time.
		 */
		switch (args->arg2) {
		case LINUX_SUID_DUMP_DISABLE:
			trace_state = PROC_TRACE_CTL_DISABLE_EXEC;
			break;
		case LINUX_SUID_DUMP_USER:
			trace_state = PROC_TRACE_CTL_ENABLE;
			break;
		default:
			return (EINVAL);
		}
		return (kern_procctl(td, P_PID, p->p_pid, PROC_TRACE_CTL,
		    &trace_state));
	case LINUX_PR_GET_KEEPCAPS:
		/*
		 * Indicate that we always clear the effective and
		 * permitted capability sets when the user id becomes
		 * non-zero (actually the capability sets are simply
		 * always zero in the current implementation).
		 */
		td->td_retval[0] = 0;
		break;
	case LINUX_PR_SET_KEEPCAPS:
		/*
		 * Ignore requests to keep the effective and permitted
		 * capability sets when the user id becomes non-zero.
		 */
		break;
	case LINUX_PR_SET_NAME:
		/*
		 * To be on the safe side we need to make sure to not
		 * overflow the size a Linux program expects. We already
		 * do this here in the copyin, so that we don't need to
		 * check on copyout.
		 */
		max_size = MIN(sizeof(comm), sizeof(p->p_comm));
		error = copyinstr((void *)(register_t)args->arg2, comm,
		    max_size, NULL);

		/* Linux silently truncates the name if it is too long. */
		if (error == ENAMETOOLONG) {
			/*
			 * XXX: copyinstr() isn't documented to populate the
			 * array completely, so do a copyin() to be on the
			 * safe side. This should be changed in case
			 * copyinstr() is changed to guarantee this.
			 */
			error = copyin((void *)(register_t)args->arg2, comm,
			    max_size - 1);
			comm[max_size - 1] = '\0';
		}
		if (error)
			return (error);

		PROC_LOCK(p);
		strlcpy(p->p_comm, comm, sizeof(p->p_comm));
		PROC_UNLOCK(p);
		break;
	case LINUX_PR_GET_NAME:
		PROC_LOCK(p);
		strlcpy(comm, p->p_comm, sizeof(comm));
		PROC_UNLOCK(p);
		error = copyout(comm, (void *)(register_t)args->arg2,
		    strlen(comm) + 1);
		break;
	case LINUX_PR_GET_SECCOMP:
	case LINUX_PR_SET_SECCOMP:
		/*
		 * Same as returned by Linux without CONFIG_SECCOMP enabled.
		 */
		error = EINVAL;
		break;
	case LINUX_PR_CAPBSET_READ:
		/*
		 * Nothing is ever dropped from the bounding set here, so
		 * every valid capability is "in" it; Linux answers EINVAL
		 * for an unknown capability number.
		 */
		if (args->arg2 > LINUX_CAP_LAST_CAP)
			error = EINVAL;
		else
			td->td_retval[0] = 1;
		break;
	case LINUX_PR_CAP_AMBIENT:
		/*
		 * The ambient set is always empty: nothing is permitted and
		 * inheritable at the same time, so RAISE is EPERM (as on
		 * Linux for a capability outside both sets); IS_SET reports
		 * 0; LOWER and CLEAR_ALL succeed.  Argument validation as
		 * Linux: arg4/arg5 must be 0, CLEAR_ALL takes cap 0.
		 */
		if (args->arg4 != 0 || args->arg5 != 0) {
			error = EINVAL;
			break;
		}
		switch (args->arg2) {
		case LINUX_PR_CAP_AMBIENT_CLEAR_ALL:
			if (args->arg3 != 0)
				error = EINVAL;
			break;
		case LINUX_PR_CAP_AMBIENT_IS_SET:
		case LINUX_PR_CAP_AMBIENT_RAISE:
		case LINUX_PR_CAP_AMBIENT_LOWER:
			if (args->arg3 > LINUX_CAP_LAST_CAP)
				error = EINVAL;
			else if (args->arg2 == LINUX_PR_CAP_AMBIENT_RAISE)
				error = EPERM;
			else
				td->td_retval[0] = 0;
			break;
		default:
			error = EINVAL;
			break;
		}
		break;
	case LINUX_PR_GET_AUXV:
		error = linux_prctl_get_auxv(td, PTRIN(args->arg2), args->arg3,
		    args->arg4, args->arg5);
		break;
	case LINUX_PR_SET_MDWE:
		/*
		 * Memory-deny-write-execute: enforced in mmap(2) and
		 * mprotect(2) (EACCES), inherited on fork unless NO_INHERIT,
		 * kept across exec, and never clearable once set - all as
		 * on Linux.
		 */
		if (args->arg3 != 0 || args->arg4 != 0 || args->arg5 != 0 ||
		    (args->arg2 & ~(LINUX_PR_MDWE_REFUSE_EXEC_GAIN |
		    LINUX_PR_MDWE_NO_INHERIT)) != 0) {
			error = EINVAL;
			break;
		}
		if (args->arg2 == LINUX_PR_MDWE_NO_INHERIT) {
			error = EINVAL;	/* NO_INHERIT needs REFUSE_EXEC_GAIN */
			break;
		}
		pem = pem_find(p);
		LINUX_PEM_XLOCK(pem);
		if (pem->mdwe != 0 && args->arg2 != 0 &&
		    (uint32_t)args->arg2 != pem->mdwe)
			error = EPERM;	/* cannot change once set */
		else if (pem->mdwe != 0 && args->arg2 == 0)
			error = EPERM;	/* cannot clear */
		else
			pem->mdwe = args->arg2;
		LINUX_PEM_XUNLOCK(pem);
		break;
	case LINUX_PR_GET_MDWE:
		if (args->arg2 != 0 || args->arg3 != 0 || args->arg4 != 0 ||
		    args->arg5 != 0) {
			error = EINVAL;
			break;
		}
		pem = pem_find(p);
		td->td_retval[0] = pem->mdwe;
		break;
	case LINUX_PR_MCE_KILL:
		/*
		 * Memory-failure policy: nothing here delivers SIGBUS on
		 * poisoned pages, so the policy is only stored, exactly
		 * validated as Linux does it.
		 */
		if (args->arg4 != 0 || args->arg5 != 0) {
			error = EINVAL;
			break;
		}
		pem = pem_find(p);
		switch (args->arg2) {
		case LINUX_PR_MCE_KILL_CLEAR:
			if (args->arg3 != 0)
				error = EINVAL;
			else
				pem->mce_kill = LINUX_PR_MCE_KILL_DEFAULT;
			break;
		case LINUX_PR_MCE_KILL_SET:
			if (args->arg3 != LINUX_PR_MCE_KILL_EARLY &&
			    args->arg3 != LINUX_PR_MCE_KILL_LATE &&
			    args->arg3 != LINUX_PR_MCE_KILL_DEFAULT)
				error = EINVAL;
			else
				pem->mce_kill = args->arg3;
			break;
		default:
			error = EINVAL;
			break;
		}
		break;
	case LINUX_PR_MCE_KILL_GET:
		if (args->arg2 != 0 || args->arg3 != 0 || args->arg4 != 0 ||
		    args->arg5 != 0) {
			error = EINVAL;
			break;
		}
		pem = pem_find(p);
		td->td_retval[0] = pem->mce_kill;
		break;
	case LINUX_PR_SET_IO_FLUSHER:
		/* CAP_SYS_RESOURCE on Linux; no scheduling effect here. */
		if (args->arg3 != 0 || args->arg4 != 0 || args->arg5 != 0 ||
		    args->arg2 > 1) {
			error = EINVAL;
			break;
		}
		error = priv_check(td, PRIV_PROC_SETRLIMIT);
		if (error != 0) {
			error = EPERM;
			break;
		}
		pem = pem_find(p);
		pem->io_flusher = args->arg2;
		break;
	case LINUX_PR_GET_IO_FLUSHER:
		if (args->arg2 != 0 || args->arg3 != 0 || args->arg4 != 0 ||
		    args->arg5 != 0) {
			error = EINVAL;
			break;
		}
		error = priv_check(td, PRIV_PROC_SETRLIMIT);
		if (error != 0) {
			error = EPERM;
			break;
		}
		pem = pem_find(p);
		td->td_retval[0] = pem->io_flusher;
		break;
	case LINUX_PR_TASK_PERF_EVENTS_DISABLE:
	case LINUX_PR_TASK_PERF_EVENTS_ENABLE:
		/* No perf events can exist: the Linux code paths return 0. */
		break;
	case LINUX_PR_GET_UNALIGN:
	case LINUX_PR_SET_UNALIGN:
	case LINUX_PR_GET_FPEMU:
	case LINUX_PR_SET_FPEMU:
	case LINUX_PR_GET_FPEXC:
	case LINUX_PR_SET_FPEXC:
	case LINUX_PR_GET_ENDIAN:
	case LINUX_PR_SET_ENDIAN:
	case LINUX_PR_MPX_ENABLE_MANAGEMENT:
	case LINUX_PR_MPX_DISABLE_MANAGEMENT:
	case LINUX_PR_SET_FP_MODE:
	case LINUX_PR_GET_FP_MODE:
	case LINUX_PR_SVE_SET_VL:
	case LINUX_PR_SVE_GET_VL:
	case LINUX_PR_PAC_RESET_KEYS:
	case LINUX_PR_SET_TAGGED_ADDR_CTRL:
	case LINUX_PR_GET_TAGGED_ADDR_CTRL:
	case LINUX_PR_SET_SYSCALL_USER_DISPATCH:
	case LINUX_PR_PAC_SET_ENABLED_KEYS:
	case LINUX_PR_PAC_GET_ENABLED_KEYS:
	case LINUX_PR_SCHED_CORE:
	case LINUX_PR_SME_SET_VL:
	case LINUX_PR_SME_GET_VL:
	case LINUX_PR_SET_MEMORY_MERGE:
	case LINUX_PR_GET_MEMORY_MERGE:
	case LINUX_PR_RISCV_V_SET_CONTROL:
	case LINUX_PR_RISCV_V_GET_CONTROL:
	case LINUX_PR_RISCV_SET_ICACHE_FLUSH_CTX:
	case LINUX_PR_PPC_GET_DEXCR:
	case LINUX_PR_PPC_SET_DEXCR:
	case LINUX_PR_GET_SHADOW_STACK_STATUS:
	case LINUX_PR_SET_SHADOW_STACK_STATUS:
	case LINUX_PR_LOCK_SHADOW_STACK_STATUS:
	case LINUX_PR_TIMER_CREATE_RESTORE_IDS:
	case LINUX_PR_FUTEX_HASH:
	case LINUX_PR_RSEQ_SLICE_EXTENSION:
	case LINUX_PR_GET_CFI:
	case LINUX_PR_SET_CFI:
		/*
		 * Other architectures' options, MPX (removed in 5.6), and
		 * features built without their CONFIG_ option: Linux returns
		 * EINVAL for all of these on x86-64 too.  Not logged.
		 */
		error = EINVAL;
		break;
	case LINUX_PR_SET_CHILD_SUBREAPER:
		if (args->arg2 == 0) {
			return (kern_procctl(td, P_PID, 0, PROC_REAP_RELEASE,
			    NULL));
		}

		return (kern_procctl(td, P_PID, 0, PROC_REAP_ACQUIRE,
		    NULL));
	case LINUX_PR_GET_CHILD_SUBREAPER: {
		struct procctl_reaper_status rs;
		l_int val;

		error = kern_procctl(td, P_PID, 0, PROC_REAP_STATUS, &rs);
		if (error != 0)
			return (error);
		val = rs.rs_reaper == p->p_pid ? 1 : 0;
		error = copyout(&val, (void *)(register_t)args->arg2,
		    sizeof(val));
		break;
	}
	case LINUX_PR_SET_NO_NEW_PRIVS:
		arg = args->arg2 == 1 ?
		    PROC_NO_NEW_PRIVS_ENABLE : PROC_NO_NEW_PRIVS_DISABLE;
		error = kern_procctl(td, P_PID, p->p_pid,
		    PROC_NO_NEW_PRIVS_CTL, &arg);
		break;
	case LINUX_PR_GET_NO_NEW_PRIVS:
		error = kern_procctl(td, P_PID, p->p_pid,
		    PROC_NO_NEW_PRIVS_STATUS, &arg);
		if (error != 0)
			return (error);
		/* Linux returns the value as the syscall return */
		td->td_retval[0] = arg == PROC_NO_NEW_PRIVS_ENABLE ? 1 : 0;
		break;
	case LINUX_PR_SET_VMA:
		/*
		 * Anonymous VMA names are optional on Linux.  We have no
		 * corresponding mapping metadata: reject the request quietly,
		 * as Linux does without CONFIG_ANON_VMA_NAME.  Allocators probe
		 * this operation frequently.
		 */
		return (EINVAL);
	case LINUX_PR_SET_PTRACER:
		/* Yama is not built in: Linux returns EINVAL then too. */
		error = EINVAL;
		break;
	case LINUX_PR_GET_TIMING:
		/* Process timing is always statistical, as on Linux. */
		td->td_retval[0] = LINUX_PR_TIMING_STATISTICAL;
		break;
	case LINUX_PR_SET_TIMING:
		/* Linux only accepts PR_TIMING_STATISTICAL here too. */
		if (args->arg2 != LINUX_PR_TIMING_STATISTICAL)
			error = EINVAL;
		break;
#if defined(__i386__) || defined(__amd64__)
	case LINUX_PR_GET_TSC:
		/* rdtsc is always permitted; we cannot trap it. */
		arg = LINUX_PR_TSC_ENABLE;
		error = copyout(&arg, (void *)(register_t)args->arg2,
		    sizeof(arg));
		break;
	case LINUX_PR_SET_TSC:
		/*
		 * PR_TSC_SIGSEGV would require setting CR4.TSD for this
		 * thread; there is no such per-thread control, so only the
		 * current (enabled) mode can be "set".
		 */
		if (args->arg2 != LINUX_PR_TSC_ENABLE)
			error = EINVAL;
		break;
#endif
	case LINUX_PR_GET_SECUREBITS:
		/*
		 * We emulate an empty capability set (see linux_capget()), so
		 * the securebits are the Linux default: none set.
		 */
		td->td_retval[0] = 0;
		break;
	case LINUX_PR_SET_SECUREBITS:
		/* Linux requires CAP_SETPCAP, which no process here holds. */
		error = EPERM;
		break;
	case LINUX_PR_SET_TIMERSLACK:
	case LINUX_PR_GET_TIMERSLACK:
		/*
		 * Timer slack has no native equivalent and we have no
		 * per-thread storage to make GET reflect SET, so neither is
		 * offered rather than returning a made-up value.
		 */
		error = EINVAL;
		break;
	case LINUX_PR_GET_TID_ADDRESS: {
		struct linux_emuldata *em;
		l_uintptr_t tidaddr;

		em = em_find(td);
		KASSERT(em != NULL, ("prctl: emuldata not found.\n"));
		tidaddr = PTROUT(em->child_clear_tid);
		error = copyout(&tidaddr, (void *)(register_t)args->arg2,
		    sizeof(tidaddr));
		break;
	}
	case LINUX_PR_SET_THP_DISABLE:
		/*
		 * Transparent huge pages cannot be disabled per process on
		 * FreeBSD, so only the current (enabled) state can be set;
		 * newer Linux also rejects any non-zero arg3..arg5.
		 */
		if (args->arg3 != 0 || args->arg4 != 0 || args->arg5 != 0 ||
		    args->arg2 != 0)
			error = EINVAL;
		break;
	case LINUX_PR_GET_THP_DISABLE:
		if (args->arg2 != 0 || args->arg3 != 0 || args->arg4 != 0 ||
		    args->arg5 != 0) {
			error = EINVAL;
			break;
		}
		td->td_retval[0] = 0;
		break;
	case LINUX_PR_GET_SPECULATION_CTRL:
	case LINUX_PR_SET_SPECULATION_CTRL:
		/*
		 * No per-task speculation misfeature control is available;
		 * ENODEV is what Linux returns when the architecture does not
		 * implement it.
		 */
		error = ENODEV;
		break;
	case LINUX_PR_CAPBSET_DROP:
	case LINUX_PR_SET_MM:
	default:
		linux_msg(td, "unsupported prctl option %d", args->option);
		error = EINVAL;
		break;
	}

	return (error);
}

int
linux_sched_setparam(struct thread *td,
    struct linux_sched_setparam_args *uap)
{
	struct sched_param sched_param;
	struct thread *tdt;
	int error, policy;

	error = copyin(uap->param, &sched_param, sizeof(sched_param));
	if (error)
		return (error);

	tdt = linux_tdfind(td, uap->pid, -1);
	if (tdt == NULL)
		return (ESRCH);

	if (linux_map_sched_prio) {
		error = kern_sched_getscheduler(td, tdt, &policy);
		if (error)
			goto out;

		switch (policy) {
		case SCHED_OTHER:
			if (sched_param.sched_priority != 0) {
				error = EINVAL;
				goto out;
			}
			sched_param.sched_priority =
			    PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE;
			break;
		case SCHED_FIFO:
		case SCHED_RR:
			if (sched_param.sched_priority < 1 ||
			    sched_param.sched_priority >= LINUX_MAX_RT_PRIO) {
				error = EINVAL;
				goto out;
			}
			/*
			 * Map [1, LINUX_MAX_RT_PRIO - 1] to
			 * [0, RTP_PRIO_MAX - RTP_PRIO_MIN] (rounding down).
			 */
			sched_param.sched_priority =
			    (sched_param.sched_priority - 1) *
			    (RTP_PRIO_MAX - RTP_PRIO_MIN + 1) /
			    (LINUX_MAX_RT_PRIO - 1);
			break;
		}
	}

	error = kern_sched_setparam(td, tdt, &sched_param);
out:	PROC_UNLOCK(tdt->td_proc);
	return (error);
}

int
linux_sched_getparam(struct thread *td,
    struct linux_sched_getparam_args *uap)
{
	struct sched_param sched_param;
	struct thread *tdt;
	int error, policy;

	tdt = linux_tdfind(td, uap->pid, -1);
	if (tdt == NULL)
		return (ESRCH);

	error = kern_sched_getparam(td, tdt, &sched_param);
	if (error) {
		PROC_UNLOCK(tdt->td_proc);
		return (error);
	}

	if (linux_map_sched_prio) {
		error = kern_sched_getscheduler(td, tdt, &policy);
		PROC_UNLOCK(tdt->td_proc);
		if (error)
			return (error);

		switch (policy) {
		case SCHED_OTHER:
			sched_param.sched_priority = 0;
			break;
		case SCHED_FIFO:
		case SCHED_RR:
			/*
			 * Map [0, RTP_PRIO_MAX - RTP_PRIO_MIN] to
			 * [1, LINUX_MAX_RT_PRIO - 1] (rounding up).
			 */
			sched_param.sched_priority =
			    (sched_param.sched_priority *
			    (LINUX_MAX_RT_PRIO - 1) +
			    (RTP_PRIO_MAX - RTP_PRIO_MIN - 1)) /
			    (RTP_PRIO_MAX - RTP_PRIO_MIN) + 1;
			break;
		}
	} else
		PROC_UNLOCK(tdt->td_proc);

	error = copyout(&sched_param, uap->param, sizeof(sched_param));
	return (error);
}

/*
 * Translate a Linux scheduling policy to the native one.  SCHED_BATCH,
 * SCHED_IDLE, SCHED_DEADLINE and SCHED_EXT have no native equivalent
 * (mapping them onto SCHED_OTHER would silently change their semantics),
 * so they are rejected with EINVAL exactly like linux_sched_setscheduler().
 */
static int
linux_to_native_sched_policy(uint32_t lpolicy, int *policy)
{

	switch (lpolicy) {
	case LINUX_SCHED_OTHER:
		*policy = SCHED_OTHER;
		return (0);
	case LINUX_SCHED_FIFO:
		*policy = SCHED_FIFO;
		return (0);
	case LINUX_SCHED_RR:
		*policy = SCHED_RR;
		return (0);
	default:
		return (EINVAL);
	}
}

static uint32_t
native_to_linux_sched_policy(int policy)
{

	switch (policy) {
	case SCHED_FIFO:
		return (LINUX_SCHED_FIFO);
	case SCHED_RR:
		return (LINUX_SCHED_RR);
	default:
		return (LINUX_SCHED_OTHER);
	}
}

/*
 * Map a native static priority of a thread running under `policy' to the
 * Linux one; identical to the mapping in linux_sched_getparam().
 */
static uint32_t
native_to_linux_sched_prio(int policy, int prio)
{

	if (!linux_map_sched_prio)
		return (prio);
	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		/*
		 * Map [0, RTP_PRIO_MAX - RTP_PRIO_MIN] to
		 * [1, LINUX_MAX_RT_PRIO - 1] (rounding up).
		 */
		return ((prio * (LINUX_MAX_RT_PRIO - 1) +
		    (RTP_PRIO_MAX - RTP_PRIO_MIN - 1)) /
		    (RTP_PRIO_MAX - RTP_PRIO_MIN) + 1);
	default:
		return (0);
	}
}

/*
 * Map a Linux static priority for `policy' to the native one; identical to
 * the mapping in linux_sched_setscheduler().  The caller has already
 * validated the Linux range.
 */
static int
linux_to_native_sched_prio(int policy, uint32_t lprio)
{

	if (!linux_map_sched_prio)
		return (lprio);
	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		/*
		 * Map [1, LINUX_MAX_RT_PRIO - 1] to
		 * [0, RTP_PRIO_MAX - RTP_PRIO_MIN] (rounding down).
		 */
		return ((lprio - 1) * (RTP_PRIO_MAX - RTP_PRIO_MIN + 1) /
		    (LINUX_MAX_RT_PRIO - 1));
	default:
		return (PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE);
	}
}

/*
 * Linux copy_struct_from_user(): copy min(usize, ksize) bytes and require
 * that any user bytes beyond our structure are zero (E2BIG otherwise).
 */
static int
linux_copyin_struct(void *kp, size_t ksize, const void *up, size_t usize)
{
	char buf[64];
	const char *ucur;
	size_t rest, n, i;
	int error;

	memset(kp, 0, ksize);
	error = copyin(up, kp, MIN(ksize, usize));
	if (error != 0)
		return (error);
	if (usize <= ksize)
		return (0);
	ucur = (const char *)up + ksize;
	for (rest = usize - ksize; rest > 0; rest -= n, ucur += n) {
		n = MIN(rest, sizeof(buf));
		error = copyin(ucur, buf, n);
		if (error != 0)
			return (error);
		for (i = 0; i < n; i++)
			if (buf[i] != 0)
				return (E2BIG);
	}
	return (0);
}

int
linux_sched_setattr(struct thread *td, struct linux_sched_setattr_args *args)
{
	struct l_sched_attr attr;
	struct sched_param sched_param;
	struct thread *tdt;
	struct proc *p;
	uint32_t size;
	int error, policy, curpolicy;
	bool keep_params, set_nice;

	if (args->attr == NULL || args->pid < 0 || args->flags != 0)
		return (EINVAL);

	error = copyin(args->attr, &size, sizeof(size));
	if (error != 0)
		return (error);
	/* ABI compatibility quirk, from Linux sched_copy_attr(). */
	if (size == 0)
		size = LINUX_SCHED_ATTR_SIZE_VER0;
	if (size < LINUX_SCHED_ATTR_SIZE_VER0 || size > PAGE_SIZE)
		goto err_size;
	error = linux_copyin_struct(&attr, sizeof(attr), args->attr, size);
	if (error == E2BIG)
		goto err_size;
	if (error != 0)
		return (error);

	if ((attr.sched_flags & (LINUX_SCHED_FLAG_UTIL_CLAMP_MIN |
	    LINUX_SCHED_FLAG_UTIL_CLAMP_MAX)) != 0 &&
	    size < LINUX_SCHED_ATTR_SIZE_VER1)
		return (EINVAL);
	if ((int32_t)attr.sched_policy < 0)
		return (EINVAL);
	/* Linux clamps the nice value silently, it does not reject it. */
	if (attr.sched_nice < LINUX_MIN_NICE)
		attr.sched_nice = LINUX_MIN_NICE;
	else if (attr.sched_nice > LINUX_MAX_NICE)
		attr.sched_nice = LINUX_MAX_NICE;

	/*
	 * SCHED_FLAG_RESET_ON_FORK: FreeBSD has no per-thread "revert to
	 * SCHED_OTHER on fork" bit, so accepting it would silently leave
	 * children real-time.  SCHED_FLAG_RECLAIM/DL_OVERRUN only apply to
	 * SCHED_DEADLINE, which we do not have.  SCHED_FLAG_UTIL_CLAMP_*
	 * needs the Linux utilization clamping infrastructure.  All of these
	 * are rejected with EINVAL; only KEEP_POLICY and KEEP_PARAMS, whose
	 * semantics we can honour exactly, are accepted.
	 */
	if ((attr.sched_flags & ~(LINUX_SCHED_FLAG_KEEP_POLICY |
	    LINUX_SCHED_FLAG_KEEP_PARAMS)) != 0)
		return (EINVAL);
	keep_params = (attr.sched_flags & LINUX_SCHED_FLAG_KEEP_PARAMS) != 0;

	tdt = linux_tdfind(td, args->pid, -1);
	if (tdt == NULL)
		return (ESRCH);
	p = tdt->td_proc;

	error = kern_sched_getscheduler(td, tdt, &curpolicy);
	if (error != 0)
		goto out;
	if ((attr.sched_flags & LINUX_SCHED_FLAG_KEEP_POLICY) != 0)
		policy = curpolicy;
	else {
		error = linux_to_native_sched_policy(attr.sched_policy,
		    &policy);
		if (error != 0)
			goto out;
	}

	if (keep_params) {
		error = kern_sched_getparam(td, tdt, &sched_param);
		if (error != 0)
			goto out;
		if (policy != curpolicy) {
			/*
			 * Linux re-derives the parameters for the new
			 * policy from the current ones.
			 */
			sched_param.sched_priority = linux_to_native_sched_prio(
			    policy, native_to_linux_sched_prio(curpolicy,
			    sched_param.sched_priority));
		}
	} else {
		/* Linux: priority must be 0 for, and only for, non-RT. */
		if (attr.sched_priority >= LINUX_MAX_RT_PRIO ||
		    ((policy == SCHED_FIFO || policy == SCHED_RR) !=
		    (attr.sched_priority != 0))) {
			error = EINVAL;
			goto out;
		}
		sched_param.sched_priority =
		    linux_to_native_sched_prio(policy, attr.sched_priority);
	}

	/*
	 * Nice is a process attribute on FreeBSD and is applied after the
	 * scheduler change below (kern_setpriority() takes the proc lock
	 * itself).  Do the permission checks up front so the two updates
	 * either both happen or neither does, as on Linux.
	 */
	set_nice = policy == SCHED_OTHER && !keep_params &&
	    attr.sched_nice != p->p_nice;
	if (set_nice) {
		error = p_cansched(td, p);
		if (error == 0 && attr.sched_nice < p->p_nice)
			error = priv_check(td, PRIV_SCHED_SETPRIORITY);
		if (error != 0) {
			error = EPERM;
			goto out;
		}
	}

	/*
	 * kern_sched_setscheduler() demands PRIV_SCHED_SETPOLICY even for
	 * SCHED_OTHER, whereas Linux lets an unprivileged caller keep a
	 * normal thread normal and only adjust nice.  An OTHER -> OTHER
	 * request with priority 0 changes nothing but nice, so apply only
	 * the Linux permission model to it.
	 */
	if (policy == SCHED_OTHER && curpolicy == SCHED_OTHER)
		error = p_cansched(td, p);
	else
		error = kern_sched_setscheduler(td, tdt, policy, &sched_param);
out:
	PROC_UNLOCK(p);
	if (error == 0 && set_nice) {
		error = kern_setpriority(td, PRIO_PROCESS, p->p_pid,
		    attr.sched_nice);
		if (error == EACCES)
			error = EPERM;
	}
	return (error);

err_size:
	size = sizeof(attr);
	(void)copyout(&size, &((struct l_sched_attr *)args->attr)->size,
	    sizeof(size));
	return (E2BIG);
}

int
linux_sched_getattr(struct thread *td, struct linux_sched_getattr_args *args)
{
	struct l_sched_attr attr;
	struct sched_param sched_param;
	struct thread *tdt;
	int error, policy, nice;

	if (args->attr == NULL || args->size > PAGE_SIZE ||
	    args->size < LINUX_SCHED_ATTR_SIZE_VER0 || args->flags != 0 ||
	    args->pid < 0)
		return (EINVAL);

	tdt = linux_tdfind(td, args->pid, -1);
	if (tdt == NULL)
		return (ESRCH);
	error = kern_sched_getscheduler(td, tdt, &policy);
	if (error == 0)
		error = kern_sched_getparam(td, tdt, &sched_param);
	nice = tdt->td_proc->p_nice;
	PROC_UNLOCK(tdt->td_proc);
	if (error != 0)
		return (error);

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = native_to_linux_sched_policy(policy);
	if (policy == SCHED_FIFO || policy == SCHED_RR)
		attr.sched_priority = native_to_linux_sched_prio(policy,
		    sched_param.sched_priority);
	else
		attr.sched_nice = nice;

	/*
	 * Linux sched_attr_copy_to_user(): report min(usize, sizeof) in
	 * attr.size and copy out exactly that many bytes.
	 */
	attr.size = MIN(args->size, sizeof(attr));
	return (copyout(&attr, args->attr, attr.size));
}

/*
 * Get affinity of a process.
 */
int
linux_sched_getaffinity(struct thread *td,
    struct linux_sched_getaffinity_args *args)
{
	struct thread *tdt;
	cpuset_t *mask;
	size_t size;
	int error;
	id_t tid;

	tdt = linux_tdfind(td, args->pid, -1);
	if (tdt == NULL)
		return (ESRCH);
	tid = tdt->td_tid;
	PROC_UNLOCK(tdt->td_proc);

	mask = malloc(sizeof(cpuset_t), M_LINUX, M_WAITOK | M_ZERO);
	size = min(args->len, sizeof(cpuset_t));
	error = kern_cpuset_getaffinity(td, CPU_LEVEL_WHICH, CPU_WHICH_TID,
	    tid, size, mask);
	if (error == ERANGE)
		error = EINVAL;
 	if (error == 0)
		error = copyout(mask, args->user_mask_ptr, size);
	if (error == 0)
		td->td_retval[0] = size;
	free(mask, M_LINUX);
	return (error);
}

/*
 *  Set affinity of a process.
 */
int
linux_sched_setaffinity(struct thread *td,
    struct linux_sched_setaffinity_args *args)
{
	struct thread *tdt;
	cpuset_t *mask;
	int cpu, error;
	size_t len;
	id_t tid;

	tdt = linux_tdfind(td, args->pid, -1);
	if (tdt == NULL)
		return (ESRCH);
	tid = tdt->td_tid;
	PROC_UNLOCK(tdt->td_proc);

	len = min(args->len, sizeof(cpuset_t));
	mask = malloc(sizeof(cpuset_t), M_TEMP, M_WAITOK | M_ZERO);
	error = copyin(args->user_mask_ptr, mask, len);
	if (error != 0)
		goto out;
	/* Linux ignore high bits */
	CPU_FOREACH_ISSET(cpu, mask)
		if (cpu > mp_maxid)
			CPU_CLR(cpu, mask);

	error = kern_cpuset_setaffinity(td, CPU_LEVEL_WHICH, CPU_WHICH_TID,
	    tid, mask);
	if (error == EDEADLK)
		error = EINVAL;
out:
	free(mask, M_TEMP);
	return (error);
}

struct linux_rlimit64 {
	uint64_t	rlim_cur;
	uint64_t	rlim_max;
};

int
linux_prlimit64(struct thread *td, struct linux_prlimit64_args *args)
{
	struct rlimit rlim, nrlim;
	struct linux_rlimit64 lrlim;
	struct proc *p;
	u_int which;
	int flags;
	int error;

	if (args->new == NULL && args->old != NULL) {
		if (linux_get_dummy_limit(td, args->resource, &rlim)) {
			lrlim.rlim_cur = rlim.rlim_cur;
			lrlim.rlim_max = rlim.rlim_max;
			return (copyout(&lrlim, args->old, sizeof(lrlim)));
		}
	}

	if (args->new != NULL) {
		/*
		 * Note. Unlike FreeBSD where rlim is signed 64-bit Linux
		 * rlim is unsigned 64-bit. FreeBSD treats negative limits
		 * as INFINITY so we do not need a conversion even.
		 */
		error = copyin(args->new, &nrlim, sizeof(nrlim));
		if (error != 0)
			return (error);
		/* Only the calling process' dummy limits are settable. */
		if (args->pid == 0 || args->pid == td->td_proc->p_pid) {
			if (linux_get_dummy_limit(td, args->resource, &rlim)) {
				if (args->old != NULL) {
					lrlim.rlim_cur = rlim.rlim_cur;
					lrlim.rlim_max = rlim.rlim_max;
					error = copyout(&lrlim, args->old,
					    sizeof(lrlim));
					if (error != 0)
						return (error);
				}
				if (linux_set_dummy_limit(td, args->resource,
				    &nrlim, &error))
					return (error);
			}
		}
	}

	if (args->resource >= LINUX_RLIM_NLIMITS)
		return (EINVAL);

	which = linux_to_bsd_resource[args->resource];
	if (which == -1)
		return (EINVAL);

	flags = PGET_HOLD | PGET_NOTWEXIT;
	if (args->new != NULL)
		flags |= PGET_CANDEBUG;
	else
		flags |= PGET_CANSEE;
	if (args->pid == 0) {
		p = td->td_proc;
		PHOLD(p);
	} else {
		error = pget(args->pid, flags, &p);
		if (error != 0)
			return (error);
	}
	if (args->old != NULL) {
		PROC_LOCK(p);
		lim_rlimit_proc(p, which, &rlim);
		PROC_UNLOCK(p);
		if (rlim.rlim_cur == RLIM_INFINITY)
			lrlim.rlim_cur = LINUX_RLIM_INFINITY;
		else
			lrlim.rlim_cur = rlim.rlim_cur;
		if (rlim.rlim_max == RLIM_INFINITY)
			lrlim.rlim_max = LINUX_RLIM_INFINITY;
		else
			lrlim.rlim_max = rlim.rlim_max;
		error = copyout(&lrlim, args->old, sizeof(lrlim));
		if (error != 0)
			goto out;
	}

	if (args->new != NULL)
		error = kern_proc_setrlimit(td, p, which, &nrlim);

 out:
	PRELE(p);
	return (error);
}

int
linux_pselect6(struct thread *td, struct linux_pselect6_args *args)
{
	struct timespec ts, *tsp;
	int error;

	if (args->tsp != NULL) {
		error = linux_get_timespec(&ts, args->tsp);
		if (error != 0)
			return (error);
		tsp = &ts;
	} else
		tsp = NULL;

	error = linux_common_pselect6(td, args->nfds, args->readfds,
	    args->writefds, args->exceptfds, tsp, args->sig);

	if (args->tsp != NULL)
		linux_put_timespec(&ts, args->tsp);
	return (error);
}

static int
linux_common_pselect6(struct thread *td, l_int nfds, l_fd_set *readfds,
    l_fd_set *writefds, l_fd_set *exceptfds, struct timespec *tsp,
    l_uintptr_t *sig)
{
	struct timeval utv, tv0, tv1, *tvp;
	struct l_pselect6arg lpse6;
	sigset_t *ssp;
	sigset_t ss;
	int error;

	ssp = NULL;
	if (sig != NULL) {
		error = copyin(sig, &lpse6, sizeof(lpse6));
		if (error != 0)
			return (error);
		error = linux_copyin_sigset(td, PTRIN(lpse6.ss),
		    lpse6.ss_len, &ss, &ssp);
		if (error != 0)
		    return (error);
	} else
		ssp = NULL;

	/*
	 * Currently glibc changes nanosecond number to microsecond.
	 * This mean losing precision but for now it is hardly seen.
	 */
	if (tsp != NULL) {
		TIMESPEC_TO_TIMEVAL(&utv, tsp);
		if (itimerfix(&utv))
			return (EINVAL);

		microtime(&tv0);
		tvp = &utv;
	} else
		tvp = NULL;

	error = kern_pselect(td, nfds, readfds, writefds,
	    exceptfds, tvp, ssp, LINUX_NFDBITS);

	if (tsp != NULL) {
		/*
		 * Compute how much time was left of the timeout,
		 * by subtracting the current time and the time
		 * before we started the call, and subtracting
		 * that result from the user-supplied value.
		 */
		microtime(&tv1);
		timevalsub(&tv1, &tv0);
		timevalsub(&utv, &tv1);
		if (utv.tv_sec < 0)
			timevalclear(&utv);
		TIMEVAL_TO_TIMESPEC(&utv, tsp);
	}
	return (error);
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_pselect6_time64(struct thread *td,
    struct linux_pselect6_time64_args *args)
{
	struct timespec ts, *tsp;
	int error;

	if (args->tsp != NULL) {
		error = linux_get_timespec64(&ts, args->tsp);
		if (error != 0)
			return (error);
		tsp = &ts;
	} else
		tsp = NULL;

	error = linux_common_pselect6(td, args->nfds, args->readfds,
	    args->writefds, args->exceptfds, tsp, args->sig);

	if (args->tsp != NULL)
		linux_put_timespec64(&ts, args->tsp);
	return (error);
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

int
linux_ppoll(struct thread *td, struct linux_ppoll_args *args)
{
	struct timespec uts, *tsp;
	int error;

	if (args->tsp != NULL) {
		error = linux_get_timespec(&uts, args->tsp);
		if (error != 0)
			return (error);
		tsp = &uts;
	} else
		tsp = NULL;

	error = linux_common_ppoll(td, args->fds, args->nfds, tsp,
	    args->sset, args->ssize);
	if (error == 0 && args->tsp != NULL)
		error = linux_put_timespec(&uts, args->tsp);
	return (error);
}

static int
linux_common_ppoll(struct thread *td, struct pollfd *fds, uint32_t nfds,
    struct timespec *tsp, l_sigset_t *sset, l_size_t ssize)
{
	struct timespec ts0, ts1;
	struct pollfd stackfds[32];
	struct pollfd *kfds;
 	sigset_t *ssp;
 	sigset_t ss;
 	int error;

	if (kern_poll_maxfds(nfds))
		return (EINVAL);
	if (sset != NULL) {
		error = linux_copyin_sigset(td, sset, ssize, &ss, &ssp);
		if (error != 0)
		    return (error);
	} else
		ssp = NULL;
	if (tsp != NULL)
		nanotime(&ts0);

	if (nfds > nitems(stackfds))
		kfds = mallocarray(nfds, sizeof(*kfds), M_TEMP, M_WAITOK);
	else
		kfds = stackfds;
	error = linux_pollin(td, kfds, fds, nfds);
	if (error != 0)
		goto out;

	error = kern_poll_kfds(td, kfds, nfds, tsp, ssp);
	if (error == 0)
		error = linux_pollout(td, kfds, fds, nfds);

	if (error == 0 && tsp != NULL) {
		if (td->td_retval[0]) {
			nanotime(&ts1);
			timespecsub(&ts1, &ts0, &ts1);
			timespecsub(tsp, &ts1, tsp);
			if (tsp->tv_sec < 0)
				timespecclear(tsp);
		} else
			timespecclear(tsp);
	}

out:
	if (nfds > nitems(stackfds))
		free(kfds, M_TEMP);
	return (error);
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_ppoll_time64(struct thread *td, struct linux_ppoll_time64_args *args)
{
	struct timespec uts, *tsp;
	int error;

	if (args->tsp != NULL) {
		error = linux_get_timespec64(&uts, args->tsp);
		if (error != 0)
			return (error);
		tsp = &uts;
	} else
 		tsp = NULL;
	error = linux_common_ppoll(td, args->fds, args->nfds, tsp,
	    args->sset, args->ssize);
	if (error == 0 && args->tsp != NULL)
		error = linux_put_timespec64(&uts, args->tsp);
	return (error);
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

static int
linux_pollin(struct thread *td, struct pollfd *fds, struct pollfd *ufds, u_int nfd)
{
	int error;
	u_int i;

	error = copyin(ufds, fds, nfd * sizeof(*fds));
	if (error != 0)
		return (error);

	for (i = 0; i < nfd; i++) {
		if (fds->events != 0)
			linux_to_bsd_poll_events(td, fds->fd,
			    fds->events, &fds->events);
		fds++;
	}
	return (0);
}

static int
linux_pollout(struct thread *td, struct pollfd *fds, struct pollfd *ufds, u_int nfd)
{
	int error = 0;
	u_int i, n = 0;

	for (i = 0; i < nfd; i++) {
		if (fds->revents != 0) {
			bsd_to_linux_poll_events(fds->revents,
			    &fds->revents);
			n++;
		}
		error = copyout(&fds->revents, &ufds->revents,
		    sizeof(ufds->revents));
		if (error)
			return (error);
		fds++;
		ufds++;
	}
	td->td_retval[0] = n;
	return (0);
}

static int
linux_sched_rr_get_interval_common(struct thread *td, pid_t pid,
    struct timespec *ts)
{
	struct thread *tdt;
	int error;

	/*
	 * According to man in case the invalid pid specified
	 * EINVAL should be returned.
	 */
	if (pid < 0)
		return (EINVAL);

	tdt = linux_tdfind(td, pid, -1);
	if (tdt == NULL)
		return (ESRCH);

	error = kern_sched_rr_get_interval_td(td, tdt, ts);
	PROC_UNLOCK(tdt->td_proc);
	return (error);
}

int
linux_sched_rr_get_interval(struct thread *td,
    struct linux_sched_rr_get_interval_args *uap)
{
	struct timespec ts;
	int error;

	error = linux_sched_rr_get_interval_common(td, uap->pid, &ts);
	if (error != 0)
		return (error);
	return (linux_put_timespec(&ts, uap->interval));
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_sched_rr_get_interval_time64(struct thread *td,
    struct linux_sched_rr_get_interval_time64_args *uap)
{
	struct timespec ts;
	int error;

	error = linux_sched_rr_get_interval_common(td, uap->pid, &ts);
	if (error != 0)
		return (error);
	return (linux_put_timespec64(&ts, uap->interval));
}
#endif

/*
 * In case when the Linux thread is the initial thread in
 * the thread group thread id is equal to the process id.
 * Glibc depends on this magic (assert in pthread_getattr_np.c).
 */
struct thread *
linux_tdfind(struct thread *td, lwpid_t tid, pid_t pid)
{
	struct linux_emuldata *em;
	struct thread *tdt;
	struct proc *p;

	tdt = NULL;
	if (tid == 0 || tid == td->td_tid) {
		if (pid != -1 && td->td_proc->p_pid != pid)
			return (NULL);
		PROC_LOCK(td->td_proc);
		return (td);
	} else if (tid > PID_MAX)
		return (tdfind(tid, pid));

	/*
	 * Initial thread where the tid equal to the pid.
	 */
	p = pfind(tid);
	if (p != NULL) {
		if (SV_PROC_ABI(p) != SV_ABI_LINUX ||
		    (pid != -1 && tid != pid)) {
			/*
			 * p is not a Linuxulator process.
			 */
			PROC_UNLOCK(p);
			return (NULL);
		}
		FOREACH_THREAD_IN_PROC(p, tdt) {
			em = em_find(tdt);
			if (tid == em->em_tid)
				return (tdt);
		}
		PROC_UNLOCK(p);
	}
	return (NULL);
}

void
linux_to_bsd_waitopts(int options, int *bsdopts)
{

	if (options & LINUX_WNOHANG)
		*bsdopts |= WNOHANG;
	if (options & LINUX_WUNTRACED)
		*bsdopts |= WUNTRACED;
	if (options & LINUX_WEXITED)
		*bsdopts |= WEXITED;
	if (options & LINUX_WCONTINUED)
		*bsdopts |= WCONTINUED;
	if (options & LINUX_WNOWAIT)
		*bsdopts |= WNOWAIT;

	/*
	 * __WCLONE: only children whose exit signal is not SIGCHLD;
	 * __WALL: both kinds.  __WNOTHREAD (children of this thread only)
	 * is a subset of the per-process wait FreeBSD always does.
	 */
	if (options & __WALL)
		*bsdopts |= WLINUXALL;
	else if (options & __WCLONE)
		*bsdopts |= WLINUXCLONE;
}

/*
 * MCL_ONFAULT (Linux 4.4) wires pages as they are touched; wiring them
 * eagerly is a strict superset, as for mlock2(2).
 */
int
linux_mlockall(struct thread *td, struct linux_mlockall_args *args)
{
	struct mlockall_args bargs;

	if ((args->how & ~(LINUX_MCL_CURRENT | LINUX_MCL_FUTURE |
	    LINUX_MCL_ONFAULT)) != 0 || args->how == 0)
		return (EINVAL);
	/* Linux: ONFAULT alone (without CURRENT or FUTURE) is EINVAL. */
	if ((args->how & (LINUX_MCL_CURRENT | LINUX_MCL_FUTURE)) == 0)
		return (EINVAL);
	bargs.how = 0;
	if ((args->how & LINUX_MCL_CURRENT) != 0)
		bargs.how |= MCL_CURRENT;
	if ((args->how & LINUX_MCL_FUTURE) != 0)
		bargs.how |= MCL_FUTURE;
	return (sys_mlockall(td, &bargs));
}

int
linux_getrandom(struct thread *td, struct linux_getrandom_args *args)
{
	struct uio uio;
	struct iovec iov;
	int error;

	if (args->flags & ~(LINUX_GRND_NONBLOCK | LINUX_GRND_RANDOM |
	    LINUX_GRND_INSECURE))
		return (EINVAL);
	/* Linux: INSECURE (never block) and RANDOM are mutually exclusive. */
	if ((args->flags & (LINUX_GRND_INSECURE | LINUX_GRND_RANDOM)) ==
	    (LINUX_GRND_INSECURE | LINUX_GRND_RANDOM))
		return (EINVAL);
	if (args->count > INT_MAX)
		args->count = INT_MAX;

	iov.iov_base = args->buf;
	iov.iov_len = args->count;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = iov.iov_len;
	uio.uio_segflg = UIO_USERSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = td;

	error = read_random_uio(&uio,
	    (args->flags & (LINUX_GRND_NONBLOCK | LINUX_GRND_INSECURE)) != 0);
	if (error == 0)
		td->td_retval[0] = args->count - uio.uio_resid;
	return (error);
}

int
linux_mincore(struct thread *td, struct linux_mincore_args *args)
{

	/* Needs to be page-aligned */
	if (args->start & PAGE_MASK)
		return (EINVAL);
	return (kern_mincore(td, args->start, args->len, args->vec));
}

#define	SYSLOG_TAG	"<6>"

/*
 * SYSLOG_ACTION_READ_ALL: copy the whole message buffer out, tagging each
 * line with a Linux-style priority prefix.
 */
static int
linux_syslog_read_all(struct thread *td, char *ubuf, int len)
{
	char buf[128], *src, *dst;
	u_int seq;
	int buflen, error;

	if (len < 6) {
		td->td_retval[0] = 0;
		return (0);
	}

	error = priv_check(td, PRIV_MSGBUF);
	if (error)
		return (error);

	mtx_lock(&msgbuf_lock);
	msgbuf_peekbytes(msgbufp, NULL, 0, &seq);
	mtx_unlock(&msgbuf_lock);

	dst = ubuf;
	error = copyout(&SYSLOG_TAG, dst, sizeof(SYSLOG_TAG));
	/* The -1 is to skip the trailing '\0'. */
	dst += sizeof(SYSLOG_TAG) - 1;

	while (error == 0) {
		mtx_lock(&msgbuf_lock);
		buflen = msgbuf_peekbytes(msgbufp, buf, sizeof(buf), &seq);
		mtx_unlock(&msgbuf_lock);

		if (buflen == 0)
			break;

		for (src = buf; src < buf + buflen && error == 0; src++) {
			if (*src == '\0')
				continue;

			if (dst >= ubuf + len)
				goto out;

			error = copyout(src, dst, 1);
			dst++;

			if (*src == '\n' && *(src + 1) != '<' &&
			    dst + sizeof(SYSLOG_TAG) < ubuf + len) {
				error = copyout(&SYSLOG_TAG,
				    dst, sizeof(SYSLOG_TAG));
				dst += sizeof(SYSLOG_TAG) - 1;
			}
		}
	}
out:
	td->td_retval[0] = dst - ubuf;
	return (error);
}

/*
 * Linux gates everything but READ_ALL and SIZE_BUFFER on CAP_SYSLOG.  The
 * closest native equivalent of clearing the message buffer is writing the
 * kern.msgbuf_clear sysctl, which is CTLFLAG_SECURE and root-only; demand
 * exactly that.
 */
static int
linux_syslog_priv_check(struct thread *td)
{
	int error;

	error = priv_check(td, PRIV_SYSCTL_WRITE);
	if (error == 0 && securelevel_gt(td->td_ucred, 0) != 0)
		error = EPERM;
	return (error);
}

int
linux_syslog(struct thread *td, struct linux_syslog_args *args)
{
	int error;

	switch (args->type) {
	case LINUX_SYSLOG_ACTION_CLOSE:
	case LINUX_SYSLOG_ACTION_OPEN:
		/* Historical no-ops on Linux, allowed to everybody. */
		td->td_retval[0] = 0;
		return (0);
	case LINUX_SYSLOG_ACTION_READ_ALL:
	case LINUX_SYSLOG_ACTION_READ_CLEAR:
		if (args->buf == NULL || args->len < 0)
			return (EINVAL);
		if (args->type == LINUX_SYSLOG_ACTION_READ_CLEAR) {
			error = linux_syslog_priv_check(td);
			if (error != 0)
				return (error);
		}
		if (args->len == 0) {
			td->td_retval[0] = 0;
			return (0);
		}
		error = linux_syslog_read_all(td, args->buf, args->len);
		if (error != 0 || args->type == LINUX_SYSLOG_ACTION_READ_ALL)
			return (error);
		/* READ_CLEAR clears after a successful read. */
		mtx_lock(&msgbuf_lock);
		msgbuf_clear(msgbufp);
		mtx_unlock(&msgbuf_lock);
		return (0);
	case LINUX_SYSLOG_ACTION_CLEAR:
		error = linux_syslog_priv_check(td);
		if (error != 0)
			return (error);
		mtx_lock(&msgbuf_lock);
		msgbuf_clear(msgbufp);
		mtx_unlock(&msgbuf_lock);
		td->td_retval[0] = 0;
		return (0);
	case LINUX_SYSLOG_ACTION_SIZE_BUFFER:
		error = priv_check(td, PRIV_MSGBUF);
		if (error != 0)
			return (error);
		td->td_retval[0] = msgbufp->msg_size;
		return (0);
	case LINUX_SYSLOG_ACTION_READ:
	case LINUX_SYSLOG_ACTION_SIZE_UNREAD:
		/*
		 * These need a per-system read cursor into the message
		 * buffer plus a wakeup when new messages arrive, which the
		 * native msgbuf does not export.
		 */
		error = linux_syslog_priv_check(td);
		if (error != 0)
			return (error);
		linux_msg(td, "syslog unsupported type 0x%x", args->type);
		return (EINVAL);
	case LINUX_SYSLOG_ACTION_CONSOLE_OFF:
	case LINUX_SYSLOG_ACTION_CONSOLE_ON:
	case LINUX_SYSLOG_ACTION_CONSOLE_LEVEL:
		/*
		 * The native kernel has no console log level: printf(9)
		 * output always reaches the console.  Pretending to honour
		 * these would leave the caller believing the console was
		 * quietened, so they are refused (EPERM for callers Linux
		 * would refuse anyway).
		 */
		error = linux_syslog_priv_check(td);
		if (error != 0)
			return (error);
		linux_msg(td, "syslog unsupported type 0x%x", args->type);
		return (EINVAL);
	default:
		return (EINVAL);
	}
}

int
linux_getcpu(struct thread *td, struct linux_getcpu_args *args)
{
	int cpu, error, node;

	cpu = td->td_oncpu; /* Make sure it doesn't change during copyout(9) */
	error = 0;
	node = cpuid_to_pcpu[cpu]->pc_domain;

	if (args->cpu != NULL)
		error = copyout(&cpu, args->cpu, sizeof(l_int));
	if (args->node != NULL)
		error = copyout(&node, args->node, sizeof(l_int));
	return (error);
}

static int
linux_process_vm_rw(struct thread *td, l_pid_t pid,
    const struct iovec *lvec, l_ulong liovcnt,
    const struct iovec *rvec_uptr, l_ulong riovcnt,
    l_ulong flags, int rw)
{
	struct proc *p;
	struct iovec *rvec;
	struct uio *luio;
	char buf[PAGE_SIZE];
	ssize_t done;
	int error;
	size_t local_moved, remote_moved;

	if (flags != 0)
		return (EINVAL);
	if (riovcnt > UIO_MAXIOV || liovcnt > UIO_MAXIOV)
		return (EINVAL);
	if (riovcnt == 0 || liovcnt == 0)
		return (0);

	/* Import local iovecs. */
	luio = NULL;
#ifdef COMPAT_LINUX32
	error = freebsd32_copyinuio(PTRIN(lvec), liovcnt, &luio);
#else
	error = copyinuio(lvec, liovcnt, &luio);
#endif
	if (error != 0)
		return (error);
	luio->uio_rw = rw == 0 ? UIO_READ : UIO_WRITE;
	luio->uio_segflg = UIO_USERSPACE;
	luio->uio_td = td;

	/*
	 * Import remote iovecs.  These describe addresses in the
	 * target process, so copy in only the iovec metadata.
	 */
	rvec = NULL;
#ifdef COMPAT_LINUX32
	error = freebsd32_copyiniov(PTRIN(rvec_uptr), riovcnt, &rvec, EINVAL);
#else
	error = copyiniov(__DECONST(struct iovec *, rvec_uptr), riovcnt,
	    &rvec, EINVAL);
#endif
	if (error != 0)
		goto out;

	/* Find target process, check permission. */
	p = NULL;
	error = pget(pid, PGET_HOLD | PGET_CANDEBUG | PGET_NOTWEXIT, &p);
	if (error != 0) {
		if (error == EACCES)
			error = EPERM;
		goto out;
	}

	/* Transfer data between local and remote iovecs. */
	done = 0;
	for (l_ulong i = 0; i < riovcnt && luio->uio_resid > 0; i++) {
		vm_offset_t raddr = (vm_offset_t)rvec[i].iov_base;
		size_t rlen = rvec[i].iov_len;

		while (rlen > 0 && luio->uio_resid > 0) {
			struct iovec riov;
			struct uio ruio;
			int local_error;
			size_t resid_before;
			size_t chunk = MIN(rlen, MIN(PAGE_SIZE,
			    luio->uio_resid));

			riov.iov_base = buf;
			riov.iov_len = chunk;
			ruio.uio_iov = &riov;
			ruio.uio_iovcnt = 1;
			ruio.uio_offset = raddr;
			ruio.uio_resid = chunk;
			ruio.uio_segflg = UIO_SYSSPACE;
			ruio.uio_td = td;

			if (rw != 0) {
				/* writev: local → buf → remote */
				ruio.uio_rw = UIO_WRITE;
				resid_before = luio->uio_resid;
				local_error = uiomove(buf, chunk, luio);
				local_moved = resid_before - luio->uio_resid;
				if (local_moved == 0) {
					error = local_error;
					break;
				}
				riov.iov_len = local_moved;
				ruio.uio_resid = local_moved;
				error = proc_rwmem(p, &ruio);
				remote_moved = local_moved - ruio.uio_resid;
				done += remote_moved;
				raddr += remote_moved;
				rlen -= remote_moved;
				if (error == 0 && remote_moved != local_moved)
					error = EFAULT;
				if (error == 0 && local_error != 0)
					error = local_error;
			} else {
				/* readv: remote → buf → local */
				ruio.uio_rw = UIO_READ;
				error = proc_rwmem(p, &ruio);
				remote_moved = chunk - ruio.uio_resid;
				if (remote_moved == 0)
					break;
				resid_before = luio->uio_resid;
				local_error = uiomove(buf, remote_moved, luio);
				if (local_error != 0 &&
				    luio->uio_resid == resid_before) {
					error = local_error;
					break;
				}
				local_moved = resid_before - luio->uio_resid;
				done += local_moved;
				raddr += local_moved;
				rlen -= local_moved;
				if (error == 0 && local_moved != remote_moved)
					error = EFAULT;
				if (error == 0 && local_error != 0)
					error = local_error;
			}
			if (error != 0 || local_moved != remote_moved)
				break;
		}
		if (error != 0)
			break;
	}

	if (p != NULL)
		PRELE(p);

	/*
	 * Like Linux: if any data was transferred, return byte count
	 * even if an error occurred partway through.
	 */
	if (done > 0) {
		td->td_retval[0] = done;
		error = 0;
	}

out:
	if (rvec != NULL)
		free(rvec, M_IOV);
	if (luio != NULL)
		freeuio(luio);
	return (error);
}

/* Pack a FreeBSD fsid into a Linux 64-bit mount id. */
static uint64_t
linux_mnt_id(const struct mount *mp)
{

	return (((uint64_t)(uint32_t)mp->mnt_stat.f_fsid.val[0] << 32) |
	    (uint32_t)mp->mnt_stat.f_fsid.val[1]);
}

/* Is child's mount point nested under parent's mount point (not equal)? */
static bool
linux_mnt_is_child(const char *parent, const char *child)
{
	size_t plen;

	plen = strlen(parent);
	if (plen == 0 || strncmp(parent, child, plen) != 0)
		return (false);
	if (child[plen] == '\0')
		return (false);			/* same mount */
	/* "/" is a prefix of everything; otherwise require a '/' boundary. */
	return (plen == 1 || child[plen] == '/');
}

static int
linux_copyin_mnt_id_req(struct l_mnt_id_req *req, const void *ureq)
{
	uint32_t size;
	int error;

	memset(req, 0, sizeof(*req));
	error = copyin(ureq, &size, sizeof(size));
	if (error != 0)
		return (error);
	if (size < LINUX_MNT_ID_REQ_SIZE_VER0)
		return (EINVAL);
	if (size > sizeof(*req))
		size = sizeof(*req);
	return (copyin(ureq, req, size));
}

int
linux_listmount(struct thread *td, struct linux_listmount_args *args)
{
	struct l_mnt_id_req req;
	struct mount *mp;
	uint64_t *ids, target;
	char tgtpath[MNAMELEN];
	l_size_t nr, count, cap;
	uint64_t cursor;
	bool have_cursor, filter;
	int error;

	if ((args->flags & ~LINUX_LISTMOUNT_REVERSE) != 0)
		return (EINVAL);
	error = linux_copyin_mnt_id_req(&req, args->req);
	if (error != 0)
		return (error);
	nr = args->nr_mnt_ids;
	if (nr == 0)
		return (0);
	cap = nr > 1024 ? 1024 : nr;		/* bound the kernel allocation */
	ids = malloc(cap * sizeof(uint64_t), M_LINUX, M_WAITOK);
	count = 0;
	target = req.mnt_id;
	cursor = req.param;
	have_cursor = cursor != 0;
	filter = target != LINUX_LSMT_ROOT;
	tgtpath[0] = '\0';

	mtx_lock(&mountlist_mtx);
	if (filter) {				/* find the target's mount point */
		TAILQ_FOREACH(mp, &mountlist, mnt_list) {
			if (linux_mnt_id(mp) == target) {
				strlcpy(tgtpath, mp->mnt_stat.f_mntonname,
				    sizeof(tgtpath));
				break;
			}
		}
		if (tgtpath[0] == '\0') {
			mtx_unlock(&mountlist_mtx);
			free(ids, M_LINUX);
			return (ENOENT);
		}
	}
#define	LM_EACH(mp)							\
	((args->flags & LINUX_LISTMOUNT_REVERSE) != 0 ?			\
	    TAILQ_LAST(&mountlist, mntlist) : TAILQ_FIRST(&mountlist))
	for (mp = LM_EACH(mp); mp != NULL && count < cap;
	    mp = ((args->flags & LINUX_LISTMOUNT_REVERSE) != 0 ?
	    TAILQ_PREV(mp, mntlist, mnt_list) : TAILQ_NEXT(mp, mnt_list))) {
		uint64_t id = linux_mnt_id(mp);

		if (filter &&
		    !linux_mnt_is_child(tgtpath, mp->mnt_stat.f_mntonname))
			continue;
		if (have_cursor) {		/* resume after the cursor id */
			if (id == cursor)
				have_cursor = false;
			continue;
		}
		ids[count++] = id;
	}
#undef	LM_EACH
	mtx_unlock(&mountlist_mtx);

	error = copyout(ids, args->mnt_ids, count * sizeof(uint64_t));
	free(ids, M_LINUX);
	if (error != 0)
		return (error);
	td->td_retval[0] = count;
	return (0);
}

int
linux_statmount(struct thread *td, struct linux_statmount_args *args)
{
	struct l_mnt_id_req req;
	struct l_statmount *sm;
	struct mount *mp;
	struct statfs sf;
	char *buf, *strp;
	uint64_t mask, want, parent, id;
	uint32_t hdr, soff, total;
	l_size_t bufsize;
	bool found;
	int error;

	if (args->flags != 0)
		return (EINVAL);
	error = linux_copyin_mnt_id_req(&req, args->req);
	if (error != 0)
		return (error);
	want = req.param;			/* requested STATMOUNT_* mask */
	bufsize = args->bufsize;
	hdr = sizeof(struct l_statmount);
	if (bufsize < hdr)
		return (EOVERFLOW);
	if (bufsize > 64 * 1024)		/* bound the allocation */
		bufsize = 64 * 1024;

	/* Snapshot the matching mount and its parent under the list lock. */
	found = false;
	parent = req.mnt_id;
	mtx_lock(&mountlist_mtx);
	TAILQ_FOREACH(mp, &mountlist, mnt_list) {
		if (linux_mnt_id(mp) == req.mnt_id) {
			sf = mp->mnt_stat;
			found = true;
			break;
		}
	}
	if (found) {
		struct mount *pm;
		size_t best = 0;

		TAILQ_FOREACH(pm, &mountlist, mnt_list) {
			if (pm != mp &&
			    linux_mnt_is_child(pm->mnt_stat.f_mntonname,
			    sf.f_mntonname)) {
				size_t l = strlen(pm->mnt_stat.f_mntonname);

				if (l >= best) {
					best = l;
					parent = linux_mnt_id(pm);
				}
			}
		}
	}
	mtx_unlock(&mountlist_mtx);
	if (!found)
		return (ENOENT);

	buf = malloc(bufsize, M_LINUX, M_WAITOK | M_ZERO);
	sm = (struct l_statmount *)buf;
	strp = buf + hdr;
	soff = 0;
	mask = 0;
	id = req.mnt_id;

#define	ADDSTR(field, src)	do {					\
	size_t _l = strlen(src) + 1;					\
	if (hdr + soff + _l > bufsize) { free(buf, M_LINUX); return (EOVERFLOW); } \
	memcpy(strp + soff, (src), _l);					\
	sm->field = soff;						\
	soff += _l;							\
} while (0)

	if ((want & LINUX_STATMOUNT_FS_TYPE) != 0) {
		ADDSTR(fs_type, sf.f_fstypename);
		mask |= LINUX_STATMOUNT_FS_TYPE;
	}
	if ((want & LINUX_STATMOUNT_MNT_POINT) != 0) {
		ADDSTR(mnt_point, sf.f_mntonname);
		mask |= LINUX_STATMOUNT_MNT_POINT;
	}
	if ((want & LINUX_STATMOUNT_MNT_ROOT) != 0) {
		ADDSTR(mnt_root, "/");
		mask |= LINUX_STATMOUNT_MNT_ROOT;
	}
	if ((want & LINUX_STATMOUNT_SB_SOURCE) != 0) {
		ADDSTR(sb_source, sf.f_mntfromname);
		mask |= LINUX_STATMOUNT_SB_SOURCE;
	}
	if ((want & LINUX_STATMOUNT_SB_BASIC) != 0) {
		sm->sb_dev_major = 0;
		sm->sb_dev_minor = 0;
		sm->sb_magic = 0;
		sm->sb_flags = 0;
		if ((sf.f_flags & MNT_RDONLY) != 0)
			sm->sb_flags |= LINUX_ST_RDONLY;
		if ((sf.f_flags & MNT_SYNCHRONOUS) != 0)
			sm->sb_flags |= LINUX_ST_SYNCHRONOUS;
		mask |= LINUX_STATMOUNT_SB_BASIC;
	}
	if ((want & LINUX_STATMOUNT_MNT_BASIC) != 0) {
		sm->mnt_id = id;
		sm->mnt_parent_id = parent;
		sm->mnt_attr = 0;
		if ((sf.f_flags & MNT_RDONLY) != 0)
			sm->mnt_attr |= LINUX_MOUNT_ATTR_RDONLY;
		if ((sf.f_flags & MNT_NOSUID) != 0)
			sm->mnt_attr |= LINUX_MOUNT_ATTR_NOSUID;
		if ((sf.f_flags & MNT_NOEXEC) != 0)
			sm->mnt_attr |= LINUX_MOUNT_ATTR_NOEXEC;
		sm->mnt_propagation = LINUX_MS_PRIVATE;
		mask |= LINUX_STATMOUNT_MNT_BASIC;
	}
#undef	ADDSTR

	sm->supported_mask = LINUX_STATMOUNT_SB_BASIC |
	    LINUX_STATMOUNT_MNT_BASIC | LINUX_STATMOUNT_MNT_ROOT |
	    LINUX_STATMOUNT_MNT_POINT | LINUX_STATMOUNT_FS_TYPE |
	    LINUX_STATMOUNT_SB_SOURCE;
	sm->mask = mask;
	total = hdr + soff;
	sm->size = total;
	error = copyout(buf, args->buf, total);
	free(buf, M_LINUX);
	if (error != 0)
		return (error);
	td->td_retval[0] = 0;
	return (0);
}

/*
 * NUMA memory-policy syscalls.  FreeBSD exposes vm_ndomains memory domains;
 * we present them as the Linux node set (nodes 0..vm_ndomains-1) and give
 * honest single-/multi-domain answers.  Policies are validated and accepted
 * but not separately enforced (the VM's own domain policy governs), which
 * matches what NUMA-aware allocators need: they query the allowed nodes and
 * set a policy without failing.
 */
#define	LINUX_MPOL_DEFAULT	0
#define	LINUX_MPOL_PREFERRED	1
#define	LINUX_MPOL_BIND		2
#define	LINUX_MPOL_INTERLEAVE	3
#define	LINUX_MPOL_LOCAL	4
#define	LINUX_MPOL_PREFERRED_MANY 5
#define	LINUX_MPOL_MAX		6
#define	LINUX_MPOL_MODE_FLAGS	0xe000	/* STATIC_NODES|RELATIVE_NODES|NUMA_BALANCING */
#define	LINUX_MPOL_F_NODE	0x01
#define	LINUX_MPOL_F_ADDR	0x02
#define	LINUX_MPOL_F_MEMS_ALLOWED 0x04
#define	LINUX_MPOL_MF_STRICT	0x01
#define	LINUX_MPOL_MF_MOVE	0x02
#define	LINUX_MPOL_MF_MOVE_ALL	0x04

/* Highest node bit set in a user nodemask of maxnode bits; -1 if empty. */
static int
linux_nodemask_max(const l_ulong *unmask, l_ulong maxnode, int *error)
{
	l_ulong word;
	int i, hi, nwords;

	*error = 0;
	if (unmask == NULL || maxnode == 0)
		return (-1);
	if (maxnode > 8192) {			/* MAX_NUMNODES sanity cap */
		*error = EINVAL;
		return (-1);
	}
	nwords = howmany(maxnode, sizeof(l_ulong) * 8);
	hi = -1;
	for (i = 0; i < nwords; i++) {
		if (copyin(&unmask[i], &word, sizeof(word)) != 0) {
			*error = EFAULT;
			return (-1);
		}
		if (word != 0) {
			int b = flsl(word) - 1 + i * (int)(sizeof(l_ulong) * 8);

			if (b < (int)maxnode)
				hi = b;
		}
	}
	return (hi);
}

int
linux_set_mempolicy(struct thread *td, struct linux_set_mempolicy_args *args)
{
	int mode, hi, error;

	mode = args->mode & ~LINUX_MPOL_MODE_FLAGS;
	if (mode < 0 || mode >= LINUX_MPOL_MAX)
		return (EINVAL);
	hi = linux_nodemask_max(args->nmask, args->maxnode, &error);
	if (error != 0)
		return (error);
	/* A bound/preferred policy naming a node we do not have is EINVAL. */
	if (hi >= vm_ndomains)
		return (EINVAL);
	if (mode == LINUX_MPOL_BIND && hi < 0)
		return (EINVAL);		/* BIND requires a non-empty set */
	return (0);
}

int
linux_get_mempolicy(struct thread *td, struct linux_get_mempolicy_args *args)
{
	l_ulong node0;
	int mode, error;

	if ((args->flags & ~(LINUX_MPOL_F_NODE | LINUX_MPOL_F_ADDR |
	    LINUX_MPOL_F_MEMS_ALLOWED)) != 0)
		return (EINVAL);
	if ((args->flags & LINUX_MPOL_F_MEMS_ALLOWED) != 0) {
		/* Cannot combine with NODE/ADDR; report the allowed node set. */
		if ((args->flags & (LINUX_MPOL_F_NODE | LINUX_MPOL_F_ADDR)) != 0)
			return (EINVAL);
		if (args->nmask != NULL) {
			if (args->maxnode < (l_ulong)vm_ndomains)
				return (EINVAL);
			node0 = ((l_ulong)1 << vm_ndomains) - 1;
			error = copyout(&node0, args->nmask, sizeof(node0));
			if (error != 0)
				return (error);
		}
		return (0);
	}
	/*
	 * No policy is separately tracked, so report MPOL_DEFAULT; with
	 * MPOL_F_NODE|MPOL_F_ADDR the "policy" out-value is the node of the
	 * address, which on our layout is domain 0.
	 */
	mode = ((args->flags & (LINUX_MPOL_F_NODE | LINUX_MPOL_F_ADDR)) ==
	    (LINUX_MPOL_F_NODE | LINUX_MPOL_F_ADDR)) ? 0 : LINUX_MPOL_DEFAULT;
	if (args->policy != NULL) {
		error = copyout(&mode, args->policy, sizeof(mode));
		if (error != 0)
			return (error);
	}
	if (args->nmask != NULL) {
		if (args->maxnode < (l_ulong)vm_ndomains)
			return (EINVAL);
		node0 = 1;			/* node 0 */
		error = copyout(&node0, args->nmask, sizeof(node0));
		if (error != 0)
			return (error);
	}
	return (0);
}

int
linux_mbind(struct thread *td, struct linux_mbind_args *args)
{
	int mode, hi, error;

	mode = args->mode & ~LINUX_MPOL_MODE_FLAGS;
	if (mode < 0 || mode >= LINUX_MPOL_MAX)
		return (EINVAL);
	if ((args->flags & ~(LINUX_MPOL_MF_STRICT | LINUX_MPOL_MF_MOVE |
	    LINUX_MPOL_MF_MOVE_ALL)) != 0)
		return (EINVAL);
	if ((args->start & PAGE_MASK) != 0)
		return (EINVAL);
	hi = linux_nodemask_max(args->nmask, args->maxnode, &error);
	if (error != 0)
		return (error);
	if (hi >= vm_ndomains)
		return (EINVAL);
	/* Single set of domains: the binding is satisfiable, so accept. */
	return (0);
}

int
linux_set_mempolicy_home_node(struct thread *td,
    struct linux_set_mempolicy_home_node_args *args)
{

	if (args->flags != 0)
		return (EINVAL);
	if ((args->start & PAGE_MASK) != 0)
		return (EINVAL);
	if (args->home_node >= (l_ulong)vm_ndomains)
		return (EINVAL);
	return (0);
}

int
linux_migrate_pages(struct thread *td, struct linux_migrate_pages_args *args)
{
	int error;

	(void)linux_nodemask_max(args->old_nodes, args->maxnode, &error);
	if (error != 0)
		return (error);
	(void)linux_nodemask_max(args->new_nodes, args->maxnode, &error);
	if (error != 0)
		return (error);
	/* One domain set: nothing migrates; 0 pages could not be moved. */
	td->td_retval[0] = 0;
	return (0);
}

int
linux_move_pages(struct thread *td, struct linux_move_pages_args *args)
{
	struct proc *p;
	vm_map_t map;
	l_uintptr_t uptr;
	l_ulong i;
	int st, node, error;

	if ((args->flags & ~(LINUX_MPOL_MF_MOVE | LINUX_MPOL_MF_MOVE_ALL)) != 0)
		return (EINVAL);
	if (args->count == 0)
		return (0);
	if (args->count > 1024 * 1024)		/* sanity cap */
		return (EINVAL);
	if (args->pages == NULL || args->status == NULL)
		return (EFAULT);
	if (args->pid == 0)
		p = td->td_proc;
	else {
		error = pget(args->pid, PGET_CANDEBUG | PGET_NOTWEXIT, &p);
		if (error != 0)
			return (error == EACCES ? EPERM : error);
	}
	map = &p->p_vmspace->vm_map;
	for (i = 0; i < args->count; i++) {
		error = copyin(&args->pages[i], &uptr, sizeof(uptr));
		if (error != 0)
			goto out;
		/*
		 * Query the residence node of each page.  With one domain any
		 * mapped page is on node 0; an unmapped address is -ENOENT,
		 * matching what a NUMA profiler expects.  (nodes != NULL asks
		 * to move pages, which is a no-op on a single domain.)
		 */
		vm_map_lock_read(map);
		if (vm_map_check_protection(map, trunc_page(uptr),
		    trunc_page(uptr) + PAGE_SIZE, VM_PROT_NONE))
			node = 0;		/* mapped: single domain -> node 0 */
		else
			node = -ENOENT;		/* not mapped */
		vm_map_unlock_read(map);
		st = node;
		error = copyout(&st, &args->status[i], sizeof(st));
		if (error != 0)
			goto out;
	}
	error = 0;
out:
	if (args->pid != 0)
		PRELE(p);
	return (error);
}

int
linux_cachestat(struct thread *td, struct linux_cachestat_args *args)
{
	struct l_cachestat_range range;
	struct l_cachestat cs;
	struct file *fp;
	struct vnode *vp;
	vm_object_t obj;
	vm_page_t m;
	vm_pindex_t pi, start, end;
	int error;

	if (args->flags != 0)
		return (EINVAL);
	error = copyin(args->cstat_range, &range, sizeof(range));
	if (error != 0)
		return (error);
	error = fget(td, args->fd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	memset(&cs, 0, sizeof(cs));
	if (fp->f_type != DTYPE_VNODE) {
		error = EBADF;
		goto out;
	}
	vp = fp->f_vnode;
	if (vp->v_type != VREG) {
		error = EBADF;
		goto out;
	}
	obj = vp->v_object;
	if (obj != NULL) {
		start = OFF_TO_IDX(range.off);
		if (range.len == 0)			/* to EOF */
			end = obj->size;
		else
			end = OFF_TO_IDX(range.off + range.len + PAGE_MASK);
		VM_OBJECT_RLOCK(obj);
		if (end > obj->size)
			end = obj->size;
		/*
		 * Count resident (cached) and dirty pages in the range.
		 * FreeBSD does not track eviction history, so nr_evicted /
		 * nr_recently_evicted stay 0; writeback state is not exposed
		 * here either.
		 */
		for (pi = start; pi < end; pi++) {
			m = vm_page_lookup(obj, pi);
			if (m == NULL || vm_page_none_valid(m))
				continue;
			cs.nr_cache++;
			if (m->dirty != 0)
				cs.nr_dirty++;
		}
		VM_OBJECT_RUNLOCK(obj);
	}
	error = copyout(&cs, args->cstat, sizeof(cs));
out:
	fdrop(fp, td);
	return (error);
}


int
linux_process_vm_readv(struct thread *td,
    struct linux_process_vm_readv_args *args)
{

	return (linux_process_vm_rw(td, args->pid,
	    (const struct iovec *)args->lvec, args->liovcnt,
	    (const struct iovec *)args->rvec, args->riovcnt,
	    args->flags, 0));
}

int
linux_process_vm_writev(struct thread *td,
    struct linux_process_vm_writev_args *args)
{

	return (linux_process_vm_rw(td, args->pid,
	    (const struct iovec *)args->lvec, args->liovcnt,
	    (const struct iovec *)args->rvec, args->riovcnt,
	    args->flags, 1));
}

/*
 * Advice a remote process may be given on Linux (process_madvise_remote_valid).
 * The calling process may give itself any advice, as on Linux >= 6.15.
 */
static bool
linux_process_madvise_remote_valid(int behavior)
{

	switch (behavior) {
	case LINUX_MADV_COLD:
	case LINUX_MADV_PAGEOUT:
	case LINUX_MADV_WILLNEED:
	case LINUX_MADV_COLLAPSE:
		return (true);
	default:
		return (false);
	}
}

int
linux_process_madvise(struct thread *td, struct linux_process_madvise_args *args)
{
	struct iovec *iov;
	size_t i, total;
	pid_t pid;
	int error;

	if (args->flags != 0)
		return (EINVAL);
	if (args->vlen > UIO_MAXIOV)
		return (EINVAL);

	/* Linux imports the vector before it looks at the pidfd. */
	iov = NULL;
	if (args->vlen != 0) {
#ifdef COMPAT_LINUX32
		error = freebsd32_copyiniov(PTRIN(args->vec), args->vlen, &iov,
		    EINVAL);
#else
		error = copyiniov(args->vec, args->vlen, &iov, EINVAL);
#endif
		if (error != 0)
			return (error);
	}

	error = linux_pidfd_topid(td, args->pidfd, &pid);
	if (error != 0)
		goto out;

	if (pid != td->td_proc->p_pid) {
		struct proc *p;

		if ((p = pfind(pid)) == NULL) {
			error = ESRCH;
			goto out;
		}
		PROC_UNLOCK(p);
		/*
		 * Cross-process madvise is not supported: it would need the
		 * target's vm_map plus a PTRACE_MODE_READ-style access check
		 * (Linux additionally wants CAP_SYS_NICE).  Refuse with the
		 * errno Linux gives an unauthorized caller.  Invalid remote
		 * advice is still EINVAL, as on Linux.
		 */
		error = linux_process_madvise_remote_valid(args->behavior) ?
		    EPERM : EINVAL;
		goto out;
	}

	total = 0;
	for (i = 0; i < args->vlen; i++) {
		error = linux_madvise_common(td, (uintptr_t)iov[i].iov_base,
		    iov[i].iov_len, args->behavior);
		if (error != 0)
			break;
		total += iov[i].iov_len;
	}
	/* Linux reports partial progress in preference to the error. */
	if (total != 0)
		error = 0;
	if (error == 0)
		td->td_retval[0] = total;
out:
	free(iov, M_IOV);
	return (error);
}

int
linux_vhangup(struct thread *td, struct linux_vhangup_args *args)
{
	struct proc *p;
	struct vnode *vp;

	/*
	 * Linux requires CAP_SYS_TTY_CONFIG and then revokes the
	 * controlling terminal.  Map to FreeBSD's VOP_REVOKE on
	 * the session's controlling tty vnode.
	 */
	if (priv_check(td, PRIV_TTY_STI) != 0)
		return (EPERM);

	p = td->td_proc;
	PROC_LOCK(p);
	if (p->p_pgrp == NULL || p->p_session->s_ttyvp == NULL) {
		PROC_UNLOCK(p);
		return (0);
	}
	vp = p->p_session->s_ttyvp;
	vref(vp);
	PROC_UNLOCK(p);

	if (vn_lock(vp, LK_EXCLUSIVE) == 0) {
		VOP_REVOKE(vp, REVOKEALL);
		VOP_UNLOCK(vp);
	}
	vrele(vp);
	return (0);
}

#if defined(__i386__) || defined(__amd64__)
int
linux_poll(struct thread *td, struct linux_poll_args *args)
{
	struct timespec ts, *tsp;

	if (args->timeout != INFTIM) {
		if (args->timeout < 0)
			return (EINVAL);
		ts.tv_sec = args->timeout / 1000;
		ts.tv_nsec = (args->timeout % 1000) * 1000000;
		tsp = &ts;
	} else
		tsp = NULL;

	return (linux_common_ppoll(td, args->fds, args->nfds,
	    tsp, NULL, 0));
}
#endif /* __i386__ || __amd64__ */

int
linux_seccomp(struct thread *td, struct linux_seccomp_args *args)
{

	switch (args->op) {
	case LINUX_SECCOMP_GET_ACTION_AVAIL:
		return (EOPNOTSUPP);
	default:
		/*
		 * Ignore unknown operations, just like Linux kernel built
		 * without CONFIG_SECCOMP.
		 */
		return (EINVAL);
	}
}

/*
 * Custom version of exec_copyin_args(), to copy out argument and environment
 * strings from the old process address space into the temporary string buffer.
 * Based on freebsd32_exec_copyin_args.
 */
int
linux_exec_copyin_args(struct image_args *args, const char *fname,
    l_uintptr_t *argv, l_uintptr_t *envv)
{
	char *argp, *envp;
	l_uintptr_t *ptr, arg;
	int error;

	bzero(args, sizeof(*args));
	if (argv == NULL)
		return (EFAULT);

	/*
	 * Allocate demand-paged memory for the file name, argument, and
	 * environment strings.
	 */
	error = exec_alloc_args(args);
	if (error != 0)
		return (error);

	/*
	 * Copy the file name.
	 */
	error = exec_args_add_fname(args, fname, UIO_USERSPACE);
	if (error != 0)
		goto err_exit;

	/*
	 * extract arguments first
	 */
	ptr = argv;
	for (;;) {
		error = copyin(ptr++, &arg, sizeof(arg));
		if (error)
			goto err_exit;
		if (arg == 0)
			break;
		argp = PTRIN(arg);
		error = exec_args_add_arg(args, argp, UIO_USERSPACE);
		if (error != 0)
			goto err_exit;
	}

	/*
	 * This comment is from Linux do_execveat_common:
	 * When argv is empty, add an empty string ("") as argv[0] to
	 * ensure confused userspace programs that start processing
	 * from argv[1] won't end up walking envp.
	 */
	if (args->argc == 0 &&
	    (error = exec_args_add_arg(args, "", UIO_SYSSPACE) != 0))
		goto err_exit;

	/*
	 * extract environment strings
	 */
	if (envv) {
		ptr = envv;
		for (;;) {
			error = copyin(ptr++, &arg, sizeof(arg));
			if (error)
				goto err_exit;
			if (arg == 0)
				break;
			envp = PTRIN(arg);
			error = exec_args_add_env(args, envp, UIO_USERSPACE);
			if (error != 0)
				goto err_exit;
		}
	}

	return (0);

err_exit:
	exec_free_args(args);
	return (error);
}

int
linux_execve(struct thread *td, struct linux_execve_args *args)
{
	struct image_args eargs;
	int error;

	LINUX_CTR(execve);

	error = linux_exec_copyin_args(&eargs, args->path, args->argp,
	    args->envp);
	if (error == 0)
		error = linux_common_execve(td, &eargs);
	AUDIT_SYSCALL_EXIT(error == EJUSTRETURN ? 0 : error, td);
	return (error);
}

static void
linux_up_rtprio_if(struct thread *td1, struct rtprio *rtp)
{
	struct rtprio rtp2;

	pri_to_rtp(td1, &rtp2);
	if (rtp2.type <  rtp->type ||
	    (rtp2.type == rtp->type &&
	    rtp2.prio < rtp->prio)) {
		rtp->type = rtp2.type;
		rtp->prio = rtp2.prio;
	}
}

#define	LINUX_PRIO_DIVIDER	RTP_PRIO_MAX / LINUX_IOPRIO_MAX

static int
linux_rtprio2ioprio(struct rtprio *rtp)
{
	int ioprio, prio;

	switch (rtp->type) {
	case RTP_PRIO_IDLE:
		prio = RTP_PRIO_MIN;
		ioprio = LINUX_IOPRIO_PRIO(LINUX_IOPRIO_CLASS_IDLE, prio);
		break;
	case RTP_PRIO_NORMAL:
		prio = rtp->prio / LINUX_PRIO_DIVIDER;
		ioprio = LINUX_IOPRIO_PRIO(LINUX_IOPRIO_CLASS_BE, prio);
		break;
	case RTP_PRIO_REALTIME:
		prio = rtp->prio / LINUX_PRIO_DIVIDER;
		ioprio = LINUX_IOPRIO_PRIO(LINUX_IOPRIO_CLASS_RT, prio);
		break;
	default:
		prio = RTP_PRIO_MIN;
		ioprio = LINUX_IOPRIO_PRIO(LINUX_IOPRIO_CLASS_NONE, prio);
		break;
	}
	return (ioprio);
}

static int
linux_ioprio2rtprio(int ioprio, struct rtprio *rtp)
{

	switch (LINUX_IOPRIO_PRIO_CLASS(ioprio)) {
	case LINUX_IOPRIO_CLASS_IDLE:
		rtp->prio = RTP_PRIO_MIN;
		rtp->type = RTP_PRIO_IDLE;
		break;
	case LINUX_IOPRIO_CLASS_BE:
		rtp->prio = LINUX_IOPRIO_PRIO_DATA(ioprio) * LINUX_PRIO_DIVIDER;
		rtp->type = RTP_PRIO_NORMAL;
		break;
	case LINUX_IOPRIO_CLASS_RT:
		rtp->prio = LINUX_IOPRIO_PRIO_DATA(ioprio) * LINUX_PRIO_DIVIDER;
		rtp->type = RTP_PRIO_REALTIME;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}
#undef LINUX_PRIO_DIVIDER

int
linux_ioprio_get(struct thread *td, struct linux_ioprio_get_args *args)
{
	struct thread *td1;
	struct rtprio rtp;
	struct pgrp *pg;
	struct proc *p;
	int error, found;

	p = NULL;
	td1 = NULL;
	error = 0;
	found = 0;
	rtp.type = RTP_PRIO_IDLE;
	rtp.prio = RTP_PRIO_MAX;
	switch (args->which) {
	case LINUX_IOPRIO_WHO_PROCESS:
		if (args->who == 0) {
			td1 = td;
			p = td1->td_proc;
			PROC_LOCK(p);
		} else if (args->who > PID_MAX) {
			td1 = linux_tdfind(td, args->who, -1);
			if (td1 != NULL)
				p = td1->td_proc;
		} else
			p = pfind(args->who);
		if (p == NULL)
			return (ESRCH);
		if ((error = p_cansee(td, p))) {
			PROC_UNLOCK(p);
			break;
		}
		if (td1 != NULL) {
			pri_to_rtp(td1, &rtp);
		} else {
			FOREACH_THREAD_IN_PROC(p, td1) {
				linux_up_rtprio_if(td1, &rtp);
			}
		}
		found++;
		PROC_UNLOCK(p);
		break;
	case LINUX_IOPRIO_WHO_PGRP:
		sx_slock(&proctree_lock);
		if (args->who == 0) {
			pg = td->td_proc->p_pgrp;
			PGRP_LOCK(pg);
		} else {
			pg = pgfind(args->who);
			if (pg == NULL) {
				sx_sunlock(&proctree_lock);
				error = ESRCH;
				break;
			}
		}
		sx_sunlock(&proctree_lock);
		LIST_FOREACH(p, &pg->pg_members, p_pglist) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p_cansee(td, p) == 0) {
				FOREACH_THREAD_IN_PROC(p, td1) {
					linux_up_rtprio_if(td1, &rtp);
					found++;
				}
			}
			PROC_UNLOCK(p);
		}
		PGRP_UNLOCK(pg);
		break;
	case LINUX_IOPRIO_WHO_USER:
		if (args->who == 0)
			args->who = td->td_ucred->cr_uid;
		sx_slock(&allproc_lock);
		FOREACH_PROC_IN_SYSTEM(p) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p->p_ucred->cr_uid == args->who &&
			    p_cansee(td, p) == 0) {
				FOREACH_THREAD_IN_PROC(p, td1) {
					linux_up_rtprio_if(td1, &rtp);
					found++;
				}
			}
			PROC_UNLOCK(p);
		}
		sx_sunlock(&allproc_lock);
		break;
	default:
		error = EINVAL;
		break;
	}
	if (error == 0) {
		if (found != 0)
			td->td_retval[0] = linux_rtprio2ioprio(&rtp);
		else
			error = ESRCH;
	}
	return (error);
}

int
linux_ioprio_set(struct thread *td, struct linux_ioprio_set_args *args)
{
	struct thread *td1;
	struct rtprio rtp;
	struct pgrp *pg;
	struct proc *p;
	int error;

	if ((error = linux_ioprio2rtprio(args->ioprio, &rtp)) != 0)
		return (error);
	/* Attempts to set high priorities (REALTIME) require su privileges. */
	if (RTP_PRIO_BASE(rtp.type) == RTP_PRIO_REALTIME &&
	    (error = priv_check(td, PRIV_SCHED_RTPRIO)) != 0)
		return (error);

	p = NULL;
	td1 = NULL;
	switch (args->which) {
	case LINUX_IOPRIO_WHO_PROCESS:
		if (args->who == 0) {
			td1 = td;
			p = td1->td_proc;
			PROC_LOCK(p);
		} else if (args->who > PID_MAX) {
			td1 = linux_tdfind(td, args->who, -1);
			if (td1 != NULL)
				p = td1->td_proc;
		} else
			p = pfind(args->who);
		if (p == NULL)
			return (ESRCH);
		if ((error = p_cansched(td, p))) {
			PROC_UNLOCK(p);
			break;
		}
		if (td1 != NULL) {
			error = rtp_to_pri(&rtp, td1);
		} else {
			FOREACH_THREAD_IN_PROC(p, td1) {
				if ((error = rtp_to_pri(&rtp, td1)) != 0)
					break;
			}
		}
		PROC_UNLOCK(p);
		break;
	case LINUX_IOPRIO_WHO_PGRP:
		sx_slock(&proctree_lock);
		if (args->who == 0) {
			pg = td->td_proc->p_pgrp;
			PGRP_LOCK(pg);
		} else {
			pg = pgfind(args->who);
			if (pg == NULL) {
				sx_sunlock(&proctree_lock);
				error = ESRCH;
				break;
			}
		}
		sx_sunlock(&proctree_lock);
		LIST_FOREACH(p, &pg->pg_members, p_pglist) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p_cansched(td, p) == 0) {
				FOREACH_THREAD_IN_PROC(p, td1) {
					if ((error = rtp_to_pri(&rtp, td1)) != 0)
						break;
				}
			}
			PROC_UNLOCK(p);
			if (error != 0)
				break;
		}
		PGRP_UNLOCK(pg);
		break;
	case LINUX_IOPRIO_WHO_USER:
		if (args->who == 0)
			args->who = td->td_ucred->cr_uid;
		sx_slock(&allproc_lock);
		FOREACH_PROC_IN_SYSTEM(p) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p->p_ucred->cr_uid == args->who &&
			    p_cansched(td, p) == 0) {
				FOREACH_THREAD_IN_PROC(p, td1) {
					if ((error = rtp_to_pri(&rtp, td1)) != 0)
						break;
				}
			}
			PROC_UNLOCK(p);
			if (error != 0)
				break;
		}
		sx_sunlock(&allproc_lock);
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

/* The only flag is O_NONBLOCK */
#define B2L_MQ_FLAGS(bflags)	((bflags) != 0 ? LINUX_O_NONBLOCK : 0)
#define L2B_MQ_FLAGS(lflags)	((lflags) != 0 ? O_NONBLOCK : 0)

int
linux_mq_open(struct thread *td, struct linux_mq_open_args *args)
{
	struct mq_attr attr;
	int error, flags;

	flags = linux_common_openflags(args->oflag);
	if ((flags & O_ACCMODE) == O_ACCMODE || (flags & O_EXEC) != 0)
		return (EINVAL);
	flags = FFLAGS(flags);
	if ((flags & O_CREAT) != 0 && args->attr != NULL) {
		error = copyin(args->attr, &attr, sizeof(attr));
		if (error != 0)
			return (error);
		attr.mq_flags = L2B_MQ_FLAGS(attr.mq_flags);
	}

	return (kern_kmq_open(td, args->name, flags, args->mode,
	    args->attr != NULL ? &attr : NULL));
}

int
linux_mq_unlink(struct thread *td, struct linux_mq_unlink_args *args)
{
	struct kmq_unlink_args bsd_args = {
		.path = PTRIN(args->name)
	};

	return (sys_kmq_unlink(td, &bsd_args));
}

int
linux_mq_timedsend(struct thread *td, struct linux_mq_timedsend_args *args)
{
	struct timespec ts, *abs_timeout;
	int error;

	if (args->abs_timeout == NULL)
		abs_timeout = NULL;
	else {
		error = linux_get_timespec(&ts, args->abs_timeout);
		if (error != 0)
			return (error);
		abs_timeout = &ts;
	}

	return (kern_kmq_timedsend(td, args->mqd, PTRIN(args->msg_ptr),
		args->msg_len, args->msg_prio, abs_timeout));
}

int
linux_mq_timedreceive(struct thread *td, struct linux_mq_timedreceive_args *args)
{
	struct timespec ts, *abs_timeout;
	int error;

	if (args->abs_timeout == NULL)
		abs_timeout = NULL;
	else {
		error = linux_get_timespec(&ts, args->abs_timeout);
		if (error != 0)
			return (error);
		abs_timeout = &ts;
	}

	return (kern_kmq_timedreceive(td, args->mqd, PTRIN(args->msg_ptr),
		args->msg_len, args->msg_prio, abs_timeout));
}

int
linux_mq_notify(struct thread *td, struct linux_mq_notify_args *args)
{
	struct sigevent ev, *evp;
	struct l_sigevent l_ev;
	int error;

	if (args->sevp == NULL)
		evp = NULL;
	else {
		error = copyin(args->sevp, &l_ev, sizeof(l_ev));
		if (error != 0)
			return (error);
		error = linux_convert_l_sigevent(&l_ev, &ev);
		if (error != 0)
			return (error);
		evp = &ev;
	}

	return (kern_kmq_notify(td, args->mqd, evp));
}

int
linux_mq_getsetattr(struct thread *td, struct linux_mq_getsetattr_args *args)
{
	struct mq_attr attr, oattr;
	int error;

	if (args->attr != NULL) {
		error = copyin(args->attr, &attr, sizeof(attr));
		if (error != 0)
			return (error);
		attr.mq_flags = L2B_MQ_FLAGS(attr.mq_flags);
	}

	error = kern_kmq_setattr(td, args->mqd, args->attr != NULL ? &attr : NULL,
	    &oattr);
	if (error == 0 && args->oattr != NULL) {
		oattr.mq_flags = B2L_MQ_FLAGS(oattr.mq_flags);
		bzero(oattr.__reserved, sizeof(oattr.__reserved));
		error = copyout(&oattr, args->oattr, sizeof(oattr));
	}

	return (error);
}

int
linux_kcmp(struct thread *td, struct linux_kcmp_args *args)
{
	int type;

	switch (args->type) {
	case LINUX_KCMP_FILE:
		type = KCMP_FILE;
		break;
	case LINUX_KCMP_FILES:
		type = KCMP_FILES;
		break;
	case LINUX_KCMP_SIGHAND:
		type = KCMP_SIGHAND;
		break;
	case LINUX_KCMP_VM:
		type = KCMP_VM;
		break;
	case LINUX_KCMP_FS:
	case LINUX_KCMP_IO:
	case LINUX_KCMP_SYSVSEM:
	case LINUX_KCMP_EPOLL_TFD:
		/*
		 * fs_struct, io context, semadj list and epoll target
		 * comparisons have no native object to compare; EOPNOTSUPP
		 * rather than the EINVAL Linux reserves for bad types.
		 */
		return (EOPNOTSUPP);
	default:
		return (EINVAL);
	}

	return (kern_kcmp(td, args->pid1, args->pid2, type, args->idx1,
	    args->idx));
}

int
linux_membarrier(struct thread *td, struct linux_membarrier_args *args)
{
	static const struct {
		int linux_cmd;
		int freebsd_cmd;
	} cmds[] = {
		{ LINUX_MEMBARRIER_CMD_QUERY,
		    MEMBARRIER_CMD_QUERY },
		{ LINUX_MEMBARRIER_CMD_GLOBAL,
		    MEMBARRIER_CMD_GLOBAL },
		{ LINUX_MEMBARRIER_CMD_GLOBAL_EXPEDITED,
		    MEMBARRIER_CMD_GLOBAL_EXPEDITED },
		{ LINUX_MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
		    MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED },
		{ LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED,
		    MEMBARRIER_CMD_PRIVATE_EXPEDITED },
		{ LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
		    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED },
		{ LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,
		    MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE },
		{ LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
		    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE },
		{ LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
		    MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ },
		{ LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
		    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ },
		{ LINUX_MEMBARRIER_CMD_GET_REGISTRATIONS,
		    MEMBARRIER_CMD_GET_REGISTRATIONS },
	};
	int cmd, error, flags, i, mask;

	cmd = -1;
	for (i = 0; i < nitems(cmds); i++) {
		if (args->cmd == cmds[i].linux_cmd) {
			cmd = cmds[i].freebsd_cmd;
			break;
		}
	}

	if (cmd == -1 || (args->flags & ~LINUX_MEMBARRIER_CMD_FLAG_CPU) != 0)
		return (EINVAL);

	flags = 0;
	if ((args->flags & LINUX_MEMBARRIER_CMD_FLAG_CPU) != 0)
		flags |= MEMBARRIER_CMD_FLAG_CPU;

	error = kern_membarrier(td, cmd, flags, 0);
	if (error != 0)
		return (error);

	if (args->cmd == LINUX_MEMBARRIER_CMD_QUERY ||
	    args->cmd == LINUX_MEMBARRIER_CMD_GET_REGISTRATIONS) {
		mask = td->td_retval[0];
		td->td_retval[0] = 0;
		for (i = 0; i < nitems(cmds); i++)
			if ((mask & cmds[i].freebsd_cmd) != 0)
				td->td_retval[0] |= cmds[i].linux_cmd;
	}

	return (0);
}

/*
 * setfsuid() & setfsgid() exist to decouple the Linux filesystem credentials
 * from the effective credentials, avoiding signal exposure during privilege
 * transitions. The signal permission model that motivated this was revised in
 * Linux 2.0, making these syscalls obsolete for new applications.
 *
 * As there's no FreeBSD equivalent, implement both syscalls as no-ops that
 * return the current effective UID/GID as the previous filesystem UID/GID.
 * Linux returns the previous filesystem UID/GID for these syscalls, with no
 * error indication.
 */

int
linux_setfsuid(struct thread *td, struct linux_setfsuid_args *args)
{
	td->td_retval[0] = td->td_ucred->cr_uid;
	return (0);
}

int
linux_setfsgid(struct thread *td, struct linux_setfsgid_args *args)
{
	td->td_retval[0] = td->td_ucred->cr_gid;
	return (0);
}

MODULE_DEPEND(linux, mqueuefs, 1, 1, 1);

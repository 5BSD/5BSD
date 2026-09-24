/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2000 Dag-Erling Smørgrav
 * Copyright (c) 1999 Pierre Beyssac
 * Copyright (c) 1993 Jan-Simon Pendry
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/blist.h>
#include <sys/bus.h>
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/exec.h>
#include <sys/event.h>
#include <sys/eventfd.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/msg.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/selinfo.h>
#include <sys/pipe.h>
#include <sys/ptrace.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <sys/rtprio.h>
#include <sys/sbuf.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/un.h>
#include <sys/unpcb.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/time.h>
#include <sys/tty.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/uuid.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/swap_pager.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_param.h>

#include <machine/clock.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>

#include <net/vnet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/route/nhop.h>
#include <net/route/route_ctl.h>

#include <geom/geom.h>
#include <geom/geom_int.h>

#if defined(__i386__) || defined(__amd64__)
#include <machine/cputypes.h>
#include <machine/md_var.h>
#endif /* __i386__ || __amd64__ */

#include <compat/linux/linux.h>
#include <compat/linux/linux_common.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_util.h>
#include <fs/pseudofs/pseudofs.h>
#include <fs/procfs/procfs.h>

/*
 * Various conversion macros
 */
#define T2J(x) ((long)(((x) * 100ULL) / (stathz ? stathz : hz)))	/* ticks to jiffies */
#define T2CS(x) ((unsigned long)(((x) * 100ULL) / (stathz ? stathz : hz)))	/* ticks to centiseconds */
#define T2S(x) ((x) / (stathz ? stathz : hz))		/* ticks to seconds */
#define B2K(x) ((x) >> 10)				/* bytes to kbytes */
#define B2P(x) ((x) >> PAGE_SHIFT)			/* bytes to pages */
#define P2B(x) ((x) << PAGE_SHIFT)			/* pages to bytes */
#define P2K(x) ((x) << (PAGE_SHIFT - 10))		/* pages to kbytes */
#define TV2J(x)	((x)->tv_sec * 100UL + (x)->tv_usec / 10000)

/**
 * @brief Mapping of ki_stat in struct kinfo_proc to the linux state
 *
 * The linux procfs state field displays one of the characters RSDZTW to
 * denote running, sleeping in an interruptible wait, waiting in an
 * uninterruptible disk sleep, a zombie process, process is being traced
 * or stopped, or process is paging respectively.
 *
 * Our struct kinfo_proc contains the variable ki_stat which contains a
 * value out of SIDL, SRUN, SSLEEP, SSTOP, SZOMB, SWAIT and SLOCK.
 *
 * This character array is used with ki_stati-1 as an index and tries to
 * map our states to suitable linux states.
 */
static char linux_state[] = "RRSTZDD";

/*
 * Filler function for proc/meminfo
 */
static int
linprocfs_domeminfo(PFS_FILL_ARGS)
{
	unsigned long memtotal;		/* total memory in bytes */
	unsigned long memfree;		/* free memory in bytes */
	unsigned long cached;		/* page cache */
	unsigned long buffers;		/* buffer cache */
	unsigned long long swaptotal;	/* total swap space in bytes */
	unsigned long long swapused;	/* used swap space in bytes */
	unsigned long long swapfree;	/* free swap space in bytes */
	size_t sz;
	int error, i, j;

	memtotal = physmem * PAGE_SIZE;
	memfree = (unsigned long)vm_free_count() * PAGE_SIZE;
	swap_pager_status(&i, &j);
	swaptotal = (unsigned long long)i * PAGE_SIZE;
	swapused = (unsigned long long)j * PAGE_SIZE;
	swapfree = swaptotal - swapused;

	/*
	 * This value may exclude wired pages, but we have no good way of
	 * accounting for that.
	 */
	cached =
	    (vm_active_count() + vm_inactive_count() + vm_laundry_count()) *
	    PAGE_SIZE;

	sz = sizeof(buffers);
	error = kernel_sysctlbyname(curthread, "vfs.bufspace", &buffers, &sz,
	    NULL, 0, 0, 0);
	if (error != 0)
		buffers = 0;

	sbuf_printf(sb,
	    "MemTotal: %9lu kB\n"
	    "MemFree:  %9lu kB\n"
	    "Buffers:  %9lu kB\n"
	    "Cached:   %9lu kB\n"
	    "SwapTotal:%9llu kB\n"
	    "SwapFree: %9llu kB\n",
	    B2K(memtotal), B2K(memfree), B2K(buffers),
	    B2K(cached), B2K(swaptotal), B2K(swapfree));

	return (0);
}

#if defined(__i386__) || defined(__amd64__)
/*
 * Filler function for proc/cpuinfo (i386 & amd64 version)
 */
static int
linprocfs_docpuinfo(PFS_FILL_ARGS)
{
	uint64_t freq;
	u_int cache_size[4];
	u_int regs[4] = { 0 };
	int fqmhz, fqkhz;
	int i, j;

	/*
	 * We default the flags to include all non-conflicting flags,
	 * and the Intel versions of conflicting flags.
	 */
	static char *cpu_feature_names[] = {
		/*  0 */ "fpu", "vme", "de", "pse",
		/*  4 */ "tsc", "msr", "pae", "mce",
		/*  8 */ "cx8", "apic", "", "sep",
		/* 12 */ "mtrr", "pge", "mca", "cmov",
		/* 16 */ "pat", "pse36", "pn", "clflush",
		/* 20 */ "", "dts", "acpi", "mmx",
		/* 24 */ "fxsr", "sse", "sse2", "ss",
		/* 28 */ "ht", "tm", "ia64", "pbe"
	};

	static char *amd_feature_names[] = {
		/*  0 */ "", "", "", "",
		/*  4 */ "", "", "", "",
		/*  8 */ "", "", "", "syscall",
		/* 12 */ "", "", "", "",
		/* 16 */ "", "", "", "mp",
		/* 20 */ "nx", "", "mmxext", "",
		/* 24 */ "", "fxsr_opt", "pdpe1gb", "rdtscp",
		/* 28 */ "", "lm", "3dnowext", "3dnow"
	};

	static char *cpu_feature2_names[] = {
		/*  0 */ "pni", "pclmulqdq", "dtes64", "monitor",
		/*  4 */ "ds_cpl", "vmx", "smx", "est",
		/*  8 */ "tm2", "ssse3", "cid", "sdbg",
		/* 12 */ "fma", "cx16", "xtpr", "pdcm",
		/* 16 */ "", "pcid", "dca", "sse4_1",
		/* 20 */ "sse4_2", "x2apic", "movbe", "popcnt",
		/* 24 */ "tsc_deadline_timer", "aes", "xsave", "",
		/* 28 */ "avx", "f16c", "rdrand", "hypervisor"
	};

	static char *amd_feature2_names[] = {
		/*  0 */ "lahf_lm", "cmp_legacy", "svm", "extapic",
		/*  4 */ "cr8_legacy", "abm", "sse4a", "misalignsse",
		/*  8 */ "3dnowprefetch", "osvw", "ibs", "xop",
		/* 12 */ "skinit", "wdt", "", "lwp",
		/* 16 */ "fma4", "tce", "", "nodeid_msr",
		/* 20 */ "", "tbm", "topoext", "perfctr_core",
		/* 24 */ "perfctr_nb", "", "bpext", "ptsc",
		/* 28 */ "perfctr_llc", "mwaitx", "", ""
	};

	static char *cpu_stdext_feature_names[] = {
		/*  0 */ "fsgsbase", "tsc_adjust", "sgx", "bmi1",
		/*  4 */ "hle", "avx2", "", "smep",
		/*  8 */ "bmi2", "erms", "invpcid", "rtm",
		/* 12 */ "cqm", "", "mpx", "rdt_a",
		/* 16 */ "avx512f", "avx512dq", "rdseed", "adx",
		/* 20 */ "smap", "avx512ifma", "", "clflushopt",
		/* 24 */ "clwb", "intel_pt", "avx512pf", "avx512er",
		/* 28 */ "avx512cd", "sha_ni", "avx512bw", "avx512vl"
	};

	static char *cpu_stdext_feature2_names[] = {
		/*  0 */ "prefetchwt1", "avx512vbmi", "umip", "pku",
		/*  4 */ "ospke", "waitpkg", "avx512_vbmi2", "",
		/*  8 */ "gfni", "vaes", "vpclmulqdq", "avx512_vnni",
		/* 12 */ "avx512_bitalg", "", "avx512_vpopcntdq", "",
		/* 16 */ "", "", "", "",
		/* 20 */ "", "", "rdpid", "",
		/* 24 */ "", "cldemote", "", "movdiri",
		/* 28 */ "movdir64b", "enqcmd", "sgx_lc", ""
	};

	static char *cpu_stdext_feature3_names[] = {
		/*  0 */ "", "", "avx512_4vnniw", "avx512_4fmaps",
		/*  4 */ "fsrm", "", "", "",
		/*  8 */ "avx512_vp2intersect", "", "md_clear", "",
		/* 12 */ "", "", "", "",
		/* 16 */ "", "", "pconfig", "",
		/* 20 */ "", "", "", "",
		/* 24 */ "", "", "ibrs", "stibp",
		/* 28 */ "flush_l1d", "arch_capabilities", "core_capabilities", "ssbd"
	};

	static char *cpu_stdext_feature_l1_names[] = {
		/*  0 */ "xsaveopt", "xsavec", "xgetbv1", "xsaves",
		/*  4 */ "xfd"
	};

	static char *power_flags[] = {
		"ts",           "fid",          "vid",
		"ttp",          "tm",           "stc",
		"100mhzsteps",  "hwpstate",     "",
		"cpb",          "eff_freq_ro",  "proc_feedback",
		"acc_power",
	};

#ifdef __i386__
	switch (cpu_vendor_id) {
	case CPU_VENDOR_AMD:
		if (cpu_class < CPUCLASS_686)
			cpu_feature_names[16] = "fcmov";
		break;
	case CPU_VENDOR_CYRIX:
		cpu_feature_names[24] = "cxmmx";
		break;
	}
#endif
	if (cpu_exthigh >= 0x80000006)
		do_cpuid(0x80000006, cache_size);
	else
		memset(cache_size, 0, sizeof(cache_size));
	for (i = 0; i < mp_ncpus; ++i) {
		fqmhz = 0;
		fqkhz = 0;
		freq = atomic_load_acq_64(&tsc_freq);
		if (freq != 0) {
			fqmhz = (freq + 4999) / 1000000;
			fqkhz = ((freq + 4999) / 10000) % 100;
		}
		sbuf_printf(sb,
		    "processor\t: %d\n"
		    "vendor_id\t: %.20s\n"
		    "cpu family\t: %u\n"
		    "model\t\t: %u\n"
		    "model name\t: %s\n"
		    "stepping\t: %u\n"
		    "cpu MHz\t\t: %d.%02d\n"
		    "cache size\t: %d KB\n"
		    "physical id\t: %d\n"
		    "siblings\t: %d\n"
		    "core id\t\t: %d\n"
		    "cpu cores\t: %d\n"
		    "apicid\t\t: %d\n"
		    "initial apicid\t: %d\n"
		    "fpu\t\t: %s\n"
		    "fpu_exception\t: %s\n"
		    "cpuid level\t: %d\n"
		    "wp\t\t: %s\n",
		    i, cpu_vendor, CPUID_TO_FAMILY(cpu_id),
		    CPUID_TO_MODEL(cpu_id), cpu_model, cpu_id & CPUID_STEPPING,
		    fqmhz, fqkhz,
		    (cache_size[2] >> 16), 0, mp_ncpus, i, mp_ncpus,
		    i, i, /*cpu_id & CPUID_LOCAL_APIC_ID ??*/
		    (cpu_feature & CPUID_FPU) ? "yes" : "no", "yes",
		    CPUID_TO_FAMILY(cpu_id), "yes");
		sbuf_cat(sb, "flags\t\t:");
		for (j = 0; j < nitems(cpu_feature_names); j++)
			if (cpu_feature & (1 << j) &&
			    cpu_feature_names[j][0] != '\0')
				sbuf_printf(sb, " %s", cpu_feature_names[j]);
		for (j = 0; j < nitems(amd_feature_names); j++)
			if (amd_feature & (1 << j) &&
			    amd_feature_names[j][0] != '\0')
				sbuf_printf(sb, " %s", amd_feature_names[j]);
		for (j = 0; j < nitems(cpu_feature2_names); j++)
			if (cpu_feature2 & (1 << j) &&
			    cpu_feature2_names[j][0] != '\0')
				sbuf_printf(sb, " %s", cpu_feature2_names[j]);
		for (j = 0; j < nitems(amd_feature2_names); j++)
			if (amd_feature2 & (1 << j) &&
			    amd_feature2_names[j][0] != '\0')
				sbuf_printf(sb, " %s", amd_feature2_names[j]);
		for (j = 0; j < nitems(cpu_stdext_feature_names); j++)
			if (cpu_stdext_feature & (1 << j) &&
			    cpu_stdext_feature_names[j][0] != '\0')
				sbuf_printf(sb, " %s",
				    cpu_stdext_feature_names[j]);
		if (tsc_is_invariant)
			sbuf_cat(sb, " constant_tsc");
		for (j = 0; j < nitems(cpu_stdext_feature2_names); j++)
			if (cpu_stdext_feature2 & (1 << j) &&
			    cpu_stdext_feature2_names[j][0] != '\0')
				sbuf_printf(sb, " %s",
				    cpu_stdext_feature2_names[j]);
		for (j = 0; j < nitems(cpu_stdext_feature3_names); j++)
			if (cpu_stdext_feature3 & (1 << j) &&
			    cpu_stdext_feature3_names[j][0] != '\0')
				sbuf_printf(sb, " %s",
				    cpu_stdext_feature3_names[j]);
		if ((cpu_feature2 & CPUID2_XSAVE) != 0) {
			cpuid_count(0xd, 0x1, regs);
			for (j = 0; j < nitems(cpu_stdext_feature_l1_names); j++)
				if (regs[0] & (1 << j) &&
				    cpu_stdext_feature_l1_names[j][0] != '\0')
					sbuf_printf(sb, " %s",
					    cpu_stdext_feature_l1_names[j]);
		}
		sbuf_cat(sb, "\n");
		sbuf_printf(sb,
		    "bugs\t\t: %s\n"
		    "bogomips\t: %d.%02d\n"
		    "clflush size\t: %d\n"
		    "cache_alignment\t: %d\n"
		    "address sizes\t: %d bits physical, %d bits virtual\n",
#if defined(I586_CPU) && !defined(NO_F00F_HACK)
		    (has_f00f_bug) ? "Intel F00F" : "",
#else
		    "",
#endif
		    fqmhz * 2, fqkhz,
		    cpu_clflush_line_size, cpu_clflush_line_size,
		    cpu_maxphyaddr,
		    (cpu_maxphyaddr > 32) ? 48 : 0);
		sbuf_cat(sb, "power management: ");
		for (j = 0; j < nitems(power_flags); j++)
			if (amd_pminfo & (1 << j))
				sbuf_printf(sb, " %s", power_flags[j]);
		sbuf_cat(sb, "\n\n");

		/* XXX per-cpu vendor / class / model / id? */
	}
	sbuf_cat(sb, "\n");

	return (0);
}
#else
/* ARM64TODO: implement non-stubbed linprocfs_docpuinfo */
static int
linprocfs_docpuinfo(PFS_FILL_ARGS)
{
	int i;

	for (i = 0; i < mp_ncpus; ++i) {
		sbuf_printf(sb,
		    "processor\t: %d\n"
		    "BogoMIPS\t: %d.%02d\n",
		    i, 0, 0);
		sbuf_cat(sb, "Features\t: ");
		sbuf_cat(sb, "\n");
		sbuf_printf(sb,
		    "CPU implementer\t: \n"
		    "CPU architecture: \n"
		    "CPU variant\t: 0x%x\n"
		    "CPU part\t: 0x%x\n"
		    "CPU revision\t: %d\n",
		    0, 0, 0);
		sbuf_cat(sb, "\n");
	}

	return (0);
}
#endif /* __i386__ || __amd64__ */

static int
_mtab_helper(const struct pfs_node *pn, const struct statfs *sp,
    const char **mntfrom, const char **mntto, const char **fstype)
{
	/* determine device name */
	*mntfrom = sp->f_mntfromname;

	/* determine mount point */
	*mntto = sp->f_mntonname;

	/* determine fs type */
	*fstype = sp->f_fstypename;
	if (strcmp(*fstype, pn->pn_info->pi_name) == 0)
		*mntfrom = *fstype = "proc";
	else if (strcmp(*fstype, "procfs") == 0)
		return (ECANCELED);

	if (strcmp(*fstype, "autofs") == 0) {
		/*
		 * FreeBSD uses eg "map -hosts", whereas Linux
		 * expects just "-hosts".
		 */
		if (strncmp(*mntfrom, "map ", 4) == 0)
			*mntfrom += 4;
	}

	if (strcmp(*fstype, "linsysfs") == 0) {
		*mntfrom = *fstype = "sysfs";
	} else {
		/* For Linux msdosfs is called vfat */
		if (strcmp(*fstype, "msdosfs") == 0)
			*fstype = "vfat";
	}
	return (0);
}

static void
_sbuf_mntoptions_helper(struct sbuf *sb, uint64_t f_flags)
{
	sbuf_cat(sb, (f_flags & MNT_RDONLY) ? "ro" : "rw");
#define ADD_OPTION(opt, name) \
	if (f_flags & (opt)) sbuf_cat(sb, "," name);
	ADD_OPTION(MNT_SYNCHRONOUS,	"sync");
	ADD_OPTION(MNT_NOEXEC,		"noexec");
	ADD_OPTION(MNT_NOSUID,		"nosuid");
	ADD_OPTION(MNT_UNION,		"union");
	ADD_OPTION(MNT_ASYNC,		"async");
	ADD_OPTION(MNT_SUIDDIR,		"suiddir");
	ADD_OPTION(MNT_NOSYMFOLLOW,	"nosymfollow");
	ADD_OPTION(MNT_NOATIME,		"noatime");
#undef ADD_OPTION
}

/*
 * Filler function for proc/mtab and proc/<pid>/mounts.
 *
 * /proc/mtab doesn't exist in Linux' procfs, but is included here so
 * users can symlink /compat/linux/etc/mtab to /proc/mtab
 */
/* Linux mount tables encode whitespace and backslashes as octal escapes. */
static void
linprocfs_mnt_escape(struct sbuf *sb, const char *str)
{

	for (; *str != '\0'; str++) {
		switch (*str) {
		case ' ': case '\t': case '\n': case '\\':
			sbuf_printf(sb, "\\%03o", (unsigned char)*str);
			break;
		default:
			sbuf_putc(sb, *str);
			break;
		}
	}
}

static int
linprocfs_domtab(PFS_FILL_ARGS)
{
	const char *mntto, *mntfrom, *fstype;
	char *dlep, *flep;
	struct vnode *vp;
	struct pwd *pwd;
	size_t lep_len;
	int error;
	struct statfs *buf, *sp;
	size_t count;

	/*
	 * Resolve emulation tree prefix
	 */
	flep = NULL;
	pwd = pwd_hold(td);
	vp = pwd->pwd_adir;
	error = vn_fullpath_global(vp, &dlep, &flep);
	pwd_drop(pwd);
	if (error != 0)
		return (error);
	lep_len = strlen(dlep);

	buf = NULL;
	error = kern_getfsstat(td, &buf, SIZE_T_MAX, &count,
	    UIO_SYSSPACE, MNT_WAIT);
	if (error != 0) {
		goto out;
	}

	for (sp = buf; count > 0; sp++, count--) {
		error = _mtab_helper(pn, sp, &mntfrom, &mntto, &fstype);
		if (error != 0) {
			MPASS(error == ECANCELED);
			continue;
		}

		/* determine mount point */
		if (strncmp(mntto, dlep, lep_len) == 0 && mntto[lep_len] == '/')
			mntto += lep_len;

		linprocfs_mnt_escape(sb, mntfrom);
		sbuf_putc(sb, ' ');
		linprocfs_mnt_escape(sb, mntto);
		sbuf_printf(sb, " %s ", fstype);
		_sbuf_mntoptions_helper(sb, sp->f_flags);
		/* a real Linux mtab will also show NFS options */
		sbuf_printf(sb, " 0 0\n");
	}

	error = 0;
out:
	free(buf, M_TEMP);
	free(flep, M_TEMP);
	return (error);
}

static int
linprocfs_doprocmountinfo(PFS_FILL_ARGS)
{
	const char *mntfrom, *mntto, *fstype;
	char *dlep, *flep;
	struct statfs *buf, *sp;
	size_t count, lep_len;
	struct vnode *vp, *rootvp;
	struct mount *mp;
	struct stat attr;
	uint64_t id, parent;
	struct pwd *pwd;
	int error;

	/*
	 * Resolve emulation tree prefix
	 */
	flep = NULL;
	pwd = pwd_hold(td);
	vp = pwd->pwd_adir;
	error = vn_fullpath_global(vp, &dlep, &flep);
	pwd_drop(pwd);
	if (error != 0)
		return (error);
	lep_len = strlen(dlep);

	buf = NULL;
	error = kern_getfsstat(td, &buf, SIZE_T_MAX, &count,
	    UIO_SYSSPACE, MNT_WAIT);
	if (error != 0)
		goto out;

	for (sp = buf; count > 0; sp++, count--) {
		error = _mtab_helper(pn, sp, &mntfrom, &mntto, &fstype);
		if (error != 0) {
			MPASS(error == ECANCELED);
			continue;
		}

		if (strncmp(mntto, dlep, lep_len) == 0 && mntto[lep_len] == '/')
			mntto += lep_len;
#if 0
		/*
		 * If the prefix is a chroot, and this mountpoint is not under
		 * the prefix, we should skip it.  Leave it for now for
		 * consistency with procmtab above.
		 */
		else
			continue;
#endif

		/* Hold this mount while obtaining its actual parent and device.
		 */
		mp = vfs_getvfs(&sp->f_fsid);
		if (mp == NULL)
			continue;
		error = vfs_busy(mp, 0);
		if (error != 0) {
			vfs_rel(mp);
			continue;
		}
		id = linux_mount_id(mp);
		parent = mp->mnt_vnodecovered != NULL ?
		    linux_mount_id(mp->mnt_vnodecovered->v_mount) :
		    id;
		error = VFS_ROOT(mp, LK_SHARED, &rootvp);
		if (error == 0) {
			error = VOP_STAT(rootvp, &attr, td->td_ucred, NOCRED);
			if (error == 0)
				translate_vnhook_major_minor(rootvp, &attr);
			vput(rootvp);
		}
		vfs_unbusy(mp);
		vfs_rel(mp);
		if (error != 0)
			goto out;
		sbuf_printf(sb, "%ju %ju %u:%u / ", (uintmax_t)id,
		    (uintmax_t)parent,
		    attr.st_dev == NODEV ? 0 : major(attr.st_dev) & 0xfff,
		    attr.st_dev == NODEV ? 0 : minor(attr.st_dev) & 0xfffff);
		linprocfs_mnt_escape(sb, mntto);
		sbuf_putc(sb, ' ');
		/* (6) mount options */
		_sbuf_mntoptions_helper(sb, sp->f_flags);
		/*
		 * (7) zero or more optional fields -- again, namespace related
		 *
		 * (8) End of variable length fields separator ("-")
		 *
		 * (9) fstype
		 *
		 * (10) mount from
		 *
		 * (11) "superblock" options -- like (6), but different
		 * semantics in Linux
		 */
		sbuf_printf(sb, " - %s ", fstype);
		linprocfs_mnt_escape(sb, mntfrom);
		sbuf_printf(sb, " %s\n",
		    (sp->f_flags & MNT_RDONLY) ? "ro" : "rw");
	}

	error = 0;
out:
	free(buf, M_TEMP);
	free(flep, M_TEMP);
	return (error);
}

/*
 * Filler function for proc/partitions
 */
static int
linprocfs_dopartitions(PFS_FILL_ARGS)
{
	struct g_class *cp;
	struct g_geom *gp;
	struct g_provider *pp;
	int major, minor;

	g_topology_lock();
	sbuf_printf(sb, "major minor  #blocks  name\n\n");

	LIST_FOREACH(cp, &g_classes, class) {
		if (strcmp(cp->name, "DISK") == 0 ||
		    strcmp(cp->name, "PART") == 0)
			LIST_FOREACH(gp, &cp->geom, geom) {
				LIST_FOREACH(pp, &gp->provider, provider) {
					if (linux_driver_get_major_minor(
					    pp->name, &major, &minor) != 0) {
						major = 0;
						minor = 0;
					}
					sbuf_printf(sb, "%4d  %7d %10lld %s\n",
					    major, minor,
					    B2K((long long)pp->mediasize),
					    pp->name);
				}
			}
	}
	g_topology_unlock();

	return (0);
}

/*
 * Filler function for proc/stat
 *
 * Output depends on kernel version:
 *
 * v2.5.40 <=
 *   user nice system idle
 * v2.5.41
 *   user nice system idle iowait
 * v2.6.11
 *   user nice system idle iowait irq softirq steal
 * v2.6.24
 *   user nice system idle iowait irq softirq steal guest
 * v2.6.33 >=
 *   user nice system idle iowait irq softirq steal guest guest_nice
 */
static int
linprocfs_dostat(PFS_FILL_ARGS)
{
	struct pcpu *pcpu;
	long cp_time[CPUSTATES];
	long *cp;
	struct timeval boottime;
	int i;
	char *zero_pad;
	bool has_intr = true;

	if (linux_kernver(td) >= LINUX_KERNVER(2,6,33)) {
		zero_pad = " 0 0 0 0\n";
	} else if (linux_kernver(td) >= LINUX_KERNVER(2,6,24)) {
		zero_pad = " 0 0 0\n";
	} else if (linux_kernver(td) >= LINUX_KERNVER(2,6,11)) {
		zero_pad = " 0 0\n";
	} else if (linux_kernver(td) >= LINUX_KERNVER(2,5,41)) {
		has_intr = false;
		zero_pad = " 0\n";
	} else {
		has_intr = false;
		zero_pad = "\n";
	}

	read_cpu_time(cp_time);
	getboottime(&boottime);
	/* Parameters common to all versions */
	sbuf_printf(sb, "cpu %lu %lu %lu %lu",
	    T2J(cp_time[CP_USER]),
	    T2J(cp_time[CP_NICE]),
	    T2J(cp_time[CP_SYS]),
	    T2J(cp_time[CP_IDLE]));

	/* Print interrupt stats if available */
	if (has_intr) {
		sbuf_printf(sb, " 0 %lu", T2J(cp_time[CP_INTR]));
	}

	/* Pad out remaining fields depending on version */
	sbuf_printf(sb, "%s", zero_pad);

	CPU_FOREACH(i) {
		pcpu = pcpu_find(i);
		cp = pcpu->pc_cp_time;
		sbuf_printf(sb, "cpu%d %lu %lu %lu %lu", i,
		    T2J(cp[CP_USER]),
		    T2J(cp[CP_NICE]),
		    T2J(cp[CP_SYS]),
		    T2J(cp[CP_IDLE]));

		if (has_intr) {
			sbuf_printf(sb, " 0 %lu", T2J(cp[CP_INTR]));
		}

		sbuf_printf(sb, "%s", zero_pad);
	}
	sbuf_printf(sb,
	    "disk 0 0 0 0\n"
	    "page %ju %ju\n"
	    "swap %ju %ju\n"
	    "intr %ju\n"
	    "ctxt %ju\n"
	    "btime %lld\n",
	    (uintmax_t)VM_CNT_FETCH(v_vnodepgsin),
	    (uintmax_t)VM_CNT_FETCH(v_vnodepgsout),
	    (uintmax_t)VM_CNT_FETCH(v_swappgsin),
	    (uintmax_t)VM_CNT_FETCH(v_swappgsout),
	    (uintmax_t)VM_CNT_FETCH(v_intr),
	    (uintmax_t)VM_CNT_FETCH(v_swtch),
	    (long long)boottime.tv_sec);
	return (0);
}

static int
linprocfs_doswaps(PFS_FILL_ARGS)
{
	struct xswdev xsw;
	uintmax_t total, used;
	int n, priority;
	char devname[SPECNAMELEN + 1];

	sbuf_printf(sb, "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");
	for (n = 0; ; n++) {
		if (swap_dev_info(n, &xsw, devname, sizeof(devname),
		    &priority) != 0)
			break;
		total = (uintmax_t)xsw.xsw_nblks * PAGE_SIZE / 1024;
		used  = (uintmax_t)xsw.xsw_used * PAGE_SIZE / 1024;

		/*
		 * The space and not tab after the device name is on
		 * purpose.  Linux does so.
		 */
		sbuf_printf(sb, "/dev/%-34s unknown\t\t%jd\t%jd\t%d\n",
		    devname, total, used, priority);
	}
	return (0);
}

/*
 * Filler function for proc/uptime
 */
static int
linprocfs_douptime(PFS_FILL_ARGS)
{
	long cp_time[CPUSTATES];
	struct timeval tv;

	getmicrouptime(&tv);
	read_cpu_time(cp_time);
	sbuf_printf(sb, "%lld.%02ld %ld.%02lu\n",
	    (long long)tv.tv_sec, tv.tv_usec / 10000,
	    T2S(cp_time[CP_IDLE] / mp_ncpus),
	    T2CS(cp_time[CP_IDLE] / mp_ncpus) % 100);
	return (0);
}

/*
 * Get OS build date
 */
static void
linprocfs_osbuild(struct thread *td, struct sbuf *sb)
{
#if 0
	char osbuild[256];
	char *cp1, *cp2;

	strncpy(osbuild, version, 256);
	osbuild[255] = '\0';
	cp1 = strstr(osbuild, "\n");
	cp2 = strstr(osbuild, ":");
	if (cp1 && cp2) {
		*cp1 = *cp2 = '\0';
		cp1 = strstr(osbuild, "#");
	} else
		cp1 = NULL;
	if (cp1)
		sbuf_printf(sb, "%s%s", cp1, cp2 + 1);
	else
#endif
		sbuf_cat(sb, "#4 Sun Dec 18 04:30:00 CET 1977");
}

/*
 * Get OS builder
 */
static void
linprocfs_osbuilder(struct thread *td, struct sbuf *sb)
{
#if 0
	char builder[256];
	char *cp;

	cp = strstr(version, "\n    ");
	if (cp) {
		strncpy(builder, cp + 5, 256);
		builder[255] = '\0';
		cp = strstr(builder, ":");
		if (cp)
			*cp = '\0';
	}
	if (cp)
		sbuf_cat(sb, builder);
	else
#endif
		sbuf_cat(sb, "des@freebsd.org");
}

/*
 * Filler function for proc/version
 */
static int
linprocfs_doversion(PFS_FILL_ARGS)
{
	char osname[LINUX_MAX_UTSNAME];
	char osrelease[LINUX_MAX_UTSNAME];

	linux_get_osname(td, osname);
	linux_get_osrelease(td, osrelease);
	sbuf_printf(sb, "%s version %s (", osname, osrelease);
	linprocfs_osbuilder(td, sb);
	sbuf_cat(sb, ") (gcc version " __VERSION__ ") ");
	linprocfs_osbuild(td, sb);
	sbuf_cat(sb, "\n");

	return (0);
}

/*
 * Filler function for proc/loadavg
 */
static int
linprocfs_doloadavg(PFS_FILL_ARGS)
{

	sbuf_printf(sb,
	    "%d.%02d %d.%02d %d.%02d %d/%d %d\n",
	    (int)(averunnable.ldavg[0] / averunnable.fscale),
	    (int)(averunnable.ldavg[0] * 100 / averunnable.fscale % 100),
	    (int)(averunnable.ldavg[1] / averunnable.fscale),
	    (int)(averunnable.ldavg[1] * 100 / averunnable.fscale % 100),
	    (int)(averunnable.ldavg[2] / averunnable.fscale),
	    (int)(averunnable.ldavg[2] * 100 / averunnable.fscale % 100),
	    1,				/* number of running tasks */
	    nprocs,			/* number of tasks */
	    lastpid			/* the last pid */
	);
	return (0);
}

static int
linprocfs_get_tty_nr(struct proc *p)
{
	struct session *sp;
	const char *ttyname;
	int error, major, minor, nr;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	sx_assert(&proctree_lock, SX_LOCKED);

	if ((p->p_flag & P_CONTROLT) == 0)
		return (-1);

	sp = p->p_pgrp->pg_session;
	if (sp == NULL)
		return (-1);

	ttyname = devtoname(sp->s_ttyp->t_dev);
	error = linux_driver_get_major_minor(ttyname, &major, &minor);
	if (error != 0)
		return (-1);

	nr = makedev(major, minor);
	return (nr);
}

/* Called with the process locked; never retain the returned thread. */
static pid_t
linprocfs_thread_id(struct thread *target, uint64_t *cookie)
{
	struct linux_emuldata *em;

	PROC_LOCK_ASSERT(target->td_proc, MA_OWNED);
	if (SV_PROC_ABI(target->td_proc) != SV_ABI_LINUX ||
	    !SV_PROC_FLAG(target->td_proc, SV_LP64))
		return (0);
	em = target->td_emuldata;
	if (em == NULL)
		return (0);
	*cookie = linux_thread_proc_cookie(target);
	return (em->em_tid);
}

static struct thread *
linprocfs_find_thread(struct proc *p, pid_t tid, uint64_t cookie)
{
	struct thread *target;
	uint64_t current;

	FOREACH_THREAD_IN_PROC(p, target) {
		if (linprocfs_thread_id(target, &current) ==
			(tid != 0 ? tid : p->p_pid) &&
		    (cookie == 0 || current == cookie))
			return (target);
	}
	return (tid == 0 ? FIRST_THREAD_IN_PROC(p) : NULL);
}

static int
linprocfs_threadself(PFS_FILL_ARGS)
{
	uint64_t cookie;
	pid_t tid;

	PROC_LOCK(td->td_proc);
	tid = linprocfs_thread_id(td, &cookie);
	PROC_UNLOCK(td->td_proc);
	if (tid == 0)
		return (ENOENT);
	sbuf_printf(sb, "%d/task/%d", td->td_proc->p_pid, tid);
	return (0);
}

/* Linux comm writes affect only a member of the caller's thread group. */
static int
linprocfs_doproccomm_thread(PFS_FILL_ARGS, pid_t tid, uint64_t cookie)
{
	struct thread *target;
	char name[16] = { 0 };
	ssize_t count;
	int error;

	if (uio->uio_rw == UIO_WRITE) {
		count = uio->uio_resid;
		error = uiomove(name, MIN(count, sizeof(name) - 1), uio);
		if (error != 0)
			return (error);
		if (p != td->td_proc)
			return (EINVAL);
	}
	PROC_LOCK(p);
	target = linprocfs_find_thread(p, tid, cookie);
	if (target == NULL) {
		PROC_UNLOCK(p);
		return (ESRCH);
	}
	thread_lock(target);
	if (uio->uio_rw == UIO_WRITE) {
		strlcpy(target->td_name, name, sizeof(target->td_name));
		if (tid == 0 || tid == p->p_pid)
			strlcpy(p->p_comm, name, sizeof(p->p_comm));
	} else
		strlcpy(name, target->td_name, sizeof(name));
	thread_unlock(target);
	PROC_UNLOCK(p);
	if (uio->uio_rw == UIO_WRITE) {
		/* Linux copies at most 15 bytes but acknowledges the full
		 * write. */
		uio->uio_offset += uio->uio_resid;
		uio->uio_resid = 0;
	} else
		sbuf_printf(sb, "%s\n", name);
	return (0);
}

static int
linprocfs_doproccomm(PFS_FILL_ARGS)
{
	return (linprocfs_doproccomm_thread(PFS_FILL_ARGNAMES, 0, 0));
}

static int
linprocfs_commattr(PFS_ATTR_ARGS)
{
	vap->va_mode = 0644;
	return (0);
}

/*
 * Filler function for proc/pid/stat
 */
static int
linprocfs_doprocstat_thread(PFS_FILL_ARGS, pid_t tid, uint64_t cookie)
{
	struct kinfo_proc kp;
	struct thread *target;
	char name[MAXCOMLEN + 1];
	struct timeval boottime;
	char state;
	static int ratelimit = 0;
	int tty_nr, policy, rtprio;
	l_sigset_t pending, blocked, ignored, caught;
	struct sigacts *ps;
	uint64_t starttime;
	vm_offset_t startcode, startdata;

	getboottime(&boottime);
	sx_slock(&proctree_lock);
	PROC_LOCK(p);
	target = linprocfs_find_thread(p, tid, cookie);
	if (target == NULL) {
		PROC_UNLOCK(p);
		sx_sunlock(&proctree_lock);
		return (ESRCH);
	}
	bsd_to_linux_sigset(&target->td_siglist, &pending);
	bsd_to_linux_sigset(&target->td_sigmask, &blocked);
	ps = p->p_sigacts;
	mtx_lock(&ps->ps_mtx);
	bsd_to_linux_sigset(&ps->ps_sigignore, &ignored);
	bsd_to_linux_sigset(&ps->ps_sigcatch, &caught);
	mtx_unlock(&ps->ps_mtx);
	fill_kinfo_proc(p, &kp);
	starttime = tid != 0 && tid != p->p_pid ?
	    linux_thread_proc_start(target) : TV2J(&kp.ki_start) - TV2J(&boottime);
	PROC_STATLOCK(p);
	thread_lock(target);
	strlcpy(name, target->td_name, sizeof(name));
	policy = target->td_pri_class == RTP_PRIO_FIFO ? 1 :
	    target->td_pri_class == RTP_PRIO_REALTIME  ? 2 :
							 0;
	rtprio = 0;
	if (policy != 0) {
		rtprio = RTP_PRIO_MAX -
		    (target->td_base_user_pri - PRI_MIN_REALTIME);
		if (linux_map_sched_prio)
			rtprio = (rtprio * 99 +
				     (RTP_PRIO_MAX - RTP_PRIO_MIN - 1)) /
				(RTP_PRIO_MAX - RTP_PRIO_MIN) +
			    1;
	}
	if (tid != 0) {
		rufetchtd(target, &kp.ki_rusage);
		kp.ki_lastcpu = target->td_lastcpu;
		kp.ki_pri.pri_user = target->td_user_pri;
		kp.ki_pri.pri_class = target->td_pri_class;
		kp.ki_stat = P_SHOULDSTOP(p) ? SSTOP :
		    TD_IS_RUNNING(target) || TD_ON_RUNQ(target) ||
			TD_CAN_RUN(target) ?
					       SRUN :
					       SSLEEP;
	}
	thread_unlock(target);
	PROC_STATUNLOCK(p);
	tty_nr = linprocfs_get_tty_nr(p);
	sx_sunlock(&proctree_lock);
	if (p->p_vmspace) {
	   startcode = (vm_offset_t)p->p_vmspace->vm_taddr;
	   startdata = (vm_offset_t)p->p_vmspace->vm_daddr;
	} else {
	   startcode = 0;
	   startdata = 0;
	}
	sbuf_printf(sb, "%d", tid != 0 ? tid : p->p_pid);
#define PS_ADD(name, fmt, arg) sbuf_printf(sb, " " fmt, arg)
	PS_ADD("comm", "(%s)", name);
	if (kp.ki_stat <= 0 || kp.ki_stat > sizeof(linux_state)) {
		state = 'R';

		if (ratelimit == 0) {
			printf("linprocfs: don't know how to handle unknown FreeBSD state %d/%zd, mapping to R\n",
			    kp.ki_stat, sizeof(linux_state));
			++ratelimit;
		}
	} else
		state = linux_state[kp.ki_stat - 1];
	PS_ADD("state",		"%c",	state);
	PS_ADD("ppid",		"%d",	p->p_pptr ? p->p_pptr->p_pid : 0);
	PS_ADD("pgrp",		"%d",	p->p_pgid);
	PS_ADD("session",	"%d",	p->p_session->s_sid);
	PROC_UNLOCK(p);
	PS_ADD("tty",		"%d",	tty_nr);
	PS_ADD("tpgid",		"%d",	kp.ki_tpgid);
	PS_ADD("flags",		"%u",	0); /* XXX */
	PS_ADD("minflt",	"%lu",	kp.ki_rusage.ru_minflt);
	PS_ADD("cminflt",	"%lu",	kp.ki_rusage_ch.ru_minflt);
	PS_ADD("majflt",	"%lu",	kp.ki_rusage.ru_majflt);
	PS_ADD("cmajflt",	"%lu",	kp.ki_rusage_ch.ru_majflt);
	PS_ADD("utime",		"%ld",	TV2J(&kp.ki_rusage.ru_utime));
	PS_ADD("stime",		"%ld",	TV2J(&kp.ki_rusage.ru_stime));
	PS_ADD("cutime",	"%ld",	TV2J(&kp.ki_rusage_ch.ru_utime));
	PS_ADD("cstime",	"%ld",	TV2J(&kp.ki_rusage_ch.ru_stime));
	PS_ADD("priority", "%d", policy != 0 ? -rtprio - 1 : kp.ki_nice + 20);
	PS_ADD("nice",		"%d",	kp.ki_nice); /* 19 (nicest) to -19 */
	PS_ADD("num_threads", "%d", kp.ki_numthreads);
	PS_ADD("itrealvalue",	"%d",	0); /* XXX */
	PS_ADD("starttime",	"%ju",	(uintmax_t)starttime);
	PS_ADD("vsize",		"%ju",	(uintmax_t)kp.ki_size);
	PS_ADD("rss",		"%ju",	(uintmax_t)kp.ki_rssize);
	PS_ADD("rlim",		"%lu",	kp.ki_rusage.ru_maxrss);
	PS_ADD("startcode",	"%ju",	(uintmax_t)startcode);
	PS_ADD("endcode",	"%ju",	(uintmax_t)startdata);
	PS_ADD("startstack",	"%u",	0); /* XXX */
	PS_ADD("kstkesp",	"%u",	0); /* XXX */
	PS_ADD("kstkeip",	"%u",	0); /* XXX */
	PS_ADD("signal", "%u", (unsigned)(pending.__mask & 0x7fffffff));
	PS_ADD("blocked", "%u", (unsigned)(blocked.__mask & 0x7fffffff));
	PS_ADD("sigignore", "%u", (unsigned)(ignored.__mask & 0x7fffffff));
	PS_ADD("sigcatch", "%u", (unsigned)(caught.__mask & 0x7fffffff));
	PS_ADD("wchan",		"%u",	0); /* XXX */
	PS_ADD("nswap",		"%lu",	kp.ki_rusage.ru_nswap);
	PS_ADD("cnswap",	"%lu",	kp.ki_rusage_ch.ru_nswap);
	PS_ADD("exitsignal",	"%d",	0); /* XXX */
	PS_ADD("processor",	"%u",	kp.ki_lastcpu);
	PS_ADD("rt_priority", "%u", rtprio);
	PS_ADD("policy", "%u", policy);
#undef PS_ADD
	sbuf_putc(sb, '\n');

	return (0);
}

static int
linprocfs_doprocstat(PFS_FILL_ARGS)
{
	return (linprocfs_doprocstat_thread(PFS_FILL_ARGNAMES, 0, 0));
}

/* Keep the historical library estimate bounded by the mapped address space. */
static segsz_t
linprocfs_vmlib(const struct kinfo_proc *kp)
{
	uintmax_t total, accounted;

	total = B2P((uintmax_t)kp->ki_size);
	accounted = (uintmax_t)kp->ki_dsize + kp->ki_ssize + kp->ki_tsize + 1;
	return (total > accounted ? total - accounted : 0);
}

/* Count user-locked mappings, excluding kernel wiring of user pages. */
static uintmax_t
linprocfs_vmlck(struct proc *p)
{
	struct vmspace *vm;
	vm_map_entry_t entry;
	uintmax_t bytes = 0;

	vm = vmspace_acquire_ref(p);
	if (vm == NULL)
		return (0);
	vm_map_lock_read(&vm->vm_map);
	VM_MAP_ENTRY_FOREACH(entry, &vm->vm_map) {
		if ((entry->eflags & MAP_ENTRY_USER_WIRED) != 0)
			bytes += entry->end - entry->start;
	}
	vm_map_unlock_read(&vm->vm_map);
	vmspace_free(vm);
	return (bytes);
}

static void
linprocfs_task_name(struct sbuf *sb, const char *name)
{
	for (; *name != '\0'; name++) {
		if (*name == '\n')
			sbuf_cat(sb, "\\n");
		else if (*name == '\\')
			sbuf_cat(sb, "\\\\");
		else
			sbuf_putc(sb, *name);
	}
}

/*
 * Filler function for proc/pid/statm
 */
static int
linprocfs_doprocstatm(PFS_FILL_ARGS)
{
	struct kinfo_proc kp;
	segsz_t lsize;

	sx_slock(&proctree_lock);
	PROC_LOCK(p);
	fill_kinfo_proc(p, &kp);
	PROC_UNLOCK(p);
	sx_sunlock(&proctree_lock);

	/*
	 * See comments in linprocfs_doprocstatus() regarding the
	 * computation of lsize.
	 */
	/* size resident share trs drs lrs dt */
	sbuf_printf(sb, "%ju ", B2P((uintmax_t)kp.ki_size));
	sbuf_printf(sb, "%ju ", (uintmax_t)kp.ki_rssize);
	sbuf_printf(sb, "%ju ", (uintmax_t)0); /* XXX */
	sbuf_printf(sb, "%ju ",	(uintmax_t)kp.ki_tsize);
	sbuf_printf(sb, "%ju ", (uintmax_t)(kp.ki_dsize + kp.ki_ssize));
	lsize = linprocfs_vmlib(&kp);
	sbuf_printf(sb, "%ju ", (uintmax_t)lsize);
	sbuf_printf(sb, "%ju\n", (uintmax_t)0); /* XXX */

	return (0);
}

/*
 * Filler function for proc/pid/status
 */
static int
linprocfs_doprocstatus_thread(PFS_FILL_ARGS, pid_t tid, uint64_t cookie)
{
	struct kinfo_proc kp;
	char *state;
	segsz_t lsize;
	struct thread *td2;
	struct sigacts *ps;
	l_sigset_t siglist, sigignore, sigcatch, pending, blocked;
	char name[MAXCOMLEN + 1];
	int i;

	sx_slock(&proctree_lock);
	PROC_LOCK(p);
	td2 = linprocfs_find_thread(p, tid, cookie);
	if (td2 == NULL) {
		PROC_UNLOCK(p);
		sx_sunlock(&proctree_lock);
		return (ESRCH);
	}
	bsd_to_linux_sigset(&td2->td_siglist, &pending);
	bsd_to_linux_sigset(&td2->td_sigmask, &blocked);
	thread_lock(td2);
	strlcpy(name, td2->td_name, sizeof(name));

	if (P_SHOULDSTOP(p)) {
		state = "T (stopped)";
	} else {
		switch(p->p_state) {
		case PRS_NEW:
			state = "I (idle)";
			break;
		case PRS_NORMAL:
			if (p->p_flag & P_WEXIT) {
				state = "X (exiting)";
				break;
			}
			switch(TD_GET_STATE(td2)) {
			case TDS_INHIBITED:
				state = "S (sleeping)";
				break;
			case TDS_RUNQ:
			case TDS_RUNNING:
				state = "R (running)";
				break;
			default:
				state = "? (unknown)";
				break;
			}
			break;
		case PRS_ZOMBIE:
			state = "Z (zombie)";
			break;
		default:
			state = "? (unknown)";
			break;
		}
	}

	thread_unlock(td2);
	fill_kinfo_proc(p, &kp);
	sx_sunlock(&proctree_lock);

	sbuf_cat(sb, "Name:\t");
	linprocfs_task_name(sb, name);
	sbuf_putc(sb, '\n');
	sbuf_printf(sb, "State:\t%s\n",		state);

	/*
	 * Credentials
	 */
	sbuf_printf(sb, "Tgid:\t%d\n",		p->p_pid);
	sbuf_printf(sb, "Pid:\t%d\n", tid != 0 ? tid : p->p_pid);
	sbuf_printf(sb, "PPid:\t%d\n",		kp.ki_ppid );
	sbuf_printf(sb, "TracerPid:\t%d\n",	kp.ki_tracer );
	sbuf_printf(sb, "Uid:\t%d\t%d\t%d\t%d\n", p->p_ucred->cr_ruid,
						p->p_ucred->cr_uid,
						p->p_ucred->cr_svuid,
						/* FreeBSD doesn't have fsuid */
						p->p_ucred->cr_uid);
	sbuf_printf(sb, "Gid:\t%d\t%d\t%d\t%d\n", p->p_ucred->cr_rgid,
						p->p_ucred->cr_gid,
						p->p_ucred->cr_svgid,
						/* FreeBSD doesn't have fsgid */
						p->p_ucred->cr_gid);
	sbuf_cat(sb, "Groups:\t");
	for (i = 0; i < p->p_ucred->cr_ngroups; i++)
		sbuf_printf(sb, "%d ",		p->p_ucred->cr_groups[i]);
	PROC_UNLOCK(p);
	sbuf_putc(sb, '\n');

	/*
	 * Memory
	 *
	 * While our approximation of VmLib may not be accurate (I
	 * don't know of a simple way to verify it, and I'm not sure
	 * it has much meaning anyway), I believe it's good enough.
	 */
	sbuf_printf(sb, "VmSize:\t%8ju kB\n",	B2K((uintmax_t)kp.ki_size));
	sbuf_printf(sb, "VmLck:\t%8ju kB\n", B2K(linprocfs_vmlck(p)));
	sbuf_printf(sb, "VmRSS:\t%8ju kB\n",	P2K((uintmax_t)kp.ki_rssize));
	sbuf_printf(sb, "VmData:\t%8ju kB\n",	P2K((uintmax_t)kp.ki_dsize));
	sbuf_printf(sb, "VmStk:\t%8ju kB\n",	P2K((uintmax_t)kp.ki_ssize));
	sbuf_printf(sb, "VmExe:\t%8ju kB\n",	P2K((uintmax_t)kp.ki_tsize));
	lsize = linprocfs_vmlib(&kp);
	sbuf_printf(sb, "VmLib:\t%8ju kB\n",	P2K((uintmax_t)lsize));

	/*
	 * Signal masks
	 */
	PROC_LOCK(p);
	bsd_to_linux_sigset(&p->p_siglist, &siglist);
	ps = p->p_sigacts;
	mtx_lock(&ps->ps_mtx);
	bsd_to_linux_sigset(&ps->ps_sigignore, &sigignore);
	bsd_to_linux_sigset(&ps->ps_sigcatch, &sigcatch);
	mtx_unlock(&ps->ps_mtx);
	PROC_UNLOCK(p);

	sbuf_printf(sb, "Threads:\t%d\n", kp.ki_numthreads);
	sbuf_printf(sb, "SigPnd:\t%016jx\n", pending.__mask);
	sbuf_printf(sb, "ShdPnd:\t%016jx\n", siglist.__mask);
	sbuf_printf(sb, "SigBlk:\t%016jx\n", blocked.__mask);
	sbuf_printf(sb, "SigIgn:\t%016jx\n",	sigignore.__mask);
	sbuf_printf(sb, "SigCgt:\t%016jx\n",	sigcatch.__mask);

	/*
	 * Linux also prints the capability masks, but we don't have
	 * capabilities yet, and when we do get them they're likely to
	 * be meaningless to Linux programs, so we lie. XXX
	 */
	sbuf_printf(sb, "CapInh:\t%016x\n",	0);
	sbuf_printf(sb, "CapPrm:\t%016x\n",	0);
	sbuf_printf(sb, "CapEff:\t%016x\n",	0);

	return (0);
}

static int
linprocfs_doprocstatus(PFS_FILL_ARGS)
{
	return (linprocfs_doprocstatus_thread(PFS_FILL_ARGNAMES, 0, 0));
}

/*
 * Filler function for proc/pid/cwd
 */
static int
linprocfs_doproccwd(PFS_FILL_ARGS)
{
	struct pwd *pwd;
	char *fullpath = "unknown";
	char *freepath = NULL;

	pwd = pwd_hold_proc(p);
	vn_fullpath(pwd->pwd_cdir, &fullpath, &freepath);
	sbuf_printf(sb, "%s", fullpath);
	if (freepath)
		free(freepath, M_TEMP);
	pwd_drop(pwd);
	return (0);
}

/*
 * Filler function for proc/pid/root
 */
static int
linprocfs_doprocroot(PFS_FILL_ARGS)
{
	struct pwd *pwd;
	struct vnode *vp;
	char *fullpath = "unknown";
	char *freepath = NULL;

	pwd = pwd_hold_proc(p);
	vp = jailed(p->p_ucred) ? pwd->pwd_jdir : pwd->pwd_rdir;
	vn_fullpath(vp, &fullpath, &freepath);
	sbuf_printf(sb, "%s", fullpath);
	if (freepath)
		free(freepath, M_TEMP);
	pwd_drop(pwd);
	return (0);
}

/*
 * Filler function for proc/pid/cmdline
 */
static int
linprocfs_doproccmdline(PFS_FILL_ARGS)
{
	int ret;

	PROC_LOCK(p);
	if ((ret = p_cansee(td, p)) != 0) {
		PROC_UNLOCK(p);
		return (ret);
	}

	/*
	 * Mimic linux behavior and pass only processes with usermode
	 * address space as valid.  Return zero silently otherwize.
	 */
	if (p->p_vmspace == &vmspace0) {
		PROC_UNLOCK(p);
		return (0);
	}
	if (p->p_args != NULL) {
		sbuf_bcpy(sb, p->p_args->ar_args, p->p_args->ar_length);
		PROC_UNLOCK(p);
		return (0);
	}

	if ((p->p_flag & P_SYSTEM) != 0) {
		PROC_UNLOCK(p);
		return (0);
	}

	PROC_UNLOCK(p);

	ret = proc_getargv(td, p, sb);
	return (ret);
}

/*
 * Filler function for proc/pid/environ
 */
static int
linprocfs_doprocenviron(PFS_FILL_ARGS)
{

	/*
	 * Mimic linux behavior and pass only processes with usermode
	 * address space as valid.  Return zero silently otherwize.
	 */
	if (p->p_vmspace == &vmspace0)
		return (0);

	return (proc_getenvv(td, p, sb));
}

static char l32_map_str[] = "%08lx-%08lx %s%s%s%s %08lx %02x:%02x %lu%s%s\n";
static char l64_map_str[] = "%016lx-%016lx %s%s%s%s %08lx %02x:%02x %lu%s%s\n";
static char vdso_str[] = "      [vdso]";
static char stack_str[] = "      [stack]";

/*
 * Filler function for proc/pid/maps
 */
static int
linprocfs_doprocmaps(PFS_FILL_ARGS)
{
	struct vmspace *vm;
	vm_map_t map;
	vm_map_entry_t entry, tmp_entry;
	vm_object_t obj, tobj, lobj;
	vm_offset_t e_start, e_end;
	vm_ooffset_t off;
	vm_prot_t e_prot;
	unsigned int last_timestamp;
	char *name = "", *freename = NULL;
	const char *l_map_str;
	ino_t ino;
	int error;
	struct vnode *vp;
	struct vattr vat;
	bool private;

	PROC_LOCK(p);
	error = p_candebug(td, p);
	PROC_UNLOCK(p);
	if (error)
		return (error);

	if (uio->uio_rw != UIO_READ)
		return (EOPNOTSUPP);

	error = 0;
	vm = vmspace_acquire_ref(p);
	if (vm == NULL)
		return (ESRCH);

	if (SV_CURPROC_FLAG(SV_LP64))
		l_map_str = l64_map_str;
	else
		l_map_str = l32_map_str;
	map = &vm->vm_map;
	vm_map_lock_read(map);
	VM_MAP_ENTRY_FOREACH(entry, map) {
		name = "";
		freename = NULL;
		/*
		 * Skip printing of the guard page of the stack region, as
		 * it confuses glibc pthread_getattr_np() method, where both
		 * the base address and size of the stack of the initial thread
		 * are calculated.
		 */
		if ((entry->eflags & (MAP_ENTRY_IS_SUB_MAP | MAP_ENTRY_GUARD)) != 0)
			continue;
		e_prot = entry->protection;
		e_start = entry->start;
		e_end = entry->end;
		obj = entry->object.vm_object;
		off = entry->offset;
		for (lobj = tobj = obj; tobj != NULL;
		    lobj = tobj, tobj = tobj->backing_object) {
			VM_OBJECT_RLOCK(tobj);
			off += lobj->backing_object_offset;
			if (lobj != obj)
				VM_OBJECT_RUNLOCK(lobj);
		}
		private = (entry->eflags & MAP_ENTRY_COW) != 0 || obj == NULL ||
		    (obj->flags & OBJ_ANON) != 0;
		last_timestamp = map->timestamp;
		vm_map_unlock_read(map);
		ino = 0;
		if (lobj) {
			vp = vm_object_vnode(lobj);
			if (vp != NULL)
				vref(vp);
			if (lobj != obj)
				VM_OBJECT_RUNLOCK(lobj);
			VM_OBJECT_RUNLOCK(obj);
			if (vp != NULL) {
				vn_fullpath(vp, &name, &freename);
				vn_lock(vp, LK_SHARED | LK_RETRY);
				VOP_GETATTR(vp, &vat, td->td_ucred);
				ino = vat.va_fileid;
				vput(vp);
			} else if (SV_PROC_ABI(p) == SV_ABI_LINUX) {
				/*
				 * sv_shared_page_base pointed out to the
				 * FreeBSD sharedpage, PAGE_SIZE is a size
				 * of it. The vDSO page is above.
				 */
				if (e_start == p->p_sysent->sv_shared_page_base +
				    PAGE_SIZE)
					name = vdso_str;
				if (e_end == p->p_sysent->sv_usrstack)
					name = stack_str;
			}
		}

		/*
		 * format:
		 *  start, end, access, offset, major, minor, inode, name.
		 */
		error = sbuf_printf(sb, l_map_str,
		    (u_long)e_start, (u_long)e_end,
		    (e_prot & VM_PROT_READ)?"r":"-",
		    (e_prot & VM_PROT_WRITE)?"w":"-",
		    (e_prot & VM_PROT_EXECUTE)?"x":"-",
		    private ? "p" : "s",
		    (u_long)off,
		    0,
		    0,
		    (u_long)ino,
		    *name ? "     " : " ",
		    name
		    );
		if (freename)
			free(freename, M_TEMP);
		vm_map_lock_read(map);
		if (error == -1) {
			error = 0;
			break;
		}
		if (last_timestamp != map->timestamp) {
			/*
			 * Look again for the entry because the map was
			 * modified while it was unlocked.  Specifically,
			 * the entry may have been clipped, merged, or deleted.
			 */
			vm_map_lookup_entry(map, e_end - 1, &tmp_entry);
			entry = tmp_entry;
		}
	}
	vm_map_unlock_read(map);
	vmspace_free(vm);

	return (error);
}

/*
 * Filler function for proc/pid/mem
 */
static int
linprocfs_doprocmem(PFS_FILL_ARGS)
{
	ssize_t resid;
	int error;

	resid = uio->uio_resid;
	error = procfs_doprocmem(PFS_FILL_ARGNAMES);

	if (uio->uio_rw == UIO_READ && resid != uio->uio_resid)
		return (0);

	if (error == EFAULT)
		error = EIO;

	return (error);
}

/*
 * Filler function for proc/net/dev
 */
static int
linprocfs_donetdev_cb(if_t ifp, void *arg)
{
	char ifname[LINUX_IFNAMSIZ];
	struct sbuf *sb = arg;

	if (ifname_bsd_to_linux_ifp(ifp, ifname, sizeof(ifname)) <= 0)
		return (ENODEV);

	sbuf_printf(sb, "%6.6s: ", ifname);
	sbuf_printf(sb, "%7ju %7ju %4ju %4ju %4lu %5lu %10lu %9ju ",
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_IBYTES),
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_IPACKETS),
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_IERRORS),
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_IQDROPS),
						/* rx_missed_errors */
	    0UL,				/* rx_fifo_errors */
	    0UL,				/* rx_length_errors +
						 * rx_over_errors +
						 * rx_crc_errors +
						 * rx_frame_errors */
	    0UL,				/* rx_compressed */
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_IMCASTS));
						/* XXX-BZ rx only? */
	sbuf_printf(sb, "%8ju %7ju %4ju %4ju %4lu %5ju %7lu %10lu\n",
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_OBYTES),
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_OPACKETS),
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_OERRORS),
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_OQDROPS),
	    0UL,				/* tx_fifo_errors */
	    (uintmax_t)if_getcounter(ifp, IFCOUNTER_COLLISIONS),
	    0UL,				/* tx_carrier_errors +
						 * tx_aborted_errors +
						 * tx_window_errors +
						 * tx_heartbeat_errors*/
	    0UL);				/* tx_compressed */
	return (0);
}

static int
linprocfs_donetdev(PFS_FILL_ARGS)
{
	struct epoch_tracker et;

	sbuf_printf(sb, "%6s|%58s|%s\n"
	    "%6s|%58s|%58s\n",
	    "Inter-", "   Receive", "  Transmit",
	    " face",
	    "bytes    packets errs drop fifo frame compressed multicast",
	    "bytes    packets errs drop fifo colls carrier compressed");

	CURVNET_SET(TD_TO_VNET(curthread));
	NET_EPOCH_ENTER(et);
	if_foreach(linprocfs_donetdev_cb, sb);
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();

	return (0);
}

struct walkarg {
	struct sbuf *sb;
};

static int
linux_route_print(struct rtentry *rt, void *vw)
{
#ifdef INET
	struct walkarg *w = vw;
	struct route_nhop_data rnd;
	struct in_addr dst, mask;
	struct nhop_object *nh;
	char ifname[16];
	uint32_t scopeid = 0;
	uint32_t gw = 0;
	uint32_t linux_flags = 0;

	rt_get_inet_prefix_pmask(rt, &dst, &mask, &scopeid);

	rt_get_rnd(rt, &rnd);

	/* select only first route in case of multipath */
	nh = nhop_select_func(rnd.rnd_nhop, 0);

	if (ifname_bsd_to_linux_ifp(nh->nh_ifp, ifname, sizeof(ifname)) <= 0)
		return (ENODEV);

	gw = (nh->nh_flags & NHF_GATEWAY)
		? nh->gw4_sa.sin_addr.s_addr : 0;

	linux_flags = RTF_UP |
		(nhop_get_rtflags(nh) & (RTF_GATEWAY | RTF_HOST));

	sbuf_printf(w->sb,
		"%s\t"
		"%08X\t%08X\t%04X\t"
		"%d\t%u\t%d\t"
		"%08X\t%d\t%u\t%u",
		ifname,
		dst.s_addr, gw, linux_flags,
		0, 0, rnd.rnd_weight,
		mask.s_addr, nh->nh_mtu, 0, 0);

	sbuf_printf(w->sb, "\n\n");
#endif
	return (0);
}

/*
 * Filler function for proc/net/route
 */
static int
linprocfs_donetroute(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	struct walkarg w = {
		.sb = sb
	};
	uint32_t fibnum = curthread->td_proc->p_fibnum;

	sbuf_printf(w.sb, "%-127s\n", "Iface\tDestination\tGateway "
               "\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU"
               "\tWindow\tIRTT");

	CURVNET_SET(TD_TO_VNET(curthread));
	NET_EPOCH_ENTER(et);
	rib_walk(fibnum, AF_INET, false, linux_route_print, &w);
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();

	return (0);
}

/*
 * Filler function for proc/sys/kernel/osrelease
 */
static int
linprocfs_doosrelease(PFS_FILL_ARGS)
{
	char osrelease[LINUX_MAX_UTSNAME];

	linux_get_osrelease(td, osrelease);
	sbuf_printf(sb, "%s\n", osrelease);

	return (0);
}

/*
 * Filler function for proc/sys/kernel/ostype
 */
static int
linprocfs_doostype(PFS_FILL_ARGS)
{
	char osname[LINUX_MAX_UTSNAME];

	linux_get_osname(td, osname);
	sbuf_printf(sb, "%s\n", osname);

	return (0);
}

/*
 * Filler function for proc/sys/kernel/version
 */
static int
linprocfs_doosbuild(PFS_FILL_ARGS)
{

	linprocfs_osbuild(td, sb);
	sbuf_cat(sb, "\n");
	return (0);
}

/*
 * Filler function for proc/sys/kernel/msgmax
 */
static int
linprocfs_domsgmax(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d\n", msginfo.msgmax);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/msgmni
 */
static int
linprocfs_domsgmni(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d\n", msginfo.msgmni);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/msgmnb
 */
static int
linprocfs_domsgmnb(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d\n", msginfo.msgmnb);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/ngroups_max
 *
 * Note that in Linux it defaults to 65536, not 1023.
 */
static int
linprocfs_dongroups_max(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d\n", ngroups_max);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/pid_max
 */
static int
linprocfs_dopid_max(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%i\n", PID_MAX);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/sem
 */
static int
linprocfs_dosem(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d %d %d %d\n", seminfo.semmsl, seminfo.semmns,
	    seminfo.semopm, seminfo.semmni);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/shmall
 */
static int
linprocfs_doshmall(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%lu\n", shminfo.shmall);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/shmmax
 */
static int
linprocfs_doshmmax(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%lu\n", shminfo.shmmax);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/shmmni
 */
static int
linprocfs_doshmmni(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%lu\n", shminfo.shmmni);
	return (0);
}

/*
 * Filler function for proc/sys/kernel/tainted
 */
static int
linprocfs_dotainted(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "0\n");
	return (0);
}

/*
 * Filler function for proc/sys/kernel/threads-max
 */
static int
linprocfs_dothreads_max(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.maxproc",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);
	sbuf_printf(sb, "%d\n", res);
	return (0);
}

/*
 * Filler function for proc/sys/vm/min_free_kbytes
 *
 * This mirrors the approach in illumos to return zero for reads. Effectively,
 * it says, no memory is kept in reserve for "atomic allocations". This class
 * of allocation can be used at times when a thread cannot be suspended.
 */
static int
linprocfs_dominfree(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d\n", 0);
	return (0);
}

/*
 * Filler function for proc/scsi/device_info
 */
static int
linprocfs_doscsidevinfo(PFS_FILL_ARGS)
{

	return (0);
}

/*
 * Filler function for proc/scsi/scsi
 */
static int
linprocfs_doscsiscsi(PFS_FILL_ARGS)
{

	return (0);
}

/*
 * Filler function for proc/devices
 */
static int
linprocfs_dodevices(PFS_FILL_ARGS)
{
	char *char_devices;
	sbuf_printf(sb, "Character devices:\n");

	char_devices = linux_get_char_devices();
	sbuf_printf(sb, "%s", char_devices);
	linux_free_get_char_devices(char_devices);

	sbuf_printf(sb, "\nBlock devices:\n");

	return (0);
}

/*
 * Filler function for proc/cmdline
 */
static int
linprocfs_docmdline(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "BOOT_IMAGE=%s", kernelname);
	sbuf_printf(sb, " ro root=302\n");
	return (0);
}

/*
 * Filler function for proc/filesystems
 */
static int
linprocfs_dofilesystems(PFS_FILL_ARGS)
{
	struct vfsconf *vfsp;

	vfsconf_slock();
	TAILQ_FOREACH(vfsp, &vfsconf, vfc_list) {
		if ((vfsp->vfc_flags & VFCF_SYNTHETIC) != 0 ||
		    strcmp(vfsp->vfc_name, "tmpfs") == 0)
			sbuf_printf(sb, "nodev");
		if (strcmp(vfsp->vfc_name, "linprocfs") == 0)
			sbuf_cat(sb, "\tproc\n");
		else if (strcmp(vfsp->vfc_name, "linsysfs") == 0)
			sbuf_cat(sb, "\tsysfs\n");
		else
			sbuf_printf(sb, "\t%s\n", vfsp->vfc_name);
	}
	vfsconf_sunlock();
	return(0);
}

/*
 * Filler function for proc/modules
 */
static int
linprocfs_domodules(PFS_FILL_ARGS)
{
#if 0
	struct linker_file *lf;

	TAILQ_FOREACH(lf, &linker_files, link) {
		sbuf_printf(sb, "%-20s%8lu%4d\n", lf->filename,
		    (unsigned long)lf->size, lf->refs);
	}
#endif
	return (0);
}

/*
 * Filler function for proc/pid/fd
 */
static int
linprocfs_fdattr(PFS_ATTR_ARGS)
{
	vap->va_mode = pn->pn_type == pfstype_dir ? 0500 : 0400;
	return (0);
}

/* Snapshot descriptor numbers without retaining pointers into the table. */
static int
linprocfs_fdlist(struct thread *td, struct proc *p, int **fds, size_t *count)
{
	struct filedesc *fdp;
	int error, limit, i;

	PROC_LOCK(p);
	error = p_candebug(td, p);
	fdp = error == 0 ? fdhold(p) : NULL;
	PROC_UNLOCK(p);
	if (error != 0 || fdp == NULL)
		return (error != 0 ? error : ENOENT);
	FILEDESC_SLOCK(fdp);
	limit = refcount_load(&fdp->fd_refcnt) != 0 ? fdp->fd_nfiles : 0;
	FILEDESC_SUNLOCK(fdp);
	*fds = mallocarray(limit, sizeof(**fds), M_TEMP, M_WAITOK);
	*count = 0;
	FILEDESC_SLOCK(fdp);
	PROC_LOCK(p);
	error = p_candebug(td, p);
	if (error == 0 && atomic_load_ptr(&p->p_fd) != fdp)
		error = ENOENT;
	for (i = 0;
	    error == 0 && refcount_load(&fdp->fd_refcnt) != 0 && i < limit;
	    i++) {
		if (fget_noref(fdp, i) != NULL)
			(*fds)[(*count)++] = i;
	}
	PROC_UNLOCK(p);
	FILEDESC_SUNLOCK(fdp);
	fddrop(fdp);
	return (error);
}

/* Take both the file and descriptor flags from one locked table snapshot. */
static int
linprocfs_fdget(struct thread *td, struct proc *p, int fd, bool follow,
    struct file **result, int *flags)
{
	struct filedesc *fdp;
	struct file *fp;
	struct filedescent *fde;
	cap_rights_t all;
	int error;

	PROC_LOCK(p);
	error = p_candebug(td, p);
	fdp = error == 0 ? fdhold(p) : NULL;
	PROC_UNLOCK(p);
	if (error != 0 || fdp == NULL)
		return (error != 0 ? error : ENOENT);
	FILEDESC_SLOCK(fdp);
	PROC_LOCK(p);
	error = p_candebug(td, p);
	if (error == 0 && atomic_load_ptr(&p->p_fd) != fdp)
		error = ENOENT;
	fp = error == 0 && refcount_load(&fdp->fd_refcnt) != 0 ?
	    fget_noref(fdp, fd) :
	    NULL;
	if (fp == NULL || !fhold(fp)) {
		fp = NULL;
		if (error == 0)
			error = ENOENT;
	} else {
		fde = &fdp->fd_ofiles[fd];
		*flags = fde->fde_flags;
		CAP_ALL(&all);
		if (follow &&
		    ((!cap_rights_contains(&fde->fde_rights, &all)) ||
			(*flags & (UF_RESOLVE_BENEATH | UF_LOOKUP_CAPMODE)) !=
			    0))
			error = ENOTCAPABLE;
		*result = fp;
	}
	PROC_UNLOCK(p);
	FILEDESC_SUNLOCK(fdp);
	fddrop(fdp);
	if (error != 0 && fp != NULL) {
		fdrop(fp, td);
		*result = NULL;
	}
	return (error);
}

static int
linprocfs_fd_vget(struct mount *mp, void *arg, int flags, struct vnode **vp)
{
	struct file *fp = arg;

	vget(fp->f_vnode, flags | LK_RETRY);
	*vp = fp->f_vnode;
	return (0);
}

static int
linprocfs_fdlookup_impl(struct thread *td, struct proc *p, int fd,
    struct componentname *cnp, struct vnode *dvp, struct vnode **vp, bool link)
{
	struct file *fp = NULL;
	int error, flags;
	bool follow;

	follow = (cnp->cn_flags & (FOLLOW | TRAILINGSLASH)) != 0 ||
	    (cnp->cn_flags & ISLASTCN) == 0;
	follow = follow && link;
	VOP_UNLOCK(dvp);
	error = linprocfs_fdget(td, p, fd, follow, &fp, &flags);
	vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
	if (error == 0 && VN_IS_DOOMED(dvp))
		error = ENOENT;
	if (error == 0 && follow) {
		if ((cnp->cn_flags & (NOSYMLINKS | NOMAGICLINKS)) != 0)
			error = ELOOP;
		else if ((cnp->cn_flags & (RINROOT | RBENEATH)) != 0)
			error = EXDEV;
		else if (fp->f_vnode == NULL) {
			struct vn_file_context *ctx = vn_file_context_current();

			error = ENXIO;
			if (fp->f_type == DTYPE_PIPE && ctx != NULL && ctx->fp != NULL &&
			    SV_PROC_ABI(td->td_proc) == SV_ABI_LINUX &&
			    (td->td_proc->p_sysent->sv_flags & SV_LP64) != 0) {
				if ((cnp->cn_flags & ISLASTCN) == 0)
					error = ENOTDIR;
				else if ((cnp->cn_flags & NOXDEV) != 0)
					error = EXDEV;
				else {
					error = pipe_reopen_file(fp, ctx->fp, ctx->openflags, td);
					/* openatfp recognizes an independently initialized file. */
					if (error == 0)
						error = ENXIO;
				}
			}
		}
		else if ((cnp->cn_flags & NOXDEV) != 0 &&
		    fp->f_vnode->v_mount != dvp->v_mount)
			error = EXDEV;
		else
			error = vn_vget_ino_gen(dvp, linprocfs_fd_vget, fp,
			    LK_EXCLUSIVE, vp);
	}
	if (error == 0 && follow && (cnp->cn_flags & ISLASTCN) != 0)
		vn_inotify_path_copy(fp);
	if (fp != NULL) {
		VOP_UNLOCK(dvp);
		fdrop(fp, td);
		vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
		if (error == 0 && VN_IS_DOOMED(dvp)) {
			if (*vp != NULL) {
				vput(*vp);
				*vp = NULL;
			}
			error = ENOENT;
		}
	}
	return (error);
}

static int
linprocfs_dofd(PFS_FILL_ARGS, int fd)
{
	struct file *fp = NULL;
	struct stat st;
	char *name, *buffer = NULL;
	int error, flags;

	error = linprocfs_fdget(td, p, fd, false, &fp, &flags);
	if (error != 0)
		return (error);
	if (fp->f_vnode != NULL) {
		error = vn_inotify_path_readlink(fp, &name, &buffer);
		if (error == EOPNOTSUPP)
			error = vn_fullpath(fp->f_vnode, &name, &buffer);
		if (error == 0)
			sbuf_cat(sb, name);
	} else if (fp->f_type == DTYPE_PIPE || fp->f_type == DTYPE_SOCKET) {
		error = fo_stat(fp, &st, td->td_ucred);
		if (error == 0 && fp->f_type == DTYPE_SOCKET)
			st.st_ino = ((struct socket *)fp->f_data)->so_gencnt;
		if (error == 0)
			sbuf_printf(sb, "%s:[%ju]",
			    fp->f_type == DTYPE_PIPE ? "pipe" : "socket",
			    (uintmax_t)st.st_ino);
	} else {
		const char *name;
		switch (fp->f_type) {
		case DTYPE_EVENTFD: name = "eventfd"; break;
		case DTYPE_TIMERFD: name = "timerfd"; break;
		case DTYPE_LINUXSIGNALFD: name = "signalfd"; break;
		case DTYPE_KQUEUE: name = "eventpoll"; break;
		case DTYPE_INOTIFY: name = "inotify"; break;
		default: name = "unknown"; break;
		}
		if (fp->f_type == DTYPE_INOTIFY)
			sbuf_cat(sb, "anon_inode:inotify");
		else
			sbuf_printf(sb, "anon_inode:[%s]", name);
	}
	free(buffer, M_TEMP);
	fdrop(fp, td);
	return (error);
}

static int
linprocfs_kevent_compare(const void *a, const void *b)
{
	const struct kevent *ka = a, *kb = b;

	if (ka->ident != kb->ident)
		return (ka->ident < kb->ident ? -1 : 1);
	return ((ka->filter > kb->filter) - (ka->filter < kb->filter));
}

/* Type-specific state is copied under its owner's locks, then formatted. */
static int
linprocfs_fdinfo_extra(struct file *fp, struct sbuf *sb)
{
	struct kinfo_file *kif;
	struct kevent *all;
	l_sigset_t mask;
	size_t count, i;
	int error = 0;

	if (fp->f_type == DTYPE_KQUEUE) {
		error = kern_kqueue_knotes(fp, &all, &count);
		if (error != 0)
			return (error);
		if (count > 1)
			qsort(all, count, sizeof(*all), linprocfs_kevent_compare);
		for (i = 0; i < count; i++) {
			/* Read/write filters describe one epoll interest. */
			if (i != 0 && all[i - 1].ident == all[i].ident)
				continue;
			sbuf_printf(sb, "tfd: %8ju events: %8jx data: %16jx\n",
			    (uintmax_t)all[i].ident, (uintmax_t)all[i].ext[1],
			    (uintmax_t)all[i].ext[0]);
		}
		free(all, M_TEMP);
		return (0);
	}
	if (fp->f_type != DTYPE_EVENTFD && fp->f_type != DTYPE_TIMERFD &&
	    fp->f_type != DTYPE_LINUXSIGNALFD)
		return (0);
	kif = malloc(sizeof(*kif), M_TEMP, M_WAITOK | M_ZERO);
	error = fo_fill_kinfo(fp, kif, NULL);
	if (error != 0)
		goto out;
	switch (fp->f_type) {
	case DTYPE_EVENTFD:
		sbuf_printf(sb, "eventfd-count: %16jx\neventfd-semaphore: %u\n",
		    (uintmax_t)kif->kf_un.kf_eventfd.kf_eventfd_value,
		    (kif->kf_un.kf_eventfd.kf_eventfd_flags & EFD_SEMAPHORE) != 0);
		break;
	case DTYPE_TIMERFD:
		sbuf_printf(sb, "clockid: %d\nticks: %ju\nsettime flags: 0%o\n"
		    "it_value: (%jd, %jd)\nit_interval: (%jd, %jd)\n",
		    kif->kf_un.kf_timerfd.kf_timerfd_clockid == CLOCK_REALTIME ? 0 :
		    kif->kf_un.kf_timerfd.kf_timerfd_clockid == CLOCK_MONOTONIC ? 7 : 1,
		    (uintmax_t)kif->kf_un.kf_timerfd.kf_timerfd_ticks,
		    kif->kf_un.kf_timerfd.kf_timerfd_setflags & 3,
		    (intmax_t)kif->kf_un.kf_timerfd.kf_timerfd_value_sec,
		    (intmax_t)kif->kf_un.kf_timerfd.kf_timerfd_value_nsec,
		    (intmax_t)kif->kf_un.kf_timerfd.kf_timerfd_interval_sec,
		    (intmax_t)kif->kf_un.kf_timerfd.kf_timerfd_interval_nsec);
		break;
	case DTYPE_LINUXSIGNALFD:
		bsd_to_linux_sigset(&kif->kf_un.kf_signalfd.kf_signalfd_mask, &mask);
		sbuf_printf(sb, "sigmask: %016jx\n", (uintmax_t)mask.__mask);
		break;
	}
out:
	free(kif, M_TEMP);
	return (error);
}

static int
linprocfs_dofdinfo(PFS_FILL_ARGS, int fd)
{
	struct file *fp = NULL;
	struct stat st;
	uint64_t id;
	off_t pos;
	int error, flags, native, linuxflags;

	error = linprocfs_fdget(td, p, fd, false, &fp, &flags);
	if (error != 0)
		return (error);
	error = fo_stat(fp, &st, td->td_ucred);
	if (error != 0)
		goto out;
	if (fp->f_type == DTYPE_SOCKET)
		st.st_ino = ((struct socket *)fp->f_data)->so_gencnt;
	native = atomic_load_int(&fp->f_flag);
	linuxflags = (native & (FREAD | FWRITE)) == (FREAD | FWRITE) ?
	    02 /* LINUX_O_RDWR */ :
	    (native & FWRITE) != 0 ? 01 /* LINUX_O_WRONLY */ :
				     0;
#define FD_FLAG(b, l)            \
	if ((native & (b)) != 0) \
	linuxflags |= (l)
	FD_FLAG(FAPPEND, 02000 /* LINUX_O_APPEND */);
	FD_FLAG(FNONBLOCK, 04000 /* LINUX_O_NONBLOCK */);
	FD_FLAG(FASYNC, 020000 /* LINUX_O_ASYNC */);
	FD_FLAG(O_DIRECT, 040000 /* LINUX_O_DIRECT */);
	FD_FLAG(O_FSYNC, 04010000 /* LINUX_O_SYNC */);
	FD_FLAG(O_DSYNC, 010000 /* LINUX_O_DSYNC */);
	FD_FLAG(O_PATH, 010000000 /* LINUX_O_PATH */);
#undef FD_FLAG
	if ((flags & UF_EXCLOSE) != 0)
		linuxflags |= 02000000 /* LINUX_O_CLOEXEC */;
	id = fp->f_vnode != NULL ? linux_vnode_mount_id(fp->f_vnode) : 0;
	pos = (fp->f_ops->fo_flags & DFLAG_SEEKABLE) != 0 ? foffset_get(fp) : 0;
	sbuf_printf(sb, "pos:\t%jd\nflags:\t0%o\nmnt_id:\t%ju\nino:\t%ju\n",
	    (intmax_t)pos, linuxflags, (uintmax_t)id, (uintmax_t)st.st_ino);
	error = linprocfs_fdinfo_extra(fp, sb);
out:
	fdrop(fp, td);
	return (error);
}

static int
linprocfs_fdlookup(struct thread *td, struct proc *p, int fd,
    struct componentname *cnp, struct vnode *dvp, struct vnode **vp)
{
	return (linprocfs_fdlookup_impl(td, p, fd, cnp, dvp, vp, true));
}

static int
linprocfs_fdinfolookup(struct thread *td, struct proc *p, int fd,
    struct componentname *cnp, struct vnode *dvp, struct vnode **vp)
{
	return (linprocfs_fdlookup_impl(td, p, fd, cnp, dvp, vp, false));
}

static int
linprocfs_fd_fill(PFS_FILL_ARGS)
{
	/* Descriptor nodes must dispatch through pn_fill_fd with an index. */
	return (EINVAL);
}

/*
 * Filler function for proc/pid/limits
 */
static const struct linux_rlimit_ident {
	const char	*desc;
	const char	*unit;
	unsigned int	rlim_id;
} linux_rlimits_ident[] = {
	{ "Max cpu time",	"seconds",	RLIMIT_CPU },
	{ "Max file size", 	"bytes",	RLIMIT_FSIZE },
	{ "Max data size",	"bytes", 	RLIMIT_DATA },
	{ "Max stack size",	"bytes", 	RLIMIT_STACK },
	{ "Max core file size",  "bytes",	RLIMIT_CORE },
	{ "Max resident set",	"bytes",	RLIMIT_RSS },
	{ "Max processes",	"processes",	RLIMIT_NPROC },
	{ "Max open files",	"files",	RLIMIT_NOFILE },
	{ "Max locked memory",	"bytes",	RLIMIT_MEMLOCK },
	{ "Max address space",	"bytes",	RLIMIT_AS },
	{ "Max file locks",	"locks",	LINUX_RLIMIT_LOCKS },
	{ "Max pending signals", "signals",	LINUX_RLIMIT_SIGPENDING },
	{ "Max msgqueue size",	"bytes",	LINUX_RLIMIT_MSGQUEUE },
	{ "Max nice priority", 		"",	LINUX_RLIMIT_NICE },
	{ "Max realtime priority",	"",	LINUX_RLIMIT_RTPRIO },
	{ "Max realtime timeout",	"us",	LINUX_RLIMIT_RTTIME },
	{ 0, 0, 0 }
};

static int
linprocfs_doproclimits(PFS_FILL_ARGS)
{
	const struct linux_rlimit_ident *li;
	struct plimit *limp;
	struct rlimit rl;
	ssize_t size;
	int res, error;

	error = 0;

	PROC_LOCK(p);
	limp = lim_hold(p->p_limit);
	PROC_UNLOCK(p);
	size = sizeof(res);
	sbuf_printf(sb, "%-26s%-21s%-21s%-21s\n", "Limit", "Soft Limit",
			"Hard Limit", "Units");
	for (li = linux_rlimits_ident; li->desc != NULL; ++li) {
		switch (li->rlim_id)
		{
		case LINUX_RLIMIT_LOCKS:
			/* FALLTHROUGH */
		case LINUX_RLIMIT_RTTIME:
			rl.rlim_cur = RLIM_INFINITY;
			break;
		case LINUX_RLIMIT_SIGPENDING:
			error = kernel_sysctlbyname(td,
			    "kern.sigqueue.max_pending_per_proc",
			    &res, &size, 0, 0, 0, 0);
			if (error != 0)
				continue;
			rl.rlim_cur = res;
			rl.rlim_max = res;
			break;
		case LINUX_RLIMIT_MSGQUEUE:
			error = kernel_sysctlbyname(td,
			    "kern.ipc.msgmnb", &res, &size, 0, 0, 0, 0);
			if (error != 0)
				continue;
			rl.rlim_cur = res;
			rl.rlim_max = res;
			break;
		case LINUX_RLIMIT_NICE:
			/* FALLTHROUGH */
		case LINUX_RLIMIT_RTPRIO:
			rl.rlim_cur = 0;
			rl.rlim_max = 0;
			break;
		default:
			rl = limp->pl_rlimit[li->rlim_id];
			break;
		}
		if (rl.rlim_cur == RLIM_INFINITY)
			sbuf_printf(sb, "%-26s%-21s%-21s%-10s\n",
			    li->desc, "unlimited", "unlimited", li->unit);
		else
			sbuf_printf(sb, "%-26s%-21llu%-21llu%-10s\n",
			    li->desc, (unsigned long long)rl.rlim_cur,
			    (unsigned long long)rl.rlim_max, li->unit);
	}

	lim_free(limp);
	return (0);
}

/*
 * The point of the following two functions is to work around
 * an assertion in Chromium; see kern/240991 for details.
 */
static int
linprocfs_dotaskattr(PFS_ATTR_ARGS)
{
	vap->va_nlink = 2 + p->p_numthreads;
	return (0);
}

/*
 * Filler function for proc/sys/kernel/random/uuid
 */
static int
linprocfs_douuid(PFS_FILL_ARGS)
{
	struct uuid uuid;

	kern_uuidgen(&uuid, 1);
	sbuf_printf_uuid(sb, &uuid);
	sbuf_printf(sb, "\n");
	return(0);
}

/*
 * Filler function for proc/sys/kernel/random/boot_id
 */
static int
linprocfs_doboot_id(PFS_FILL_ARGS)
{
       static bool firstboot = 1;
       static struct uuid uuid;

       if (firstboot) {
               kern_uuidgen(&uuid, 1);
               firstboot = 0;
       }
       sbuf_printf_uuid(sb, &uuid);
       sbuf_printf(sb, "\n");
       return(0);
}

/*
 * Filler function for proc/pid/auxv
 */
static int
linprocfs_doauxv(PFS_FILL_ARGS)
{
	struct sbuf *asb;
	off_t buflen, resid;
	int error;

	/*
	 * Mimic linux behavior and pass only processes with usermode
	 * address space as valid. Return zero silently otherwise.
	 */
	if (p->p_vmspace == &vmspace0)
		return (0);

	if (uio->uio_resid == 0)
		return (0);
	if (uio->uio_offset < 0 || uio->uio_resid < 0)
		return (EINVAL);

	asb = sbuf_new_auto();
	if (asb == NULL)
		return (ENOMEM);
	error = proc_getauxv(td, p, asb);
	if (error != 0)
		goto out;
	error = sbuf_finish(asb);
	if (error != 0)
		goto out;

	resid = sbuf_len(asb) - uio->uio_offset;
	if (resid > uio->uio_resid)
		buflen = uio->uio_resid;
	else
		buflen = resid;
	if (buflen > IOSIZE_MAX) {
		error = EINVAL;
		goto out;
	}
	if (buflen > maxphys)
		buflen = maxphys;
	if (resid > 0)
		error = uiomove(sbuf_data(asb) + uio->uio_offset, buflen, uio);
out:
	sbuf_delete(asb);
	return (error);
}

/*
 * Filler function for proc/self/oom_score_adj
 */
static int
linprocfs_do_oom_score_adj(PFS_FILL_ARGS)
{
	struct linux_pemuldata *pem;
	long oom;

	pem = pem_find(p);
	if (pem == NULL || uio == NULL)
		return (EOPNOTSUPP);
	if (uio->uio_rw == UIO_READ) {
		sbuf_printf(sb, "%d\n", pem->oom_score_adj);
	} else {
		sbuf_trim(sb);
		sbuf_finish(sb);
		oom = strtol(sbuf_data(sb), NULL, 10);
		if (oom < LINUX_OOM_SCORE_ADJ_MIN ||
		    oom > LINUX_OOM_SCORE_ADJ_MAX)
			return (EINVAL);
		pem->oom_score_adj = oom;
	}
	return (0);
}

/*
 * Filler function for proc/sys/vm/max_map_count
 *
 * Maximum number of active map areas, on Linux this limits the number
 * of vmaps per mm struct. We don't limit mappings, return a suitable
 * large value.
 */
static int
linprocfs_domax_map_cnt(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d\n", INT32_MAX);
	return (0);
}

/*
 * Filler function for proc/sysvipc/msg
 */
static int
linprocfs_dosysvipc_msg(PFS_FILL_ARGS)
{
	struct msqid_kernel *msqids;
	size_t id, size;
	int error;

	sbuf_printf(sb,
	    "%10s %10s %4s  %10s %10s %5s %5s %5s %5s %5s %5s %10s %10s %10s\n",
	    "key", "msqid", "perms", "cbytes", "qnum", "lspid", "lrpid",
	    "uid", "gid", "cuid", "cgid", "stime", "rtime", "ctime");

	error = kern_get_msqids(curthread, &msqids, &size);
	if (error != 0)
		return (error);

	for (id = 0; id < size; id++) {
		if (msqids[id].u.msg_qbytes == 0)
			continue;
		sbuf_printf(sb,
		    "%10d %10zu  %4o  %10lu %10lu %5u %5u %5u %5u %5u %5u %jd %jd %jd\n",
		    (int)msqids[id].u.msg_perm.key,
		    IXSEQ_TO_IPCID(id, msqids[id].u.msg_perm),
		    msqids[id].u.msg_perm.mode,
		    msqids[id].u.msg_cbytes,
		    msqids[id].u.msg_qnum,
		    msqids[id].u.msg_lspid,
		    msqids[id].u.msg_lrpid,
		    msqids[id].u.msg_perm.uid,
		    msqids[id].u.msg_perm.gid,
		    msqids[id].u.msg_perm.cuid,
		    msqids[id].u.msg_perm.cgid,
		    (intmax_t)msqids[id].u.msg_stime,
		    (intmax_t)msqids[id].u.msg_rtime,
		    (intmax_t)msqids[id].u.msg_ctime);
	}

	free(msqids, M_TEMP);
	return (0);
}

/*
 * Filler function for proc/sysvipc/sem
 */
static int
linprocfs_dosysvipc_sem(PFS_FILL_ARGS)
{
	struct semid_kernel *semids;
	size_t id, size;
	int error;

	sbuf_printf(sb, "%10s %10s %4s %10s %5s %5s %5s %5s %10s %10s\n",
	    "key", "semid", "perms", "nsems", "uid", "gid", "cuid", "cgid",
	    "otime", "ctime");

	error = kern_get_sema(curthread, &semids, &size);
	if (error != 0)
		return (error);

	for (id = 0; id < size; id++) {
		if ((semids[id].u.sem_perm.mode & SEM_ALLOC) == 0)
			continue;
		sbuf_printf(sb,
		    "%10d %10zu  %4o %10u %5u %5u %5u %5u %jd %jd\n",
		    (int)semids[id].u.sem_perm.key,
		    IXSEQ_TO_IPCID(id, semids[id].u.sem_perm),
		    semids[id].u.sem_perm.mode,
		    semids[id].u.sem_nsems,
		    semids[id].u.sem_perm.uid,
		    semids[id].u.sem_perm.gid,
		    semids[id].u.sem_perm.cuid,
		    semids[id].u.sem_perm.cgid,
		    (intmax_t)semids[id].u.sem_otime,
		    (intmax_t)semids[id].u.sem_ctime);
	}

	free(semids, M_TEMP);
	return (0);
}

/*
 * Filler function for proc/sysvipc/shm
 */
static int
linprocfs_dosysvipc_shm(PFS_FILL_ARGS)
{
	struct shmid_kernel *shmids;
	size_t id, size;
	int error;

	sbuf_printf(sb,
	    "%10s %10s %s %21s %5s %5s %5s %5s %5s %5s %5s %10s %10s %10s %21s %21s\n",
	    "key", "shmid", "perms", "size", "cpid", "lpid", "nattch", "uid",
	    "gid", "cuid", "cgid", "atime", "dtime", "ctime", "rss", "swap");

	error = kern_get_shmsegs(curthread, &shmids, &size);
	if (error != 0)
		return (error);

	for (id = 0; id < size; id++) {
		if ((shmids[id].u.shm_perm.mode & SHMSEG_ALLOCATED) == 0)
			continue;
		sbuf_printf(sb,
		    "%10d %10zu  %4o %21zu %5u %5u  %5u %5u %5u %5u %5u %jd %jd %jd %21d %21d\n",
		    (int)shmids[id].u.shm_perm.key,
		    IXSEQ_TO_IPCID(id, shmids[id].u.shm_perm),
		    shmids[id].u.shm_perm.mode,
		    shmids[id].u.shm_segsz,
		    shmids[id].u.shm_cpid,
		    shmids[id].u.shm_lpid,
		    shmids[id].u.shm_nattch,
		    shmids[id].u.shm_perm.uid,
		    shmids[id].u.shm_perm.gid,
		    shmids[id].u.shm_perm.cuid,
		    shmids[id].u.shm_perm.cgid,
		    (intmax_t)shmids[id].u.shm_atime,
		    (intmax_t)shmids[id].u.shm_dtime,
		    (intmax_t)shmids[id].u.shm_ctime,
		    0, 0);	/* XXX rss & swp are not supported */
	}

	free(shmids, M_TEMP);
	return (0);
}

/*
 * Filler function for proc/sys/fs/file-max
 */
static int
linprocfs_dofile_max(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.maxfiles",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);
	sbuf_printf(sb, "%d\n", res);
	return (0);
}

/*
 * Filler function for proc/sys/fs/file-nr
 */
static int
linprocfs_dofile_nr(PFS_FILL_ARGS)
{
	int openfiles, maxfiles, error;
	size_t size;

	size = sizeof(openfiles);
	error = kernel_sysctlbyname(curthread, "kern.openfiles",
	    &openfiles, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);
	size = sizeof(maxfiles);
	error = kernel_sysctlbyname(curthread, "kern.maxfiles",
	    &maxfiles, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);
	/*
	 * From Linux's proc_sys_fs(5):
	 * the "free file handles" value is always zero.
	 */
	sbuf_printf(sb, "%d\t0\t%d\n", openfiles, maxfiles);
	return (0);
}

/*
 * Filler function for proc/sys/fs/nr_open
 */
static int
linprocfs_donr_open(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.maxfilesperproc",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);
	sbuf_printf(sb, "%d\n", res);
	return (0);
}

/*
 * Filler function for proc/sys/fs/overflowuid
 */
static int
linprocfs_dooverflowuid(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "%u\n", UID_NOBODY);
	return (0);
}

/*
 * Filler function for proc/sys/fs/overflowgid
 */
static int
linprocfs_dooverflowgid(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "%u\n", GID_NOGROUP);
	return (0);
}

/*
 * Filler function for proc/sys/fs/suid_dumpable
 */
static int
linprocfs_dosuid_dumpable(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.sugid_coredump",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);
	sbuf_printf(sb, "%d\n", res ? 1 : 0);
	return (0);
}

/*
 * Filler function for proc/sys/fs/protected_hardlinks
 */
static int
linprocfs_doprotected_hardlinks(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread,
	    "security.bsd.hardlink_check_uid",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);
	sbuf_printf(sb, "%d\n", res ? 1 : 0);
	return (0);
}

static int
linprocfs_doinotify(const char *sysctl, PFS_FILL_ARGS)
{
	size_t size;
	int error, val;

	if (uio->uio_rw == UIO_READ) {
		size = sizeof(val);
		error = kernel_sysctlbyname(curthread,
		    __DECONST(void *, sysctl), &val, &size, NULL, 0, 0, 0);
		if (error == 0)
			sbuf_printf(sb, "%d\n", val);
	} else {
		char *endp, *newval;
		long vall;

		sbuf_trim(sb);
		sbuf_finish(sb);
		newval = sbuf_data(sb);
		vall = strtol(newval, &endp, 10);
		if (vall < 0 || vall > INT_MAX || endp == newval ||
		    *endp != '\0')
			return (EINVAL);
		val = (int)vall;
		error = kernel_sysctlbyname(curthread,
		    __DECONST(void *, sysctl), NULL, NULL,
		    &val, sizeof(val), 0, 0);
	}
	return (error);
}

/*
 * Filler function for proc/sys/fs/inotify/max_queued_events
 */
static int
linprocfs_doinotify_max_queued_events(PFS_FILL_ARGS)
{
	return (linprocfs_doinotify("vfs.inotify.max_queued_events",
	    PFS_FILL_ARGNAMES));
}

/*
 * Filler function for proc/sys/fs/inotify/max_user_instances
 */
static int
linprocfs_doinotify_max_user_instances(PFS_FILL_ARGS)
{
	return (linprocfs_doinotify("vfs.inotify.max_user_instances",
	    PFS_FILL_ARGNAMES));
}

/*
 * Filler function for proc/sys/fs/inotify/max_user_watches
 */
static int
linprocfs_doinotify_max_user_watches(PFS_FILL_ARGS)
{
	return (linprocfs_doinotify("vfs.inotify.max_user_watches",
	    PFS_FILL_ARGNAMES));
}

/*
 * Filler function for proc/sys/fs/mqueue/msg_default
 */
static int
linprocfs_domqueue_msg_default(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.mqueue.default_maxmsg",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);

	sbuf_printf(sb, "%d\n", res);
	return (0);
}

/*
 * Filler function for proc/sys/fs/mqueue/msgsize_default
 */
static int
linprocfs_domqueue_msgsize_default(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.mqueue.default_msgsize",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);

	sbuf_printf(sb, "%d\n", res);
	return (0);

}

/*
 * Filler function for proc/sys/fs/mqueue/msg_max
 */
static int
linprocfs_domqueue_msg_max(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.mqueue.maxmsg",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);

	sbuf_printf(sb, "%d\n", res);
	return (0);
}

/*
 * Filler function for proc/sys/fs/mqueue/msgsize_max
 */
static int
linprocfs_domqueue_msgsize_max(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.mqueue.maxmsgsize",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);

	sbuf_printf(sb, "%d\n", res);
	return (0);
}

/*
 * Filler function for proc/sys/fs/mqueue/queues_max
 */
static int
linprocfs_domqueue_queues_max(PFS_FILL_ARGS)
{
	int res, error;
	size_t size = sizeof(res);

	error = kernel_sysctlbyname(curthread, "kern.mqueue.maxmq",
	    &res, &size, NULL, 0, 0, 0);
	if (error != 0)
		return (error);

	sbuf_printf(sb, "%d\n", res);
	return (0);
}

/*
 * Constructor
 */
/*
 * Filler function for proc/<pid>/cgroup
 *
 * Report the cgroup v2 unified hierarchy at the root with no controllers or
 * limits.  Runtimes (Go, the JVM, Node) read this to detect a CPU quota; the
 * "0::/" line with no matching cgroupfs limit means "unconstrained", which is
 * correct here and stops them mis-detecting or warning.
 */
static int
linprocfs_doproccgroup(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "0::/\n");
	return (0);
}

/*
 * Filler function for proc/<pid>/cpuset
 */
static int
linprocfs_doproccpuset(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "/\n");
	return (0);
}

static int
linprocfs_net_sysctl(struct thread *td, const char *name, void *data, size_t *len)
{
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	error = kernel_sysctlbyname(td, __DECONST(char *, name), data, len,
	    NULL, 0, len, 0);
	CURVNET_RESTORE();
	return (error);
}

/* Use native, credential-filtered PCB snapshots; never expose PCB pointers. */
static int
linprocfs_pcbs(struct thread *td, const char *name, void **data, size_t *len)
{
	size_t size;
	int error;

	*data = NULL;
	for (int attempt = 0; attempt < 4; attempt++) {
		size = 0;
		error = linprocfs_net_sysctl(td, name, NULL, &size);
		if (error != 0)
			return (error);
		if (size > 128 * 1024 * 1024)
			return (ENOMEM);
		*data = malloc(size, M_TEMP, M_WAITOK);
		*len = size;
		error = linprocfs_net_sysctl(td, name, *data, len);
		if (error == 0)
			return (0);
		free(*data, M_TEMP);
		*data = NULL;
		if (error != ENOMEM)
			return (error);
	}
	return (EAGAIN);
}

static void
linprocfs_netaddr(struct sbuf *sb, const struct in_conninfo *inc,
    bool ipv6, bool remote)
{
	const struct in6_addr *a6;
	uint32_t words[4];

	if (ipv6) {
		a6 = remote ? &inc->inc6_faddr : &inc->inc6_laddr;
		memcpy(words, a6, sizeof(words));
		sbuf_printf(sb, "%08X%08X%08X%08X", words[0], words[1],
		    words[2], words[3]);
	} else
		sbuf_printf(sb, "%08X", remote ? inc->inc_faddr.s_addr :
		    inc->inc_laddr.s_addr);
	sbuf_printf(sb, ":%04X", ntohs(remote ? inc->inc_fport : inc->inc_lport));
}

static int
linprocfs_donetinet(PFS_FILL_ARGS)
{
	/* Native TCP state -> Linux TCP state. */
	static const uint8_t states[] = { 7, 10, 2, 3, 1, 8, 4, 11, 9, 5, 6 };
	struct xinpcb *inp;
	struct xtcpcb *tcp;
	struct xsocket *so;
	void *data;
	char *cursor;
	size_t len, record;
	unsigned index = 0, state;
	bool is_tcp = strncmp(pn->pn_name, "tcp", 3) == 0;
	bool ipv6 = strchr(pn->pn_name, '6') != NULL;
	int error;

	error = linprocfs_pcbs(td, is_tcp ? "net.inet.tcp.pcblist" :
	    "net.inet.udp.pcblist", &data, &len);
	if (error != 0)
		return (error);
	sbuf_cat(sb, "  sl  local_address rem_address   st tx_queue rx_queue "
	    "tr tm->when retrnsmt   uid  timeout inode\n");
	for (cursor = data; len >= sizeof(ksize_t); cursor += record, len -= record) {
		record = *(ksize_t *)cursor;
		if (record < sizeof(ksize_t) || record > len) {
			error = EIO;
			break;
		}
		if (record == sizeof(struct xinpgen))
			continue;
		if (record != (is_tcp ? sizeof(struct xtcpcb) : sizeof(struct xinpcb))) {
			error = EIO;
			break;
		}
		if (is_tcp) {
			tcp = (struct xtcpcb *)cursor;
			inp = &tcp->xt_inp;
			state = tcp->t_state >= 0 && tcp->t_state < nitems(states) ?
			    states[tcp->t_state] : 7;
		} else {
			inp = (struct xinpcb *)cursor;
			state = (inp->xi_socket.so_state & SS_ISCONNECTED) != 0 ? 1 : 7;
		}
		so = &inp->xi_socket;
		if ((so->xso_family == AF_INET6) != ipv6)
			continue;
		if (so->xso_family != AF_INET && so->xso_family != AF_INET6)
			continue;
		sbuf_printf(sb, "%4u: ", index++);
		linprocfs_netaddr(sb, &inp->inp_inc, ipv6, false);
		sbuf_putc(sb, ' ');
		linprocfs_netaddr(sb, &inp->inp_inc, ipv6, true);
		sbuf_printf(sb, " %02X %08X:%08X 00:00000000 00000000 %5u 0 %ju\n",
		    state, so->so_snd.sb_cc, so->so_rcv.sb_cc, so->so_uid,
		    (uintmax_t)so->xso_gen);
	}
	free(data, M_TEMP);
	return (error);
}

static int
linprocfs_donetunix(PFS_FILL_ARGS)
{
	static const char *names[] = { "net.local.stream.pcblist",
	    "net.local.dgram.pcblist", "net.local.seqpacket.pcblist" };
	struct xunpcb *unp;
	struct xsocket *so;
	void *data;
	char *cursor;
	size_t len, record, pathlen;
	int error;

	sbuf_cat(sb, "Num       RefCount Protocol Flags    Type St Inode Path\n");
	for (unsigned i = 0; i < nitems(names); i++) {
		error = linprocfs_pcbs(td, names[i], &data, &len);
		if (error != 0)
			return (error);
		for (cursor = data; len >= sizeof(ksize_t); cursor += record, len -= record) {
			record = *(ksize_t *)cursor;
			if (record < sizeof(ksize_t) || record > len) {
				error = EIO;
				break;
			}
			if (record == sizeof(struct xunpgen))
				continue;
			if (record != sizeof(struct xunpcb)) {
				error = EIO;
				break;
			}
			unp = (struct xunpcb *)cursor;
			so = &unp->xu_socket;
			sbuf_printf(sb, "0000000000000000: 00000000 00000000 %08X %04X %02X %ju",
			    (so->so_options & SO_ACCEPTCONN) != 0 ? 0x10000 : 0,
			    so->so_type == SOCK_SEQPACKET ? 5 : so->so_type,
			    (so->so_state & SS_ISCONNECTED) != 0 ? 3 : 1,
			    (uintmax_t)so->xso_gen);
			if (unp->xu_addr.sun_len > 2 && unp->xu_addr.sun_path[0] == '\0') {
				const unsigned char *name = (const unsigned char *)&unp->xu_addr + 2;
				pathlen = MIN(unp->xu_addr.sun_len - 2, SUN_ABSTRACT_MAXLEN - 2);
				sbuf_putc(sb, ' ');
				for (size_t j = 0; j < pathlen; j++)
					sbuf_putc(sb, name[j] == 0 ? '@' : name[j]);
			} else {
				pathlen = strnlen(unp->xu_addr.sun_path, sizeof(unp->xu_addr.sun_path));
				if (pathlen != 0) {
					sbuf_putc(sb, ' ');
					sbuf_bcat(sb, unp->xu_addr.sun_path, pathlen);
				}
			}
			sbuf_putc(sb, '\n');
		}
		free(data, M_TEMP);
		if (error != 0)
			return (error);
	}
	return (0);
}

static int
linprocfs_init(PFS_INIT_ARGS)
{
	struct pfs_node *dir, *fs, *root, *sys, *threadfile, *fddir, *fdnode;

	root = pi->pi_root;
	pi->pi_thread_id = linprocfs_thread_id;
	pfs_create_link(root, NULL, "thread-self", linprocfs_threadself, NULL,
	    NULL, NULL, 0);

	/* /proc/... */
	pfs_create_file(root, NULL, "cmdline", &linprocfs_docmdline, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "cpuinfo", &linprocfs_docpuinfo, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "devices", &linprocfs_dodevices, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "filesystems", &linprocfs_dofilesystems,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(root, NULL, "loadavg", &linprocfs_doloadavg, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "meminfo", &linprocfs_domeminfo, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "modules", &linprocfs_domodules, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "mounts", &linprocfs_domtab, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "mtab", &linprocfs_domtab, NULL, NULL, NULL,
	    PFS_RD);
	pfs_create_file(root, NULL, "partitions", &linprocfs_dopartitions, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_link(root, NULL, "self", &procfs_docurproc, NULL, NULL, NULL,
	    0);
	pfs_create_file(root, NULL, "stat", &linprocfs_dostat, NULL, NULL, NULL,
	    PFS_RD);
	pfs_create_file(root, NULL, "swaps", &linprocfs_doswaps, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "uptime", &linprocfs_douptime, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(root, NULL, "version", &linprocfs_doversion, NULL, NULL,
	    NULL, PFS_RD);

	/* /proc/bus/... */
	pfs_create_dir(root, &dir, "bus", NULL, NULL, NULL, 0);
	pfs_create_dir(dir, &dir, "pci", NULL, NULL, NULL, 0);
	pfs_create_dir(dir, &dir, "devices", NULL, NULL, NULL, 0);

	/* /proc/net/... */
	pfs_create_dir(root, &dir, "net", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "dev", &linprocfs_donetdev, NULL, NULL, NULL,
	    PFS_RD);
	pfs_create_file(dir, NULL, "route", &linprocfs_donetroute, NULL, NULL,
	    NULL, PFS_RD);

	const char *inet_tables[] = { "tcp", "tcp6", "udp", "udp6" };
	for (unsigned i = 0; i < nitems(inet_tables); i++)
		pfs_create_file(dir, NULL, inet_tables[i], linprocfs_donetinet,
		    NULL, NULL, NULL, PFS_RD | PFS_AUTODRAIN);
	pfs_create_file(dir, NULL, "unix", linprocfs_donetunix,
	    NULL, NULL, NULL, PFS_RD | PFS_AUTODRAIN);

	/* /proc/<pid>/... */
	pfs_create_dir(root, &dir, "pid", NULL, NULL, NULL, PFS_PROCDEP);
	pfs_create_file(dir, NULL, "cmdline", &linprocfs_doproccmdline, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "cgroup", &linprocfs_doproccgroup, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "cpuset", &linprocfs_doproccpuset, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_link(dir, NULL, "cwd", &linprocfs_doproccwd, NULL, NULL,
	    NULL, PFS_MAGICLINK);
	pfs_create_file(dir, NULL, "environ", &linprocfs_doprocenviron, NULL,
	    &procfs_candebug, NULL, PFS_RD);
	pfs_create_link(dir, NULL, "exe", &procfs_doprocfile, NULL,
	    &procfs_notsystem, NULL, PFS_MAGICLINK);
	pfs_create_file(dir, NULL, "maps", &linprocfs_doprocmaps, NULL, NULL,
	    NULL, PFS_RD | PFS_AUTODRAIN);
	pfs_create_file(dir, NULL, "mem", &linprocfs_doprocmem, procfs_attr_rw,
	    &procfs_candebug, NULL, PFS_RDWR | PFS_RAW);
	pfs_create_file(dir, NULL, "mountinfo", &linprocfs_doprocmountinfo,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "mounts", &linprocfs_domtab, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_link(dir, NULL, "root", &linprocfs_doprocroot, NULL, NULL,
	    NULL, PFS_MAGICLINK);
	pfs_create_file(dir, NULL, "stat", &linprocfs_doprocstat, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "statm", &linprocfs_doprocstatm, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "status", &linprocfs_doprocstatus, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_dir(dir, &fddir, "fd", linprocfs_fdattr, procfs_candebug,
	    NULL, 0);
	fddir->pn_fdlist = linprocfs_fdlist;
	pfs_create_link(fddir, &fdnode, "descriptor", linprocfs_fd_fill, NULL,
	    procfs_candebug, NULL, PFS_FDNAME | PFS_MAGICLINK);
	fdnode->pn_fill_fd = linprocfs_dofd;
	fdnode->pn_fdlookup = linprocfs_fdlookup;
	pfs_create_dir(dir, &fddir, "fdinfo", linprocfs_fdattr, procfs_candebug,
	    NULL, 0);
	fddir->pn_fdlist = linprocfs_fdlist;
	pfs_create_file(fddir, &fdnode, "descriptor", linprocfs_fd_fill,
	    linprocfs_fdattr, procfs_candebug, NULL, PFS_FDNAME | PFS_RD | PFS_AUTODRAIN);
	fdnode->pn_fill_fd = linprocfs_dofdinfo;
	fdnode->pn_fdlookup = linprocfs_fdinfolookup;
	pfs_create_file(dir, NULL, "auxv", &linprocfs_doauxv, NULL,
	    &procfs_candebug, NULL, PFS_RD | PFS_RAWRD);
	pfs_create_file(dir, NULL, "limits", &linprocfs_doproclimits, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "oom_score_adj", &linprocfs_do_oom_score_adj,
	    procfs_attr_rw, &procfs_candebug, NULL, PFS_RDWR);

	pfs_create_file(dir, NULL, "comm", linprocfs_doproccomm,
	    linprocfs_commattr, NULL, NULL, PFS_RDWR | PFS_RAWWR);

	/* /proc/<pid>/task/... */
	pfs_create_dir(dir, &dir, "task", linprocfs_dotaskattr, NULL, NULL, 0);
	/* Threads share memory views but retain their own identity. */
	pfs_create_dir(dir, &dir, "tid", NULL, NULL, NULL, PFS_TIDNAME);
	pfs_create_link(dir, NULL, "cwd", linprocfs_doproccwd, NULL,
	    procfs_candebug, NULL, PFS_MAGICLINK);
	pfs_create_link(dir, NULL, "root", linprocfs_doprocroot, NULL,
	    procfs_candebug, NULL, PFS_MAGICLINK);
	pfs_create_link(dir, NULL, "exe", procfs_doprocfile, NULL,
	    procfs_candebug, NULL, PFS_MAGICLINK);
	pfs_create_file(dir, NULL, "mem", &linprocfs_doprocmem, procfs_attr_rw,
	    &procfs_candebug, NULL, PFS_RDWR | PFS_RAW);
	pfs_create_file(dir, NULL, "maps", &linprocfs_doprocmaps, NULL, NULL,
	    NULL, PFS_RD | PFS_AUTODRAIN);
	pfs_create_file(dir, &threadfile, "status", &linprocfs_doprocstatus,
	    NULL, NULL, NULL, PFS_RD);
	threadfile->pn_fill_thread = linprocfs_doprocstatus_thread;
	pfs_create_file(dir, &threadfile, "stat", &linprocfs_doprocstat, NULL,
	    NULL, NULL, PFS_RD);
	threadfile->pn_fill_thread = linprocfs_doprocstat_thread;

	pfs_create_file(dir, &threadfile, "comm", linprocfs_doproccomm,
	    linprocfs_commattr, NULL, NULL, PFS_RDWR | PFS_RAWWR);
	threadfile->pn_fill_thread = linprocfs_doproccomm_thread;
	pfs_create_file(dir, NULL, "cmdline", linprocfs_doproccmdline, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "statm", linprocfs_doprocstatm, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "limits", linprocfs_doproclimits, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "environ", linprocfs_doprocenviron, NULL,
	    procfs_candebug, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "auxv", linprocfs_doauxv, NULL,
	    procfs_candebug, NULL, PFS_RD | PFS_RAWRD);
	pfs_create_file(dir, NULL, "mounts", linprocfs_domtab, NULL, NULL, NULL,
	    PFS_RD);
	pfs_create_file(dir, NULL, "mountinfo", linprocfs_doprocmountinfo, NULL,
	    NULL, NULL, PFS_RD);

	pfs_create_dir(dir, &fddir, "fd", linprocfs_fdattr, procfs_candebug,
	    NULL, 0);
	fddir->pn_fdlist = linprocfs_fdlist;
	pfs_create_link(fddir, &fdnode, "descriptor", linprocfs_fd_fill, NULL,
	    procfs_candebug, NULL, PFS_FDNAME | PFS_MAGICLINK);
	fdnode->pn_fill_fd = linprocfs_dofd;
	fdnode->pn_fdlookup = linprocfs_fdlookup;
	pfs_create_dir(dir, &fddir, "fdinfo", linprocfs_fdattr, procfs_candebug,
	    NULL, 0);
	fddir->pn_fdlist = linprocfs_fdlist;
	pfs_create_file(fddir, &fdnode, "descriptor", linprocfs_fd_fill,
	    linprocfs_fdattr, procfs_candebug, NULL, PFS_FDNAME | PFS_RD | PFS_AUTODRAIN);
	fdnode->pn_fill_fd = linprocfs_dofdinfo;
	fdnode->pn_fdlookup = linprocfs_fdinfolookup;

	/* /proc/scsi/... */
	pfs_create_dir(root, &dir, "scsi", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "device_info", &linprocfs_doscsidevinfo,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "scsi", &linprocfs_doscsiscsi, NULL, NULL,
	    NULL, PFS_RD);

	/* /proc/sys/... */
	pfs_create_dir(root, &sys, "sys", NULL, NULL, NULL, 0);

	/* /proc/sys/kernel/... */
	pfs_create_dir(sys, &dir, "kernel", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "osrelease", &linprocfs_doosrelease, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "ostype", &linprocfs_doostype, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "version", &linprocfs_doosbuild, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "msgmax", &linprocfs_domsgmax, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "msgmni", &linprocfs_domsgmni, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "msgmnb", &linprocfs_domsgmnb, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "ngroups_max", &linprocfs_dongroups_max,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "pid_max", &linprocfs_dopid_max, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "sem", &linprocfs_dosem, NULL, NULL, NULL,
	    PFS_RD);
	pfs_create_file(dir, NULL, "shmall", &linprocfs_doshmall, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "shmmax", &linprocfs_doshmmax, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "shmmni", &linprocfs_doshmmni, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "tainted", &linprocfs_dotainted, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "threads-max", &linprocfs_dothreads_max,
	    NULL, NULL, NULL, PFS_RD);

	/* /proc/sys/kernel/random/... */
	pfs_create_dir(dir, &dir, "random", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "uuid", &linprocfs_douuid, NULL, NULL, NULL,
	    PFS_RD);
	pfs_create_file(dir, NULL, "boot_id", &linprocfs_doboot_id, NULL, NULL,
	    NULL, PFS_RD);

	/* /proc/sys/vm/.... */
	pfs_create_dir(sys, &dir, "vm", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "min_free_kbytes", &linprocfs_dominfree,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "max_map_count", &linprocfs_domax_map_cnt,
	    NULL, NULL, NULL, PFS_RD);

	/* /proc/sysvipc/... */
	pfs_create_dir(root, &dir, "sysvipc", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "msg", &linprocfs_dosysvipc_msg, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "sem", &linprocfs_dosysvipc_sem, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(dir, NULL, "shm", &linprocfs_dosysvipc_shm, NULL, NULL,
	    NULL, PFS_RD);

	/* /proc/sys/fs/... */
	pfs_create_dir(sys, &fs, "fs", NULL, NULL, NULL, 0);

	pfs_create_file(fs, NULL, "file-nr", &linprocfs_dofile_nr,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(fs, NULL, "file-max", &linprocfs_dofile_max,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(fs, NULL, "nr_open", &linprocfs_donr_open,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(fs, NULL, "overflowgid", &linprocfs_dooverflowgid,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(fs, NULL, "overflowuid", &linprocfs_dooverflowuid,
	    NULL, NULL, NULL, PFS_RD);
	pfs_create_file(fs, NULL, "protected_hardlinks",
	    &linprocfs_doprotected_hardlinks, NULL, NULL, NULL, PFS_RD);
	pfs_create_file(fs, NULL, "suid_dumpable", &linprocfs_dosuid_dumpable,
	    NULL, NULL, NULL, PFS_RD);

	pfs_create_dir(fs, &dir, "inotify", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "max_queued_events",
	    &linprocfs_doinotify_max_queued_events, NULL, NULL, NULL, PFS_RDWR);
	pfs_create_file(dir, NULL, "max_user_instances",
	    &linprocfs_doinotify_max_user_instances, NULL, NULL, NULL, PFS_RDWR);
	pfs_create_file(dir, NULL, "max_user_watches",
	    &linprocfs_doinotify_max_user_watches, NULL, NULL, NULL, PFS_RDWR);

	/* /proc/sys/fs/mqueue/... */
	pfs_create_dir(fs, &dir, "mqueue", NULL, NULL, NULL, 0);
	pfs_create_file(dir, NULL, "msg_default",
	    &linprocfs_domqueue_msg_default, NULL, NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "msgsize_default",
	    &linprocfs_domqueue_msgsize_default, NULL, NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "msg_max", &linprocfs_domqueue_msg_max, NULL,
	    NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "msgsize_max",
	    &linprocfs_domqueue_msgsize_max, NULL, NULL, NULL, PFS_RD);
	pfs_create_file(dir, NULL, "queues_max", &linprocfs_domqueue_queues_max,
	    NULL, NULL, NULL, PFS_RD);

	return (0);
}

/*
 * Destructor
 */
static int
linprocfs_uninit(PFS_INIT_ARGS)
{

	/* nothing to do, pseudofs will GC */
	return (0);
}

PSEUDOFS(linprocfs, 1, VFCF_JAIL);
#if defined(__aarch64__) || defined(__amd64__)
MODULE_DEPEND(linprocfs, linux_common, 1, 1, 1);
#else
MODULE_DEPEND(linprocfs, linux, 1, 1, 1);
#endif
MODULE_DEPEND(linprocfs, procfs, 1, 1, 1);
MODULE_DEPEND(linprocfs, sysvmsg, 1, 1, 1);
MODULE_DEPEND(linprocfs, sysvsem, 1, 1, 1);
MODULE_DEPEND(linprocfs, sysvshm, 1, 1, 1);

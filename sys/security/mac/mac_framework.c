/*-
 * Copyright (c) 1999-2002, 2006, 2009 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * Copyright (c) 2008-2009 Apple Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract 
 * N66001-04-C-6019 ("SEFOS").
 *
 * This software was developed at the University of Cambridge Computer
 * Laboratory with support from a grant from Google, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*-
 * Framework for extensible kernel access control.  This file contains core
 * kernel infrastructure for the TrustedBSD MAC Framework, including policy
 * registration, versioning, locking, error composition operator, and system
 * calls.
 *
 * The MAC Framework implements three programming interfaces:
 *
 * - The kernel MAC interface, defined in mac_framework.h, and invoked
 *   throughout the kernel to request security decisions, notify of security
 *   related events, etc.
 *
 * - The MAC policy module interface, defined in mac_policy.h, which is
 *   implemented by MAC policy modules and invoked by the MAC Framework to
 *   forward kernel security requests and notifications to policy modules.
 *
 * - The user MAC API, defined in mac.h, which allows user programs to query
 *   and set label state on objects.
 *
 * The majority of the MAC Framework implementation may be found in
 * src/sys/security/mac.  Sample policy modules may be found in
 * src/sys/security/mac_*.
 */

#include "opt_mac.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/sbuf.h>
#include <sys/sdt.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/*
 * DTrace SDT providers for MAC.
 */
SDT_PROVIDER_DEFINE(mac);
SDT_PROVIDER_DEFINE(mac_framework);
SDT_PROBE_DEFINE4(mac_framework, , , hook__args, "char *", "char *",
    "u_int", "const uint64_t *");
SDT_PROBE_DEFINE3(mac_framework, , , hook__skip, "char *", "char *", "int");
SDT_PROBE_DEFINE2(mac_framework, , , hook__start, "char *", "char *");
SDT_PROBE_DEFINE4(mac_framework, , , hook__done, "char *", "char *", "int", "int");
SDT_PROBE_DEFINE1(mac_framework, , , register__start, "struct mac_policy_conf *");
SDT_PROBE_DEFINE2(mac_framework, , , register__done, "struct mac_policy_conf *", "int");
SDT_PROBE_DEFINE1(mac_framework, , , unregister__start, "struct mac_policy_conf *");
SDT_PROBE_DEFINE2(mac_framework, , , unregister__done, "struct mac_policy_conf *", "int");


SDT_PROBE_DEFINE2(mac, , policy, modevent, "int",
    "struct mac_policy_conf *");
SDT_PROBE_DEFINE1(mac, , policy, register,
    "struct mac_policy_conf *");
SDT_PROBE_DEFINE1(mac, , policy, unregister,
    "struct mac_policy_conf *");
SDT_PROBE_DEFINE3(mac_framework, , , policy__decision, "char *", "char *",
    "int");

/*
 * Root sysctl node for all MAC and MAC policy controls.
 */
SYSCTL_NODE(_security, OID_AUTO, mac, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "TrustedBSD MAC policy controls");

/*
 * Root sysctl node for MAC modules' jail parameters.
 */
SYSCTL_JAIL_PARAM_NODE(mac, "Jail parameters for MAC policy controls");

/*
 * Declare that the kernel provides a specific version of MAC support.
 * This permits modules to refuse to be loaded if the necessary support isn't
 * present, even if it's pre-boot.
 */
MODULE_VERSION(kernel_mac_support, MAC_VERSION);

static unsigned int	mac_version = MAC_VERSION;
SYSCTL_UINT(_security_mac, OID_AUTO, version, CTLFLAG_RD, &mac_version, 0,
    "");

/*
 * Flags for inlined checks. Note this would be best hotpatched at runtime.
 * The following is a band-aid.
 *
 * Use FPFLAG for hooks running in commonly executed paths and FPFLAG_RARE
 * for the rest.
 */
#define FPFLAG(f)	\
bool __read_frequently mac_##f##_fp_flag

#define FPFLAG_RARE(f)	\
bool __read_mostly mac_##f##_fp_flag

FPFLAG(priv_check);
FPFLAG(priv_grant);
FPFLAG(vnode_check_lookup);
FPFLAG(vnode_check_open);
FPFLAG(vnode_check_stat);
FPFLAG(vnode_check_read);
FPFLAG(vnode_check_write);
FPFLAG(vnode_check_mmap);
FPFLAG(vnode_check_mmap_image);
FPFLAG_RARE(vnode_check_poll);
FPFLAG_RARE(vnode_check_rename_from);
FPFLAG_RARE(vnode_check_access);
FPFLAG_RARE(vnode_check_readlink);
FPFLAG_RARE(pipe_check_stat);
FPFLAG_RARE(pipe_check_poll);
FPFLAG_RARE(pipe_check_read);
FPFLAG_RARE(ifnet_create_mbuf);
FPFLAG_RARE(ifnet_check_transmit);
FPFLAG(file_check_ioctl);
FPFLAG(file_check_mmap);
FPFLAG(file_check_read);
FPFLAG(file_check_write);
FPFLAG(file_check_stat);
FPFLAG_RARE(file_check_fcntl);
FPFLAG(proc_check_fork);
FPFLAG(proc_check_mmap_anon);
FPFLAG(proc_check_mprotect);
FPFLAG(proc_check_syscall);
FPFLAG(system_check_kas_info);
FPFLAG(file_notify_close);
FPFLAG(vnode_check_close);
FPFLAG(pipe_check_write);
FPFLAG(socket_check_send);
FPFLAG(socket_check_receive);
FPFLAG(socket_check_poll);
FPFLAG(socket_check_stat);

#undef FPFLAG
#undef FPFLAG_RARE

/*
 * Labels consist of a indexed set of "slots", which are allocated policies
 * as required.  The MAC Framework maintains a bitmask of slots allocated so
 * far to prevent reuse.  Slots cannot be reused, as the MAC Framework
 * guarantees that newly allocated slots in labels will be NULL unless
 * otherwise initialized, and because we do not have a mechanism to garbage
 * collect slots on policy unload.  As labeled policies tend to be statically
 * loaded during boot, and not frequently unloaded and reloaded, this is not
 * generally an issue.
 */
#if MAC_MAX_SLOTS > 32
#error "MAC_MAX_SLOTS too large"
#endif

static unsigned int mac_max_slots = MAC_MAX_SLOTS;
static unsigned int mac_slot_offsets_free = (1 << MAC_MAX_SLOTS) - 1;
SYSCTL_UINT(_security_mac, OID_AUTO, max_slots, CTLFLAG_RD, &mac_max_slots,
    0, "");

/*
 * Has the kernel started generating labeled objects yet?  All read/write
 * access to this variable is serialized during the boot process.  Following
 * the end of serialization, we don't update this flag; no locking.
 */
static int	mac_late = 0;

/*
 * Each policy declares a mask of object types requiring labels to be
 * allocated for them.  For convenience, we combine and cache the bitwise or
 * of the per-policy object flags to track whether we will allocate a label
 * for an object type at run-time.
 */
uint64_t	mac_labeled;
SYSCTL_UQUAD(_security_mac, OID_AUTO, labeled, CTLFLAG_RD, &mac_labeled, 0,
    "Mask of object types being labeled");

MALLOC_DEFINE(M_MACTEMP, "mactemp", "MAC temporary label storage");

/*
 * MAC policy modules are placed in one of two lists: mac_static_policy_list,
 * for policies that are loaded early and cannot be unloaded, and
 * mac_policy_list, which holds policies either loaded later in the boot
 * cycle or that may be unloaded.  The static policy list does not require
 * locks to iterate over, but the dynamic list requires synchronization.
 * Support for dynamic policy loading can be compiled out using the
 * MAC_STATIC kernel option.
 *
 * The dynamic policy list is protected by two locks: modifying the list
 * requires both locks to be held exclusively.  One of the locks,
 * mac_policy_rm, is acquired over policy entry points that will never sleep;
 * the other, mac_policy_rms, is acquired over policy entry points that may
 * sleep.  The former category will be used when kernel locks may be held
 * over calls to the MAC Framework, during network processing in ithreads,
 * etc.  The latter will tend to involve potentially blocking memory
 * allocations, extended attribute I/O, etc.
 */
#ifndef MAC_STATIC
static struct rmlock mac_policy_rm;	/* Non-sleeping entry points. */
static struct rmslock mac_policy_rms;	/* Sleeping entry points. */
#endif

/*
 * Fast-path flag state: every count, every flag write and every policy's
 * mpc_fp_active.  Never held across policy code.  It is not the policy-list
 * lock on purpose: a policy switching its hooks must not wait for threads
 * inside hooks, which a thread asleep in a policy may keep there for long.
 * Lock order: mac_policy_rms and mac_policy_rm, then mac_policy_fp_mtx, then
 * the lockless-lookup recalculation mutex in vfs_cache.c.
 */
static struct mtx mac_policy_fp_mtx;

struct mac_policy_list_head mac_policy_list;
struct mac_policy_list_head mac_static_policy_list;
u_int mac_policy_count;			/* Registered policy count. */

static void	mac_policy_xlock(void);
static void	mac_policy_xlock_assert(void);
static void	mac_policy_xunlock(void);

void
mac_policy_slock_nosleep(struct rm_priotracker *tracker)
{

#ifndef MAC_STATIC
	if (!mac_late)
		return;

	rm_rlock(&mac_policy_rm, tracker);
#endif
}

void
mac_policy_slock_sleep(void)
{

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
 	    "mac_policy_slock_sleep");

#ifndef MAC_STATIC
	if (!mac_late)
		return;

	rms_rlock(&mac_policy_rms);
#endif
}

void
mac_policy_sunlock_nosleep(struct rm_priotracker *tracker)
{

#ifndef MAC_STATIC
	if (!mac_late)
		return;

	rm_runlock(&mac_policy_rm, tracker);
#endif
}

void
mac_policy_sunlock_sleep(void)
{

#ifndef MAC_STATIC
	if (!mac_late)
		return;

	rms_runlock(&mac_policy_rms);
#endif
}

static void
mac_policy_xlock(void)
{

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
 	    "mac_policy_xlock()");

#ifndef MAC_STATIC
	if (!mac_late)
		return;

	rms_wlock(&mac_policy_rms);
	rm_wlock(&mac_policy_rm);
#endif
}

static void
mac_policy_xunlock(void)
{

#ifndef MAC_STATIC
	if (!mac_late)
		return;

	rm_wunlock(&mac_policy_rm);
	rms_wunlock(&mac_policy_rms);
#endif
}

static void
mac_policy_xlock_assert(void)
{

#ifndef MAC_STATIC
	if (!mac_late)
		return;

	rm_assert(&mac_policy_rm, RA_WLOCKED);
#endif
}

/*
 * Initialize the MAC subsystem, including appropriate SMP locks.
 */
static void
mac_init(void *dummy __unused)
{

	LIST_INIT(&mac_static_policy_list);
	LIST_INIT(&mac_policy_list);
	mac_labelzone_init();
	mtx_init(&mac_policy_fp_mtx, "mac fastpath", NULL, MTX_DEF);

#ifndef MAC_STATIC
	rm_init_flags(&mac_policy_rm, "mac_policy_rm", RM_NOWITNESS |
	    RM_RECURSE);
	rms_init(&mac_policy_rms, "mac_policy_rms");
#endif
}

/*
 * For the purposes of modules that want to know if they were loaded "early",
 * set the mac_late flag once we've processed modules either linked into the
 * kernel, or loaded before the kernel startup.
 */
static void
mac_late_init(void *dummy __unused)
{

	mac_late = 1;
}

/*
 * Given a policy, derive from its set of non-NULL label init methods what
 * object types the policy is interested in.
 */
static uint64_t
mac_policy_getlabeled(struct mac_policy_conf *mpc)
{
	uint64_t labeled;

#define	MPC_FLAG(method, flag)					\
	if (mpc->mpc_ops->mpo_ ## method != NULL)			\
		labeled |= (flag);					\

	labeled = 0;
	MPC_FLAG(cred_init_label, MPC_OBJECT_CRED);
	MPC_FLAG(proc_init_label, MPC_OBJECT_PROC);
	MPC_FLAG(vnode_init_label, MPC_OBJECT_VNODE);
	MPC_FLAG(inpcb_init_label, MPC_OBJECT_INPCB);
	MPC_FLAG(socket_init_label, MPC_OBJECT_SOCKET);
	MPC_FLAG(devfs_init_label, MPC_OBJECT_DEVFS);
	MPC_FLAG(mbuf_init_label, MPC_OBJECT_MBUF);
	MPC_FLAG(ipq_init_label, MPC_OBJECT_IPQ);
	MPC_FLAG(ifnet_init_label, MPC_OBJECT_IFNET);
	MPC_FLAG(bpfdesc_init_label, MPC_OBJECT_BPFDESC);
	MPC_FLAG(pipe_init_label, MPC_OBJECT_PIPE);
	MPC_FLAG(mount_init_label, MPC_OBJECT_MOUNT);
	MPC_FLAG(posixsem_init_label, MPC_OBJECT_POSIXSEM);
	MPC_FLAG(posixshm_init_label, MPC_OBJECT_POSIXSHM);
	MPC_FLAG(prison_init_label, MPC_OBJECT_PRISON);
	MPC_FLAG(sysvmsg_init_label, MPC_OBJECT_SYSVMSG);
	MPC_FLAG(sysvmsq_init_label, MPC_OBJECT_SYSVMSQ);
	MPC_FLAG(sysvsem_init_label, MPC_OBJECT_SYSVSEM);
	MPC_FLAG(sysvshm_init_label, MPC_OBJECT_SYSVSHM);
	MPC_FLAG(syncache_init_label, MPC_OBJECT_SYNCACHE);
	MPC_FLAG(ip6q_init_label, MPC_OBJECT_IP6Q);

#undef MPC_FLAG
	return (labeled);
}

/*
 * When policies are loaded or unloaded, walk the list of registered policies
 * and built mac_labeled, a bitmask representing the union of all objects
 * requiring labels across all policies.
 */
static void
mac_policy_update(void)
{
	struct mac_policy_conf *mpc;

	mac_policy_xlock_assert();

	mac_labeled = 0;
	mac_policy_count = 0;
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {
		mac_labeled |= mac_policy_getlabeled(mpc);
		mac_policy_count++;
	}
	LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {
		mac_labeled |= mac_policy_getlabeled(mpc);
		mac_policy_count++;
	}

	cache_fast_lookup_enabled_recalc();
}

/*
 * There are frequently used code paths which check for rarely installed
 * policies. Gross hack below enables doing it in a cheap manner.
 */

#define FPO(f)	(offsetof(struct mac_policy_ops, mpo_##f) / sizeof(void *))
#define	FPE(f)	{ .offset = FPO(f), .flag = &mac_##f##_fp_flag, .name = #f }

struct mac_policy_fastpath_elem {
	int		count;
	bool		*flag;
	size_t		offset;
	const char	*name;
};

struct mac_policy_fastpath_elem mac_policy_fastpath_array[] = {
	FPE(priv_check),
	FPE(priv_grant),
	FPE(vnode_check_lookup),
	FPE(vnode_check_readlink),
	FPE(vnode_check_open),
	FPE(vnode_check_stat),
	FPE(vnode_check_read),
	FPE(vnode_check_write),
	FPE(vnode_check_mmap_image),
	FPE(vnode_check_mmap),
	FPE(vnode_check_poll),
	FPE(vnode_check_rename_from),
	FPE(vnode_check_access),
	FPE(pipe_check_stat),
	FPE(pipe_check_poll),
	FPE(pipe_check_read),
	FPE(ifnet_create_mbuf),
	FPE(ifnet_check_transmit),
	FPE(file_check_ioctl),
	FPE(file_check_mmap),
	FPE(file_check_read),
	FPE(file_check_write),
	FPE(file_check_stat),
	FPE(file_check_fcntl),
	FPE(proc_check_fork),
	FPE(proc_check_mmap_anon),
	FPE(proc_check_mprotect),
	FPE(proc_check_syscall),
	FPE(system_check_kas_info),
	FPE(file_notify_close),
	FPE(vnode_check_close),
	FPE(pipe_check_write),
	FPE(socket_check_send),
	FPE(socket_check_receive),
	FPE(socket_check_poll),
	FPE(socket_check_stat),
};

/*
 * Bit i of mpc_fp_active stands for mac_policy_fastpath_array[i]; the top
 * bit marks a policy whose fast-path state the framework keeps (from
 * registration to unregistration), so that a late mac_policy_fastpath_set()
 * cannot count a hook of a policy that is going away.
 */
#define	MAC_FP_COUNTED	(1ULL << 63)
_Static_assert(nitems(mac_policy_fastpath_array) < 64,
    "mpc_fp_active has one bit per fast-path hook and a marker bit");

static void
mac_policy_fastpath_enable(struct mac_policy_fastpath_elem *mpfe)
{

	mtx_assert(&mac_policy_fp_mtx, MA_OWNED);
	MPASS(mpfe->count >= 0);
	mpfe->count++;
	if (mpfe->count == 1) {
		MPASS(*mpfe->flag == false);
		*mpfe->flag = true;
	}
}

static void
mac_policy_fastpath_disable(struct mac_policy_fastpath_elem *mpfe)
{

	mtx_assert(&mac_policy_fp_mtx, MA_OWNED);
	MPASS(mpfe->count >= 1);
	mpfe->count--;
	if (mpfe->count == 0) {
		MPASS(*mpfe->flag == true);
		*mpfe->flag = false;
	}
}

/* Count or uncount hook i of mpc; idempotent. */
static void
mac_policy_fastpath_apply(struct mac_policy_conf *mpc, int i, bool active)
{
	uint64_t bit;

	mtx_assert(&mac_policy_fp_mtx, MA_OWNED);
	bit = 1ULL << i;
	if (active) {
		if ((mpc->mpc_fp_active & bit) != 0)
			return;
		mpc->mpc_fp_active |= bit;
		mac_policy_fastpath_enable(&mac_policy_fastpath_array[i]);
	} else {
		if ((mpc->mpc_fp_active & bit) == 0)
			return;
		mpc->mpc_fp_active &= ~bit;
		mac_policy_fastpath_disable(&mac_policy_fastpath_array[i]);
	}
}

static void
mac_policy_fastpath_register(struct mac_policy_conf *mpc)
{
	const void * const *ops;
	int i;

	mac_policy_xlock_assert();

	ops = (const void * const *)mpc->mpc_ops;
	mtx_lock(&mac_policy_fp_mtx);
	mpc->mpc_fp_active = MAC_FP_COUNTED;
	if ((mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_FP_INACTIVE) == 0) {
		for (i = 0; i < nitems(mac_policy_fastpath_array); i++) {
			if (ops[mac_policy_fastpath_array[i].offset] != NULL)
				mac_policy_fastpath_apply(mpc, i, true);
		}
	}
	mtx_unlock(&mac_policy_fp_mtx);
}

static void
mac_policy_fastpath_unregister(struct mac_policy_conf *mpc)
{
	int i;

	mac_policy_xlock_assert();

	mtx_lock(&mac_policy_fp_mtx);
	for (i = 0; i < nitems(mac_policy_fastpath_array); i++)
		mac_policy_fastpath_apply(mpc, i, false);
	mpc->mpc_fp_active = 0;
	mtx_unlock(&mac_policy_fp_mtx);
}

int
mac_policy_fastpath_set(struct mac_policy_conf *mpc, const u_short *hooks,
    u_int nhooks, bool active)
{
	const void * const *ops;
	int idx[nitems(mac_policy_fastpath_array)];
	u_int n;
	int i;

	if (mpc == NULL || (nhooks != 0 && hooks == NULL) ||
	    nhooks > nitems(mac_policy_fastpath_array))
		return (EINVAL);
	if (nhooks == 0)
		return (0);
	ops = (const void * const *)mpc->mpc_ops;
	mtx_lock(&mac_policy_fp_mtx);
	if ((mpc->mpc_fp_active & MAC_FP_COUNTED) == 0) {
		mtx_unlock(&mac_policy_fp_mtx);
		return (ENOENT);
	}
	/* Validate every hook before changing any. */
	for (n = 0; n < nhooks; n++) {
		for (i = 0; i < nitems(mac_policy_fastpath_array); i++) {
			if (mac_policy_fastpath_array[i].offset == hooks[n])
				break;
		}
		if (i == nitems(mac_policy_fastpath_array)) {
			mtx_unlock(&mac_policy_fp_mtx);
			return (EOPNOTSUPP);
		}
		if (ops[hooks[n]] == NULL) {
			mtx_unlock(&mac_policy_fp_mtx);
			return (EINVAL);
		}
		idx[n] = i;
	}
	for (n = 0; n < nhooks; n++)
		mac_policy_fastpath_apply(mpc, idx[n], active);
	cache_fast_lookup_enabled_recalc();
	mtx_unlock(&mac_policy_fp_mtx);
	/* Publish before the caller's next store, its return included. */
	atomic_thread_fence_seq_cst();
	return (0);
}

u_int
mac_policy_fastpath_hooks(const struct mac_policy_conf *mpc, u_short *hooks,
    u_int maxhooks)
{
	const void * const *ops;
	u_int n;
	int i;

	ops = (const void * const *)mpc->mpc_ops;
	n = 0;
	for (i = 0; i < nitems(mac_policy_fastpath_array); i++) {
		if (ops[mac_policy_fastpath_array[i].offset] == NULL)
			continue;
		if (n < maxhooks)
			hooks[n] = (u_short)mac_policy_fastpath_array[i].offset;
		n++;
	}
	return (n);
}

/*
 * security.mac.fastpath: the framework's fast-path state, for tests and
 * for measuring what a configuration keeps hot.
 *
 *	flags 0x<bit i set: flag i is true>
 *	hook <name> count <policies counting it>	(one per hook)
 *	policy <name> inactive <0|1> active 0x<counted hooks>
 *	    implemented 0x<hooks the policy has>	(one per policy)
 *
 * The state is copied under the locks and formatted after they are dropped.
 */
#define	MAC_FP_NAMELEN	32

struct mac_fastpath_snap {
	char		mfs_name[MAC_FP_NAMELEN];
	int		mfs_inactive;
	uint64_t	mfs_active;
	uint64_t	mfs_implemented;
};

static void
mac_fastpath_snap_policy(struct mac_fastpath_snap *s,
    const struct mac_policy_conf *mpc)
{
	const void * const *ops;
	int i;

	mtx_assert(&mac_policy_fp_mtx, MA_OWNED);
	strlcpy(s->mfs_name, mpc->mpc_name, sizeof(s->mfs_name));
	s->mfs_inactive =
	    (mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_FP_INACTIVE) != 0;
	s->mfs_active = mpc->mpc_fp_active & ~MAC_FP_COUNTED;
	s->mfs_implemented = 0;
	ops = (const void * const *)mpc->mpc_ops;
	for (i = 0; i < nitems(mac_policy_fastpath_array); i++) {
		if (ops[mac_policy_fastpath_array[i].offset] != NULL)
			s->mfs_implemented |= 1ULL << i;
	}
}

static int
sysctl_mac_fastpath(SYSCTL_HANDLER_ARGS)
{
	int counts[nitems(mac_policy_fastpath_array)];
	struct mac_fastpath_snap *snap;
	struct mac_policy_conf *mpc;
	struct sbuf sb;
	uint64_t flags;
	u_int cap, i, npol;
	int error;

	/* Policies registering now wait; mac_policy_count holds still. */
	mac_policy_slock_sleep();
	cap = mac_policy_count;
	snap = malloc(sizeof(*snap) * MAX(cap, 1), M_TEMP, M_WAITOK | M_ZERO);
	npol = 0;
	mtx_lock(&mac_policy_fp_mtx);
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {
		if (npol < cap)
			mac_fastpath_snap_policy(&snap[npol++], mpc);
	}
	LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {
		if (npol < cap)
			mac_fastpath_snap_policy(&snap[npol++], mpc);
	}
	flags = 0;
	for (i = 0; i < nitems(mac_policy_fastpath_array); i++) {
		counts[i] = mac_policy_fastpath_array[i].count;
		if (*mac_policy_fastpath_array[i].flag)
			flags |= 1ULL << i;
	}
	mtx_unlock(&mac_policy_fp_mtx);
	mac_policy_sunlock_sleep();

	sbuf_new_for_sysctl(&sb, NULL, 1024, req);
	sbuf_printf(&sb, "flags 0x%016jx\n", (uintmax_t)flags);
	for (i = 0; i < nitems(mac_policy_fastpath_array); i++)
		sbuf_printf(&sb, "hook %s count %d\n",
		    mac_policy_fastpath_array[i].name, counts[i]);
	for (i = 0; i < npol; i++)
		sbuf_printf(&sb, "policy %s inactive %d active 0x%016jx "
		    "implemented 0x%016jx\n", snap[i].mfs_name,
		    snap[i].mfs_inactive, (uintmax_t)snap[i].mfs_active,
		    (uintmax_t)snap[i].mfs_implemented);
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	free(snap, M_TEMP);
	return (error);
}
SYSCTL_PROC(_security_mac, OID_AUTO, fastpath,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_mac_fastpath, "A",
    "Fast-path flags, their counts, and each policy's counted hooks");

#undef FPE
#undef FPO

static int
mac_policy_register(struct mac_policy_conf *mpc)
{
	struct mac_policy_list_head *mpc_list;
	struct mac_policy_conf *last_mpc, *tmpc;
	int error, slot, static_entry;

	error = 0;

	/*
	 * We don't technically need exclusive access while !mac_late, but
	 * hold it for assertion consistency.
	 */
	SDT_PROBE1(mac_framework, , , register__start, mpc);
	mac_policy_xlock();

	/*
	 * If the module can potentially be unloaded, or we're loading late,
	 * we have to stick it in the non-static list and pay an extra
	 * performance overhead.  Otherwise, we can pay a light locking cost
	 * and stick it in the static list.
	 */
	static_entry = (!mac_late &&
	    !(mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_UNLOADOK));

	mpc_list = (static_entry) ? &mac_static_policy_list :
	    &mac_policy_list;
	last_mpc = NULL;
	LIST_FOREACH(tmpc, mpc_list, mpc_list) {
		last_mpc = tmpc;
		if (strcmp(tmpc->mpc_name, mpc->mpc_name) == 0) {
			error = EEXIST;
			goto out;
		}
	}
	if (mpc->mpc_field_off != NULL) {
		slot = ffs(mac_slot_offsets_free);
		if (slot == 0) {
			error = ENOMEM;
			goto out;
		}
		slot--;
		mac_slot_offsets_free &= ~(1 << slot);
		*mpc->mpc_field_off = slot;
	}
	mpc->mpc_runtime_flags |= MPC_RUNTIME_FLAG_REGISTERED;

	/*
	 * Some modules may depend on the operations of its dependencies.
	 * Inserting modules in order of registration ensures operations
	 * that work on the module list retain dependency order.
	 */
	if (last_mpc == NULL)
		LIST_INSERT_HEAD(mpc_list, mpc, mpc_list);
	else
		LIST_INSERT_AFTER(last_mpc, mpc, mpc_list);
	/*
	 * Per-policy initialization.  Currently, this takes place under the
	 * exclusive lock, so policies must not sleep in their init method.
	 * In the future, we may want to separate "init" from "start", with
	 * "init" occurring without the lock held.  Likewise, on tear-down,
	 * breaking out "stop" from "destroy".
	 */
	if (MAC_POLICY_PRESENT(init, mpc))
		MAC_POLICY_CALL_VOID(init, mpc, mpc);

	mac_policy_fastpath_register(mpc);

	mac_policy_update();

	SDT_PROBE1(mac, , policy, register, mpc);
	printf("Security policy loaded: %s (%s)\n", mpc->mpc_fullname,
	    mpc->mpc_name);

out:
	mac_policy_xunlock();
	{
		int trace_result = error;
		SDT_PROBE2(mac_framework, , , register__done, mpc, trace_result);
		return (trace_result);
	}
}

static int
mac_policy_unregister(struct mac_policy_conf *mpc)
{

	/*
	 * If we fail the load, we may get a request to unload.  Check to see
	 * if we did the run-time registration, and if not, silently succeed.
	 */
	SDT_PROBE1(mac_framework, , , unregister__start, mpc);
	mac_policy_xlock();
	if ((mpc->mpc_runtime_flags & MPC_RUNTIME_FLAG_REGISTERED) == 0) {
		mac_policy_xunlock();
		{
		int trace_result = 0;
		SDT_PROBE2(mac_framework, , , unregister__done, mpc, trace_result);
		return (trace_result);
	}
	}
#if 0
	/*
	 * Don't allow unloading modules with private data.
	 */
	if (mpc->mpc_field_off != NULL) {
		mac_policy_xunlock();
		{
		int trace_result = EBUSY;
		SDT_PROBE2(mac_framework, , , unregister__done, mpc, trace_result);
		return (trace_result);
	}
	}
#endif
	/*
	 * Only allow the unload to proceed if the module is unloadable by
	 * its own definition.
	 */
	if ((mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_UNLOADOK) == 0) {
		mac_policy_xunlock();
		{
		int trace_result = EBUSY;
		SDT_PROBE2(mac_framework, , , unregister__done, mpc, trace_result);
		return (trace_result);
	}
	}

	mac_policy_fastpath_unregister(mpc);

	if (MAC_POLICY_PRESENT(destroy, mpc))
		MAC_POLICY_CALL_VOID(destroy, mpc, mpc);

	LIST_REMOVE(mpc, mpc_list);
	mpc->mpc_runtime_flags &= ~MPC_RUNTIME_FLAG_REGISTERED;
	mac_policy_update();
	mac_policy_xunlock();

	SDT_PROBE1(mac, , policy, unregister, mpc);
	printf("Security policy unload: %s (%s)\n", mpc->mpc_fullname,
	    mpc->mpc_name);

	{
		int trace_result = 0;
		SDT_PROBE2(mac_framework, , , unregister__done, mpc, trace_result);
		return (trace_result);
	}
}

/*
 * Allow MAC policy modules to register during boot, etc.
 */
int
mac_policy_modevent(module_t mod, int type, void *data)
{
	struct mac_policy_conf *mpc;
	int error;

	error = 0;
	mpc = (struct mac_policy_conf *) data;

#ifdef MAC_STATIC
	if (mac_late) {
		printf("mac_policy_modevent: MAC_STATIC and late\n");
		return (EBUSY);
	}
#endif

	SDT_PROBE2(mac, , policy, modevent, type, mpc);
	switch (type) {
	case MOD_LOAD:
		if (mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_NOTLATE &&
		    mac_late) {
			printf("mac_policy_modevent: can't load %s policy "
			    "after booting\n", mpc->mpc_name);
			error = EBUSY;
			break;
		}
		error = mac_policy_register(mpc);
		break;
	case MOD_UNLOAD:
		/* Don't unregister the module if it was never registered. */
		if ((mpc->mpc_runtime_flags & MPC_RUNTIME_FLAG_REGISTERED)
		    != 0)
			error = mac_policy_unregister(mpc);
		else
			error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

/*
 * Define an error value precedence, and given two arguments, selects the
 * value with the higher precedence.
 */
int
mac_error_select(int error1, int error2)
{

	/* Certain decision-making errors take top priority. */
	if (error1 == EDEADLK || error2 == EDEADLK)
		return (EDEADLK);

	/* Invalid arguments should be reported where possible. */
	if (error1 == EINVAL || error2 == EINVAL)
		return (EINVAL);

	/* Precedence goes to "visibility", with both process and file. */
	if (error1 == ESRCH || error2 == ESRCH)
		return (ESRCH);

	if (error1 == ENOENT || error2 == ENOENT)
		return (ENOENT);

	/* Precedence goes to DAC/MAC protections. */
	if (error1 == EACCES || error2 == EACCES)
		return (EACCES);

	/* Precedence goes to privilege. */
	if (error1 == EPERM || error2 == EPERM)
		return (EPERM);

	/* Precedence goes to error over success; otherwise, arbitrary. */
	if (error1 != 0)
		return (error1);
	return (error2);
}

int
mac_check_structmac_consistent(const struct mac *mac)
{
	/* Require that labels have a non-zero length. */
	if (mac->m_buflen > MAC_MAX_LABEL_BUF_LEN ||
	    mac->m_buflen <= sizeof(""))
		return (EINVAL);

	return (0);
}

SYSINIT(mac, SI_SUB_MAC, SI_ORDER_FIRST, mac_init, NULL);
SYSINIT(mac_late, SI_SUB_MAC_LATE, SI_ORDER_FIRST, mac_late_init, NULL);
